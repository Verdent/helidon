/*
 * Copyright (c) 2026 Oracle and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.helidon.security.providers.oidc.next;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;

import io.helidon.common.configurable.Resource;
import io.helidon.common.configurable.ResourceConfig;
import io.helidon.http.ClientResponseHeaders;
import io.helidon.http.DateTime;
import io.helidon.http.HeaderNames;
import io.helidon.http.HeaderValues;
import io.helidon.http.Status;
import io.helidon.json.JsonObject;
import io.helidon.json.JsonParser;
import io.helidon.json.JsonValue;
import io.helidon.json.JsonValueType;
import io.helidon.security.jwt.jwk.JwkKeys;
import io.helidon.webclient.api.HttpClientResponse;
import io.helidon.webclient.api.WebClient;

final class OidcJwkSetLoader {
    private static final Set<String> FORBIDDEN_OPENID_PROVIDER_JWK_PARAMETERS =
            Set.of("k", "d", "p", "q", "dp", "dq", "qi", "oth");
    private static final Duration MAX_DURATION = Duration.ofSeconds(Long.MAX_VALUE);

    private final WebClient webClient;
    private final Function<URI, Optional<String>> unauthorizedJwkSetAccessToken;
    private final Clock clock;

    OidcJwkSetLoader(WebClient webClient) {
        this(webClient, _ -> Optional.empty(), Clock.systemUTC());
    }

    OidcJwkSetLoader(WebClient webClient, Function<URI, Optional<String>> unauthorizedJwkSetAccessToken) {
        this(webClient, unauthorizedJwkSetAccessToken, Clock.systemUTC());
    }

    OidcJwkSetLoader(WebClient webClient,
                     Function<URI, Optional<String>> unauthorizedJwkSetAccessToken,
                     Clock clock) {
        this.webClient = webClient;
        this.unauthorizedJwkSetAccessToken = unauthorizedJwkSetAccessToken;
        this.clock = clock;
    }

    static LoadedJwkSet loadLocal(ResourceConfig config) {
        if (config.uri().isPresent()) {
            throw new IllegalArgumentException("token-validation.verification-jwk must be local key material, not a URI");
        }
        Resource resource = config.build();
        resource.cacheBytes();
        return LoadedJwkSet.local(JwkKeys.builder().resource(resource).build());
    }

    LoadedJwkSet load(URI uri, boolean revalidate) {
        String scheme = uri.getScheme();
        if ("file".equalsIgnoreCase(scheme)) {
            JsonObject keys = loadFile(uri);
            validateOpenIdProviderJwkSet(keys);
            return LoadedJwkSet.local(JwkKeys.create(keys));
        }
        if ("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme)) {
            return loadRemote(uri, revalidate);
        }
        throw new IllegalStateException("Unsupported JWK Set URI scheme: " + uri);
    }

    private static void validateOpenIdProviderJwkSet(JsonObject jsonObject) {
        /*
         * Configured and discovered provider JWK Set URIs have the same public-key role. Explicit local resources
         * for access-token verification, client assertion signing, or ID Token decryption are loaded separately.
         *
         * Spec: OpenID Connect Discovery 1.0, 3 OpenID Provider Metadata, jwks_uri
         * https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
         * Quote: "This contains the signing key(s) the RP uses to validate signatures from the OP."
         * Quote: "The JWK Set MAY also contain the Server's encryption key(s), which are used by RPs to encrypt
         * requests to the Server."
         * Quote: "The JWK Set MUST NOT contain private or symmetric key values."
         */
        jsonObject.arrayValue("keys")
                .ifPresent(keys -> keys.values()
                        .stream()
                        .filter(value -> value.type() == JsonValueType.OBJECT)
                        .map(JsonValue::asObject)
                        .forEach(OidcJwkSetLoader::validateOpenIdProviderJwk));
    }

    private static void validateOpenIdProviderJwk(JsonObject jwk) {
        if (jwk.stringValue("kty").filter("oct"::equals).isPresent()
                || containsAny(jwk, FORBIDDEN_OPENID_PROVIDER_JWK_PARAMETERS)) {
            throw new IllegalStateException("OpenID Provider JWK Set must not contain private or symmetric key values");
        }
    }

    private static boolean containsAny(JsonObject jsonObject, Set<String> names) {
        for (String name : names) {
            if (jsonObject.containsKey(name)) {
                return true;
            }
        }
        return false;
    }

    private JsonObject loadFile(URI uri) {
        try (InputStream inputStream = Files.newInputStream(Path.of(uri))) {
            return JsonParser.create(inputStream).readJsonObject();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to load JWK Set", e);
        }
    }

    private LoadedJwkSet loadRemote(URI uri, boolean revalidate) {
        /*
         * OpenID Connect Discovery 1.0 sections 3 and 7.1, and RFC 8414 sections 2 and 6.1,
         * require authenticated HTTPS for provider key retrieval.
         * https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
         * https://www.rfc-editor.org/rfc/rfc8414.html#section-6.1
         * Refuse redirects so the approved key endpoint cannot silently change or downgrade its transport.
         * Deployments using redirects must configure the final JWKS URI instead.
         */
        Status status;
        Instant requestedAt = clock.instant();
        try (HttpClientResponse response = request(uri, Optional.empty(), revalidate)) {
            status = response.status();
            if (status.code() != Status.UNAUTHORIZED_401_CODE && status.code() != Status.FORBIDDEN_403_CODE) {
                return successfulResponse(response, requestedAt);
            }
        }
        // Close the first response before acquiring a token through the same tenant WebClient. In particular, a
        // single-connection pool must not wait on a still-open unauthorized JWK response.
        Optional<String> bearerToken = unauthorizedJwkSetAccessToken.apply(uri);
        if (bearerToken.isEmpty()) {
            throw new IllegalStateException("JWK Set endpoint returned status: " + status);
        }
        String token = bearerToken.orElseThrow();
        if (token.isBlank() || token.indexOf('\r') >= 0 || token.indexOf('\n') >= 0) {
            throw new IllegalStateException("JWK Set access token is invalid");
        }
        requestedAt = clock.instant();
        try (HttpClientResponse response = request(uri, bearerToken, revalidate)) {
            return successfulResponse(response, requestedAt);
        }
    }

    private HttpClientResponse request(URI uri, Optional<String> bearerToken, boolean revalidate) {
        var request = webClient.get()
                .uri(uri)
                .followRedirects(false)
                .header(HeaderValues.ACCEPT_JSON);
        if (revalidate) {
            // When our local maximum expires before an intermediary's max-age, ask it to validate with the origin.
            request.header(HeaderValues.CACHE_NO_CACHE);
        }
        bearerToken.ifPresent(token -> request.header(HeaderNames.AUTHORIZATION, "Bearer " + token));
        return request.request();
    }

    private LoadedJwkSet successfulResponse(HttpClientResponse response, Instant requestedAt) {
        // A JWK Set must be a complete representation; partial or other non-200 responses cannot replace trust keys.
        if (!response.status().equals(Status.OK_200)) {
            throw new IllegalStateException("JWK Set endpoint returned status: " + response.status());
        }
        JsonObject jsonObject = response.as(JsonObject.class);
        validateOpenIdProviderJwkSet(jsonObject);
        Instant receivedAt = clock.instant();
        return withCachePolicy(JwkKeys.create(jsonObject), response.headers(), requestedAt, receivedAt);
    }

    private static LoadedJwkSet withCachePolicy(JwkKeys keys,
                                                ClientResponseHeaders headers,
                                                Instant requestedAt,
                                                Instant receivedAt) {
        boolean noStore = false;
        boolean noCache = false;
        boolean mustRevalidate = false;
        Duration maxAge = null;
        Duration staleIfError = null;
        for (String field : headers.all(HeaderNames.CACHE_CONTROL, List::of)) {
            for (String directive : field.split(",")) {
                String[] parts = directive.strip().split("=", 2);
                switch (parts[0].strip().toLowerCase(Locale.ROOT)) {
                case "no-store" -> noStore = true;
                case "no-cache" -> noCache = true;
                case "must-revalidate" -> mustRevalidate = true;
                case "max-age" -> {
                    Duration value = deltaSeconds(parts);
                    maxAge = maxAge == null || value.compareTo(maxAge) < 0 ? value : maxAge;
                }
                case "stale-if-error" -> {
                    Duration value = deltaSeconds(parts);
                    staleIfError = staleIfError == null || value.compareTo(staleIfError) < 0 ? value : staleIfError;
                }
                default -> { }
                }
            }
        }

        // RFC 9111, 4.2 and 5.3: max-age takes precedence over Expires, and response Age/Date reduces freshness.
        // https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2
        Duration apparentAge = headers.first(HeaderNames.DATE)
                .flatMap(OidcJwkSetLoader::httpDate)
                .map(date -> positiveDuration(date, receivedAt))
                .orElse(Duration.ZERO);
        Optional<Duration> ageHeader = headers.first(HeaderNames.AGE)
                .flatMap(OidcJwkSetLoader::parseDeltaSeconds);
        if (headers.contains(HeaderNames.AGE) && ageHeader.isEmpty()) {
            throw new IllegalStateException("JWK Set endpoint returned an invalid Age header");
        }
        Duration age = ageHeader.orElse(Duration.ZERO);
        Duration responseDelay = positiveDuration(requestedAt, receivedAt);
        Duration currentAge = apparentAge.compareTo(age) > 0 ? apparentAge : age;
        try {
            Duration correctedAge = age.plus(responseDelay);
            if (correctedAge.compareTo(currentAge) > 0) {
                currentAge = correctedAge;
            }
        } catch (ArithmeticException _) {
            currentAge = MAX_DURATION;
        }

        Duration freshness = maxAge;
        if (freshness == null && headers.contains(HeaderNames.EXPIRES)) {
            Instant date = headers.first(HeaderNames.DATE).flatMap(OidcJwkSetLoader::httpDate).orElse(receivedAt);
            freshness = headers.first(HeaderNames.EXPIRES)
                    .flatMap(OidcJwkSetLoader::httpDate)
                    .map(expires -> positiveDuration(date, expires))
                    .orElse(Duration.ZERO);
        }
        boolean alreadyStale = freshness != null && freshness.compareTo(currentAge) < 0;
        if (alreadyStale && currentAge.minus(freshness).compareTo(Duration.ofSeconds(1)) >= 0) {
            // Never promote an already-expired intermediary response to a new, trusted key set.
            throw new IllegalStateException("JWK Set endpoint returned an expired cached response");
        }
        if (freshness != null) {
            freshness = freshness.compareTo(currentAge) <= 0 ? Duration.ZERO : freshness.minus(currentAge);
        }
        if (noStore || noCache) {
            freshness = Duration.ZERO;
        }
        return new LoadedJwkSet(keys, Optional.ofNullable(freshness), currentAge, Optional.ofNullable(staleIfError),
                                !noStore, !noStore && !noCache && !mustRevalidate && !alreadyStale);
    }

    private static Optional<Instant> httpDate(String value) {
        try {
            return Optional.of(DateTime.parse(value).toInstant());
        } catch (DateTimeParseException _) {
            return Optional.empty();
        }
    }

    private static Duration positiveDuration(Instant start, Instant end) {
        try {
            Duration between = Duration.between(start, end);
            return between.isNegative() ? Duration.ZERO : between;
        } catch (ArithmeticException _) {
            return MAX_DURATION;
        }
    }

    private static Duration deltaSeconds(String[] directive) {
        return directive.length == 2 ? parseDeltaSeconds(directive[1]).orElse(Duration.ZERO) : Duration.ZERO;
    }

    private static Optional<Duration> parseDeltaSeconds(String text) {
        String digits = text.strip();
        if (digits.isEmpty()) {
            return Optional.empty();
        }
        for (int i = 0; i < digits.length(); i++) {
            if (digits.charAt(i) < '0' || digits.charAt(i) > '9') {
                return Optional.empty();
            }
        }
        try {
            return Optional.of(Duration.ofSeconds(Long.parseLong(digits)));
        } catch (NumberFormatException _) {
            return Optional.empty();
        }
    }

    record LoadedJwkSet(JwkKeys keys,
                        Optional<Duration> freshness,
                        Duration responseAge,
                        Optional<Duration> staleIfError,
                        boolean reusable,
                        boolean staleAllowed) {
        private static LoadedJwkSet local(JwkKeys keys) {
            return new LoadedJwkSet(keys, Optional.empty(), Duration.ZERO, Optional.empty(), true, true);
        }
    }
}
