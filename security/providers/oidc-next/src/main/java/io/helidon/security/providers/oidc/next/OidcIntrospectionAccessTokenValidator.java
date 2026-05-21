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

import java.net.InetAddress;
import java.net.URI;
import java.net.URLEncoder;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Locale;
import java.util.Optional;

import io.helidon.common.Errors;
import io.helidon.common.parameters.Parameters;
import io.helidon.http.HeaderNames;
import io.helidon.http.HeaderValues;
import io.helidon.http.Status;
import io.helidon.json.JsonObject;
import io.helidon.json.JsonParser;
import io.helidon.security.jwt.JwtValidator;
import io.helidon.webclient.api.HttpClientResponse;
import io.helidon.webclient.api.WebClient;

final class OidcIntrospectionAccessTokenValidator {
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(10);

    private final WebClient webClient;

    private OidcIntrospectionAccessTokenValidator(WebClient webClient) {
        this.webClient = webClient;
    }

    static OidcIntrospectionAccessTokenValidator create() {
        return new OidcIntrospectionAccessTokenValidator(WebClient.create());
    }

    static void validateIntrospectionEndpointUri(URI uri) {
        /*
         * Spec: RFC 7662, 2 Introspection Endpoint
         * https://www.rfc-editor.org/rfc/rfc7662.html#section-2
         * Quote: "MUST be protected by a transport-layer security mechanism".
         * The `http` loopback allowance is Helidon local/test support, not a spec exception.
         */
        String scheme = uri.getScheme();
        if ("https".equalsIgnoreCase(scheme)) {
            return;
        }
        if ("http".equalsIgnoreCase(scheme) && isLoopback(uri)) {
            return;
        }
        throw new IllegalArgumentException(
                "introspection-endpoint-uri must use https, except for http loopback endpoints: " + uri);
    }

    OidcTokenValidationResult validate(String token, OidcTenantContext tenantContext) {
        Optional<URI> endpointUri = tenantContext.endpointClient().introspectionEndpointUri();
        OidcTenantConfig tenantConfig = tenantContext.tenantConfig();
        Optional<String> clientId = tenantConfig.clientId();
        Optional<String> clientSecret = tenantConfig.clientSecret();
        if (endpointUri.isEmpty() || clientId.isEmpty() || clientSecret.isEmpty()) {
            return OidcTokenValidationResult.failure("Bearer Token introspection is not configured");
        }

        try (HttpClientResponse response = request(endpointUri.orElseThrow(),
                                                   token,
                                                   clientId.orElseThrow(),
                                                   clientSecret.orElseThrow())) {
            if (response.status().family() != Status.Family.SUCCESSFUL) {
                if (response.status().code() >= 500) {
                    return OidcTokenValidationResult.failure("Bearer Token introspection endpoint is unavailable");
                }
                return OidcTokenValidationResult.failure("Bearer Token introspection endpoint rejected the token");
            }

            return validateResponse(token, tenantContext, response);
        } catch (RuntimeException e) {
            return OidcTokenValidationResult.failure("Bearer Token introspection endpoint is unavailable", e);
        }
    }

    private OidcTokenValidationResult validateResponse(String token,
                                                       OidcTenantContext tenantContext,
                                                       HttpClientResponse response) {
        JsonObject jsonObject;
        try {
            jsonObject = JsonParser.create(response.inputStream()).readJsonObject();
        } catch (RuntimeException e) {
            return OidcTokenValidationResult.failure("Bearer Token introspection response is invalid", e);
        }

        try {
            Optional<Boolean> active = jsonObject.booleanValue("active");
            if (active.isEmpty()) {
                return OidcTokenValidationResult.failure("Bearer Token introspection response is invalid");
            }
            if (!active.orElseThrow()) {
                return OidcTokenValidationResult.failure("Bearer Token introspection response is inactive");
            }

            OidcValidatedIntrospection validated = OidcValidatedIntrospection.create(token, jsonObject);
            OidcTokenValidationResult claimValidation = validateClaims(validated, tenantContext);
            if (!claimValidation.succeeded()) {
                return claimValidation;
            }
            return OidcTokenValidationResult.success(validated);
        } catch (RuntimeException e) {
            return OidcTokenValidationResult.failure("Bearer Token introspection response is invalid", e);
        }
    }

    private OidcTokenValidationResult validateClaims(OidcValidatedIntrospection validated,
                                                     OidcTenantContext tenantContext) {
        OidcTokenValidationPolicy policy = tenantContext.tokenValidationPolicy();
        Optional<String> expectedIssuer = tenantContext.metadata().issuer().map(Object::toString);
        Optional<String> expectedAudience = policy.audience();
        Instant now = Instant.now();
        if (policy.audienceValidationEnabled() && expectedAudience.isEmpty()) {
            return OidcTokenValidationResult.failure("Bearer Token introspection is not configured");
        }

        JwtValidator.Builder builder = JwtValidator.builder()
                .addExpirationValidator(it -> it.now(now).allowedTimeSkew(policy.clockSkew()))
                .addIssueTimeValidator(it -> it.now(now).allowedTimeSkew(policy.clockSkew()))
                .addNotBeforeValidator(it -> it.now(now).allowedTimeSkew(policy.clockSkew()));
        expectedIssuer.ifPresent(issuer -> builder.addIssuerValidator(issuer, false));
        if (policy.audienceValidationEnabled()) {
            expectedAudience.ifPresent(builder::addAudienceValidator);
        }
        Errors claimErrors = builder.build().validate(validated.jwt());
        if (!claimErrors.isValid()) {
            return OidcTokenValidationResult.failure("Bearer Token introspection claims are invalid");
        }

        if (validated.principalId().isEmpty()) {
            return OidcTokenValidationResult.failure("Bearer Token introspection response has no principal claim");
        }
        if (validated.tokenType()
                .filter(tokenType -> !"bearer".equalsIgnoreCase(tokenType))
                .isPresent()) {
            return OidcTokenValidationResult.failure("Bearer Token introspection claims are invalid");
        }
        return OidcTokenValidationResult.success(validated);
    }

    private HttpClientResponse request(URI endpointUri, String token, String clientId, String clientSecret) {
        Parameters form = Parameters.builder("oidc-introspection-form")
                .add("token", token)
                .add("token_type_hint", "access_token")
                .build();
        return webClient.post()
                .uri(endpointUri)
                .readTimeout(REQUEST_TIMEOUT)
                .header(HeaderValues.ACCEPT_JSON)
                .header(HeaderNames.AUTHORIZATION, basicAuthorization(clientId, clientSecret))
                .header(HeaderValues.CACHE_NO_CACHE)
                .header(HeaderNames.CONTENT_TYPE, "application/x-www-form-urlencoded")
                .submit(form);
    }

    private String basicAuthorization(String clientId, String clientSecret) {
        String credentials = formEncode(clientId) + ":" + formEncode(clientSecret);
        return "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
    }

    private static String formEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static boolean isLoopback(URI uri) {
        String host = uri.getHost();
        if (host == null) {
            return false;
        }
        String normalizedHost = host.toLowerCase(Locale.ROOT);
        if ("localhost".equals(normalizedHost)) {
            return true;
        }
        try {
            return InetAddress.getByName(unbracketIpv6Literal(normalizedHost)).isLoopbackAddress();
        } catch (UnknownHostException e) {
            return false;
        }
    }

    private static String unbracketIpv6Literal(String host) {
        if (host.startsWith("[") && host.endsWith("]")) {
            return host.substring(1, host.length() - 1);
        }
        return host;
    }
}
