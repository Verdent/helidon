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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.DateTimeException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;

import io.helidon.common.LazyValue;
import io.helidon.http.SetCookie;
import io.helidon.json.JsonObject;
import io.helidon.json.JsonParser;
import io.helidon.security.jwt.Jwt;
import io.helidon.security.jwt.SignedJwt;

final class OidcCookieStateHandler {
    static final int MAX_SESSION_COOKIES = 16;

    private static final String PROTECTED_COOKIE_VERSION = "v1";
    private static final String ROUTED_AUTHENTICATION_REQUEST_VERSION = "r1.";
    private static final int MAX_ROUTED_TENANT_HINT_LENGTH = 1024;
    private static final int AES_GCM_TAG_BITS = 128;
    private static final int AES_GCM_TAG_BYTES = AES_GCM_TAG_BITS / Byte.SIZE;
    private static final int AES_GCM_IV_BYTES = 12;
    private static final int BROWSER_SESSION_GENERATION_BYTES = 32;
    private static final String BROWSER_SESSION_GENERATION_COOKIE_SUFFIX = "-generation";

    private final OidcCookieConfig cookieConfig;
    private final LazyValue<Optional<OidcCookieKeys>> keys;
    private final SecureRandom secureRandom;

    private OidcCookieStateHandler(OidcCookieConfig cookieConfig,
                                   LazyValue<Optional<OidcCookieKeys>> keys,
                                   SecureRandom secureRandom) {
        this.cookieConfig = cookieConfig;
        this.keys = keys;
        this.secureRandom = secureRandom;
    }

    static OidcCookieStateHandler create(String tenantId, OidcTenantConfig tenantConfig) {
        return new OidcCookieStateHandler(tenantConfig.cookies(),
                                          LazyValue.create(() -> OidcCookieKeys.create(tenantId, tenantConfig)),
                                          new SecureRandom());
    }

    static String browserSessionGenerationCookieName(OidcCookieConfig cookieConfig) {
        return cookieConfig.localAuthenticationCookieName() + BROWSER_SESSION_GENERATION_COOKIE_SUFFIX;
    }

    static List<SetCookie> removeLocalAuthenticationResultCookies(OidcCookieConfig config) {
        List<SetCookie> cookies = new ArrayList<>(MAX_SESSION_COOKIES);
        for (int index = 0; index < MAX_SESSION_COOKIES; index++) {
            cookies.add(removeCookie(sessionCookieName(config, index)));
        }
        return List.copyOf(cookies);
    }

    static String sessionCookieName(OidcCookieConfig config, int index) {
        return config.localAuthenticationCookieName() + (index == 0 ? "" : "." + index);
    }

    OidcCookieConfig cookieConfig() {
        return cookieConfig;
    }

    SetCookie createAuthenticationRequestCookie(OidcAuthenticationRequestState state) {
        return createAuthenticationRequestCookie(state, false);
    }

    SetCookie createAuthenticationRequestCookie(OidcAuthenticationRequestState state, boolean customState) {
        String value = protect(OidcCookieKeys.Purpose.AUTHENTICATION_REQUEST, toJson(state).toString());
        if (customState) {
            // The hint is untrusted. The callback uses it only to select the tenant's protected cookie key;
            // the decrypted tenant and the complete returned state must still match.
            String tenantHint = encode(state.tenantId().getBytes(StandardCharsets.UTF_8));
            if (tenantHint.length() > MAX_ROUTED_TENANT_HINT_LENGTH) {
                throw new IllegalStateException("OIDC adapter tenant routing hint is too large");
            }
            value = ROUTED_AUTHENTICATION_REQUEST_VERSION + tenantHint + "." + value;
        }
        SetCookie cookie = cookieBuilder(cookieConfig.authenticationRequestCookieName(),
                             value)
                .maxAge(cookieConfig.authenticationRequestLifetime())
                .build();
        if (customState && cookie.toString().length() > cookieConfig.maxCookieSize()) {
            throw new IllegalStateException("OIDC adapter authentication request cookie exceeds cookies.max-cookie-size");
        }
        return cookie;
    }

    static Optional<String> authenticationRequestTenantHint(String cookieValue) {
        if (cookieValue == null || !cookieValue.startsWith(ROUTED_AUTHENTICATION_REQUEST_VERSION)) {
            return Optional.empty();
        }
        int end = cookieValue.indexOf('.', ROUTED_AUTHENTICATION_REQUEST_VERSION.length());
        if (end <= ROUTED_AUTHENTICATION_REQUEST_VERSION.length()
                || end - ROUTED_AUTHENTICATION_REQUEST_VERSION.length() > MAX_ROUTED_TENANT_HINT_LENGTH) {
            return Optional.empty();
        }
        String encoded = cookieValue.substring(ROUTED_AUTHENTICATION_REQUEST_VERSION.length(), end);
        try {
            byte[] bytes = decode(encoded);
            String tenantId = new String(bytes, StandardCharsets.UTF_8);
            return !tenantId.isEmpty() && encode(tenantId.getBytes(StandardCharsets.UTF_8)).equals(encoded)
                    ? Optional.of(tenantId)
                    : Optional.empty();
        } catch (RuntimeException _) {
            return Optional.empty();
        }
    }

    List<SetCookie> createLocalAuthenticationResultCookies(OidcLocalAuthenticationResult result,
                                                           Map<String, List<String>> currentCookies,
                                                           Instant now) {
        return localAuthenticationResultCookies(prepareLocalAuthenticationResult(result, currentCookies), now);
    }

    PreparedSession prepareLocalAuthenticationResult(OidcLocalAuthenticationResult result,
                                                     Map<String, List<String>> currentCookies) {
        String json = toJson(result).toString();
        if (json.length() > cookieConfig.maxSessionSize()) {
            throw new SessionCookieException("OIDC session exceeds cookies.max-session-size");
        }
        byte[] payload = json.getBytes(StandardCharsets.UTF_8);
        if (payload.length > cookieConfig.maxSessionSize()) {
            throw new SessionCookieException("OIDC session exceeds cookies.max-session-size");
        }
        String encoding = "n";
        try {
            if (cookieConfig.compression() == OidcCookieCompression.GZIP) {
                ByteArrayOutputStream output = new ByteArrayOutputStream();
                try (GZIPOutputStream gzip = new GZIPOutputStream(output)) {
                    gzip.write(payload);
                }
                byte[] compressed = output.toByteArray();
                if (compressed.length < payload.length) {
                    payload = compressed;
                    encoding = "g";
                }
            }
            byte[] iv = new byte[AES_GCM_IV_BYTES];
            secureRandom.nextBytes(iv);
            String encodedIv = encode(iv);
            int encodedLength = (int) (((long) payload.length + AES_GCM_TAG_BYTES) * 4 + 2) / 3;
            for (int count = 1; count <= Math.min(cookieConfig.maxChunks(), MAX_SESSION_COOKIES); count++) {
                String framing = "v2." + encoding + "." + count + "." + encodedIv + ".";
                int[] capacities = new int[count];
                int capacity = 0;
                long headerSize = encodedLength;
                long responseSize = encodedLength;
                for (int index = 0; index < count; index++) {
                    String prefix = framing + index + ".";
                    int overhead = sessionCookie(index, prefix, result.expiresAt(),
                                                 Duration.ofSeconds(Long.MAX_VALUE)).toString().length();
                    capacities[index] = Math.max(0, cookieConfig.maxCookieSize() - overhead);
                    capacity += capacities[index];
                    responseSize += overhead + 14L;
                    headerSize += sessionCookieName(cookieConfig, index).length() + 1L + prefix.length();
                    if (index != 0) {
                        headerSize += 2;
                    }
                }
                List<String> retired = new ArrayList<>();
                for (int index = count; index < MAX_SESSION_COOKIES; index++) {
                    String name = sessionCookieName(cookieConfig, index);
                    if (currentCookies.containsKey(name)) {
                        retired.add(name);
                        responseSize += removeCookie(name).toString().length() + 14L;
                    }
                }
                if (capacity < encodedLength || headerSize > cookieConfig.maxTotalSize()
                        || responseSize > cookieConfig.maxTotalSize()) {
                    continue;
                }
                Cipher cipher = cipher(Cipher.ENCRYPT_MODE, iv, OidcCookieKeys.Purpose.LOCAL_AUTHENTICATION);
                cipher.updateAAD(framing.getBytes(StandardCharsets.US_ASCII));
                String ciphertext = encode(cipher.doFinal(payload));
                List<String> values = new ArrayList<>(count);
                int offset = 0;
                for (int index = 0; index < count; index++) {
                    int end = Math.min(ciphertext.length(), offset + capacities[index]);
                    values.add(framing + index + "." + ciphertext.substring(offset, end));
                    offset = end;
                }
                return new PreparedSession(values, retired, result.expiresAt());
            }
            throw new SessionCookieException("OIDC session exceeds the configured cookie storage capacity");
        } catch (IOException | GeneralSecurityException | DateTimeException e) {
            throw new SessionCookieException("Could not protect the OIDC session", e);
        }
    }

    List<SetCookie> localAuthenticationResultCookies(PreparedSession session, Instant now) {
        Duration maxAge = Duration.between(now, session.expiresAt());
        if (maxAge.isNegative()) {
            maxAge = Duration.ZERO;
        }
        List<SetCookie> cookies = new ArrayList<>();
        for (int index = 0; index < session.values().size(); index++) {
            SetCookie cookie = sessionCookie(index, session.values().get(index), session.expiresAt(), maxAge);
            if (cookie.toString().length() > cookieConfig.maxCookieSize()) {
                throw new SessionCookieException("OIDC session cookie exceeds cookies.max-cookie-size");
            }
            cookies.add(cookie);
        }
        session.retiredNames().forEach(name -> cookies.add(removeCookie(name)));
        long responseSize = cookies.stream().mapToLong(cookie -> cookie.toString().length() + 14L).sum();
        if (responseSize > cookieConfig.maxTotalSize()) {
            throw new SessionCookieException("OIDC session update exceeds the configured cookie header budget");
        }
        return List.copyOf(cookies);
    }

    boolean localAuthenticationCookiesPresent(Map<String, List<String>> cookies) {
        for (int index = 0; index < MAX_SESSION_COOKIES; index++) {
            if (cookies.containsKey(sessionCookieName(cookieConfig, index))) {
                return true;
            }
        }
        return false;
    }

    BrowserSessionGeneration createBrowserSessionGeneration() {
        byte[] randomValue = new byte[BROWSER_SESSION_GENERATION_BYTES];
        secureRandom.nextBytes(randomValue);
        String value = encode(randomValue);
        SetCookie cookie = cookieBuilder(browserSessionGenerationCookieName(),
                                         protect(OidcCookieKeys.Purpose.BROWSER_SESSION_GENERATION, value))
                .maxAge(cookieConfig.authenticationRequestLifetime().plus(cookieConfig.localAuthenticationLifetime()))
                .build();
        return new BrowserSessionGeneration(value, cookie);
    }

    String browserSessionGenerationCookieName() {
        return browserSessionGenerationCookieName(cookieConfig);
    }

    Optional<String> readBrowserSessionGeneration(String cookieValue) {
        try {
            String value = unprotect(OidcCookieKeys.Purpose.BROWSER_SESSION_GENERATION, cookieValue);
            byte[] decoded = decode(value);
            return decoded.length == BROWSER_SESSION_GENERATION_BYTES ? Optional.of(value) : Optional.empty();
        } catch (RuntimeException _) {
            return Optional.empty();
        }
    }

    List<SetCookie> removeLocalAuthenticationResultCookies() {
        return removeLocalAuthenticationResultCookies(cookieConfig);
    }

    SetCookie removeAuthenticationRequestCookie() {
        return removeCookie(cookieConfig.authenticationRequestCookieName());
    }

    Optional<OidcAuthenticationRequestState> readAuthenticationRequestState(String cookieValue, Instant now) {
        return decodeAuthenticationRequestState(cookieValue)
                .filter(state -> !now.isAfter(state.expiresAt()));
    }

    Optional<OidcLocalAuthenticationResult> readLocalAuthenticationResult(String cookieValue,
                                                                          Instant now,
                                                                          OidcIdTokenDecryptor idTokenDecryptor) {
        return decodeLocalAuthenticationResult(cookieValue, idTokenDecryptor)
                .filter(result -> !now.isAfter(result.expiresAt()));
    }

    Optional<OidcLocalAuthenticationResult> readLocalAuthenticationResult(Map<String, List<String>> cookies,
                                                                         Instant now,
                                                                         OidcIdTokenDecryptor idTokenDecryptor) {
        try {
            List<String> baseValues = cookies.getOrDefault(sessionCookieName(cookieConfig, 0), List.of());
            if (baseValues.size() != 1) {
                return Optional.empty();
            }
            long size = 0;
            int present = 0;
            for (int index = 0; index < MAX_SESSION_COOKIES; index++) {
                String name = sessionCookieName(cookieConfig, index);
                List<String> values = cookies.getOrDefault(name, List.of());
                if (values.size() > 1) {
                    return Optional.empty();
                }
                if (!values.isEmpty()) {
                    String value = values.getFirst();
                    long length = name.length() + 1L + value.length();
                    size += length + (present++ == 0 ? 0 : 2);
                    if (length > cookieConfig.maxCookieSize() || size > cookieConfig.maxTotalSize()) {
                        return Optional.empty();
                    }
                }
            }
            String base = baseValues.getFirst();
            String[] first = sessionParts(base);
            int count = Integer.parseInt(first[2]);
            if (count < 1 || count > cookieConfig.maxChunks() || count > MAX_SESSION_COOKIES
                    || !Integer.toString(count).equals(first[2])) {
                return Optional.empty();
            }
            String framing = String.join(".", first[0], first[1], first[2], first[3]) + ".";
            StringBuilder combined = new StringBuilder(framing).append("0.");
            for (int index = 0; index < count; index++) {
                List<String> values = cookies.getOrDefault(sessionCookieName(cookieConfig, index), List.of());
                if (values.size() != 1) {
                    return Optional.empty();
                }
                String value = values.getFirst();
                String prefix = framing + index + ".";
                if (!value.startsWith(prefix) || value.length() == prefix.length()) {
                    return Optional.empty();
                }
                combined.append(value, prefix.length(), value.length());
            }
            return readLocalAuthenticationResult(combined.toString(), now, idTokenDecryptor);
        } catch (RuntimeException _) {
            return Optional.empty();
        }
    }

    Optional<OidcAuthenticationRequestState> decodeAuthenticationRequestState(String cookieValue) {
        try {
            Optional<String> tenantHint = authenticationRequestTenantHint(cookieValue);
            if (cookieValue.startsWith(ROUTED_AUTHENTICATION_REQUEST_VERSION) && tenantHint.isEmpty()) {
                return Optional.empty();
            }
            String protectedValue = tenantHint
                    .map(_ -> cookieValue.substring(cookieValue.indexOf('.', ROUTED_AUTHENTICATION_REQUEST_VERSION.length()) + 1))
                    .orElse(cookieValue);
            JsonObject json = JsonParser.create(unprotect(OidcCookieKeys.Purpose.AUTHENTICATION_REQUEST, protectedValue))
                    .readJsonObject();
            OidcAuthenticationRequestState state = authenticationRequestStateFromJson(json);
            if (tenantHint.isPresent() && !tenantHint.orElseThrow().equals(state.tenantId())) {
                return Optional.empty();
            }
            return Optional.of(state);
        } catch (RuntimeException _) {
            return Optional.empty();
        }
    }

    Optional<OidcLocalAuthenticationResult> decodeLocalAuthenticationResult(String cookieValue,
                                                                            OidcIdTokenDecryptor idTokenDecryptor) {
        try {
            if (cookieValue.length() > cookieConfig.maxTotalSize()) {
                return Optional.empty();
            }
            String[] parts = sessionParts(cookieValue);
            int count = Integer.parseInt(parts[2]);
            if (count < 1 || count > cookieConfig.maxChunks() || count > MAX_SESSION_COOKIES
                    || !Integer.toString(count).equals(parts[2])
                    || !parts[4].equals("0")) {
                return Optional.empty();
            }
            byte[] iv = decode(parts[3]);
            if (iv.length != AES_GCM_IV_BYTES) {
                return Optional.empty();
            }
            Cipher cipher = cipher(Cipher.DECRYPT_MODE, iv, OidcCookieKeys.Purpose.LOCAL_AUTHENTICATION);
            String framing = String.join(".", parts[0], parts[1], parts[2], parts[3]) + ".";
            cipher.updateAAD(framing.getBytes(StandardCharsets.US_ASCII));
            byte[] payload = cipher.doFinal(decode(parts[5]));
            if (parts[1].equals("g")) {
                // Only authenticated payload reaches the decompressor. Read at most the configured bound plus one.
                try (GZIPInputStream gzip = new GZIPInputStream(new ByteArrayInputStream(payload))) {
                    payload = gzip.readNBytes(cookieConfig.maxSessionSize() + 1);
                }
            }
            if (payload.length > cookieConfig.maxSessionSize()) {
                return Optional.empty();
            }
            String jsonText = StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(payload)).toString();
            JsonObject json = JsonParser.create(jsonText).readJsonObject();
            return Optional.of(localAuthenticationResultFromJson(json, idTokenDecryptor));
        } catch (RuntimeException | GeneralSecurityException | IOException _) {
            return Optional.empty();
        }
    }

    private static SetCookie.Builder cookieBuilder(String name, String value) {
        return SetCookie.builder(name, value)
                .path("/")
                .httpOnly(true)
                .secure(true)
                .sameSite(SetCookie.SameSite.LAX);
    }

    private static SetCookie removeCookie(String name) {
        return cookieBuilder(name, "")
                .maxAge(Duration.ZERO)
                .expires(Instant.EPOCH)
                .build();
    }

    private static String[] sessionParts(String value) {
        String[] parts = value.split("\\.", 6);
        if (parts.length != 6 || !parts[0].equals("v2")
                || !(parts[1].equals("n") || parts[1].equals("g"))) {
            throw new IllegalArgumentException("Invalid OIDC session cookie format");
        }
        return parts;
    }

    private static String encode(byte[] value) {
        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(value);
    }

    private static byte[] decode(String value) {
        byte[] decoded = Base64.getUrlDecoder().decode(value);
        if (!encode(decoded).equals(value)) {
            throw new IllegalArgumentException("Invalid OIDC cookie encoding");
        }
        return decoded;
    }

    private SetCookie sessionCookie(int index, String value, Instant expiresAt, Duration maxAge) {
        return cookieBuilder(sessionCookieName(cookieConfig, index), value)
                .maxAge(maxAge)
                .expires(expiresAt)
                .build();
    }

    private JsonObject toJson(OidcAuthenticationRequestState state) {
        JsonObject.Builder builder = JsonObject.builder()
                .set("tenant_id", state.tenantId())
                .set("state", state.state())
                .set("expected_issuer", state.expectedIssuer())
                .set("original_uri", state.originalUri().toString())
                .set("redirection_endpoint_uri", state.redirectionEndpointUri().toString())
                .set("requested_scope", OidcScopeSupport.serializeScopes(state.requestedScopes()))
                .set("created_at", state.createdAt().toString())
                .set("expires_at", state.expiresAt().toString());
        if (state.nonce() != null) {
            builder.set("nonce", state.nonce());
        }
        state.pkceVerifier().ifPresent(pkceVerifier -> builder.set("pkce_verifier", pkceVerifier));
        state.browserSessionGeneration()
                .ifPresent(generation -> builder.set("browser_session_generation", generation));
        return builder.build();
    }

    private JsonObject toJson(OidcLocalAuthenticationResult result) {
        JsonObject.Builder builder = JsonObject.builder()
                .set("tenant_id", result.tenantId())
                .set("id_token", result.idToken().rawToken())
                .set("access_token", result.accessToken())
                .set("token_type", result.tokenType())
                .set("created_at", result.createdAt().toString())
                .set("expires_at", result.expiresAt().toString());
        result.refreshToken().ifPresent(refreshToken -> builder.set("refresh_token", refreshToken));
        result.browserSessionGeneration()
                .ifPresent(generation -> builder.set("browser_session_generation", generation));
        result.scope().ifPresent(scope -> builder.set("scope", scope));
        result.userInfo().ifPresent(userInfo -> builder.set("userinfo", userInfo));
        result.accessTokenExpiresAt()
                .ifPresent(accessTokenExpiresAt -> builder.set("access_token_expires_at",
                                                               accessTokenExpiresAt.toString()));
        return builder.build();
    }

    private OidcAuthenticationRequestState authenticationRequestStateFromJson(JsonObject json) {
        return new OidcAuthenticationRequestState(
                json.stringValue("tenant_id").orElseThrow(),
                json.stringValue("state").orElseThrow(),
                json.stringValue("nonce").orElse(null),
                json.stringValue("pkce_verifier").orElse(null),
                json.stringValue("browser_session_generation").orElse(null),
                json.stringValue("expected_issuer").orElseThrow(),
                URI.create(json.stringValue("original_uri").orElseThrow()),
                URI.create(json.stringValue("redirection_endpoint_uri").orElseThrow()),
                OidcScopeSupport.parseScopeString(json.stringValue("requested_scope").orElseThrow(),
                                                 "Authentication Request scope"),
                Instant.parse(json.stringValue("created_at").orElseThrow()),
                Instant.parse(json.stringValue("expires_at").orElseThrow()));
    }

    private OidcLocalAuthenticationResult localAuthenticationResultFromJson(JsonObject json,
                                                                            OidcIdTokenDecryptor idTokenDecryptor) {
        String rawIdToken = json.stringValue("id_token").orElseThrow();
        OidcIdTokenDecryptor.OidcResolvedIdToken resolvedIdToken = idTokenDecryptor.resolve(rawIdToken);
        SignedJwt signedJwt = resolvedIdToken.signedJwt();
        Jwt jwt = signedJwt.getJwt();
        OidcValidatedIdToken idToken = new OidcValidatedIdToken(rawIdToken,
                                                                resolvedIdToken.encrypted(),
                                                                signedJwt,
                                                                jwt);
        String tenantId = json.stringValue("tenant_id").orElseThrow();
        String accessToken = json.stringValue("access_token").orElseThrow();
        String tokenType = json.stringValue("token_type").orElseThrow();
        Instant createdAt = Instant.parse(json.stringValue("created_at").orElseThrow());
        Instant expiresAt = Instant.parse(json.stringValue("expires_at").orElseThrow());
        Optional<Instant> accessTokenExpiresAt = json.stringValue("access_token_expires_at").map(Instant::parse);
        OidcLocalAuthenticationState state = OidcLocalAuthenticationState.builder()
                .tenantId(tenantId)
                .idToken(idToken)
                .accessToken(accessToken)
                .tokenType(tokenType)
                .refreshToken(json.stringValue("refresh_token"))
                .browserSessionGeneration(json.stringValue("browser_session_generation"))
                .scope(json.stringValue("scope"))
                .userInfo(json.objectValue("userinfo"))
                .createdAt(createdAt)
                .expiresAt(expiresAt)
                .accessTokenExpiresAt(accessTokenExpiresAt)
                .buildPrototype();
        return OidcLocalAuthenticationResult.fromStoredValues(state);
    }

    private String protect(OidcCookieKeys.Purpose purpose, String value) {
        byte[] iv = new byte[AES_GCM_IV_BYTES];
        secureRandom.nextBytes(iv);
        try {
            byte[] ciphertext = cipher(Cipher.ENCRYPT_MODE, iv, purpose)
                    .doFinal(value.getBytes(StandardCharsets.UTF_8));
            return PROTECTED_COOKIE_VERSION + "."
                    + encode(iv) + "."
                    + encode(ciphertext);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to protect OIDC cookie state", e);
        }
    }

    private String unprotect(OidcCookieKeys.Purpose purpose, String value) {
        String[] parts = value.split("\\.", -1);
        if (parts.length != 3 || !PROTECTED_COOKIE_VERSION.equals(parts[0])) {
            throw new IllegalArgumentException("Unsupported OIDC cookie format");
        }
        byte[] iv = decode(parts[1]);
        byte[] ciphertext = decode(parts[2]);
        if (iv.length != AES_GCM_IV_BYTES || ciphertext.length < AES_GCM_TAG_BYTES) {
            throw new IllegalArgumentException("Invalid OIDC cookie format");
        }
        try {
            byte[] plaintext = cipher(Cipher.DECRYPT_MODE, iv, purpose).doFinal(ciphertext);
            return new String(plaintext, StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Failed to read OIDC cookie state", e);
        }
    }

    private Cipher cipher(int mode, byte[] iv, OidcCookieKeys.Purpose purpose) {
        try {
            OidcCookieKeys.KeyMaterial keyMaterial = keys.get().orElseThrow(
                    () -> new IllegalStateException("OIDC cookie protection is not configured"))
                    .keyMaterial(purpose);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(mode, keyMaterial.key(), new GCMParameterSpec(AES_GCM_TAG_BITS, iv));
            cipher.updateAAD(keyMaterial.additionalAuthenticatedData());
            return cipher;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to initialize OIDC cookie state protection", e);
        }
    }

    record BrowserSessionGeneration(String value, SetCookie cookie) {
    }

    record PreparedSession(List<String> values, List<String> retiredNames, Instant expiresAt) {
        PreparedSession {
            values = List.copyOf(values);
            retiredNames = List.copyOf(retiredNames);
            if (values.isEmpty() || values.size() + retiredNames.size() > MAX_SESSION_COOKIES) {
                throw new IllegalArgumentException("Invalid prepared session cookie set");
            }
        }

        @Override
        public String toString() {
            return "PreparedSession[parts=" + values.size() + ", expiresAt=" + expiresAt + "]";
        }
    }

    static final class SessionCookieException extends IllegalStateException {
        SessionCookieException(String message) {
            super(message);
        }

        SessionCookieException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
