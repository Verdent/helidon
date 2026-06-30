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

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import io.helidon.http.SetCookie;
import io.helidon.json.JsonObject;
import io.helidon.json.JsonParser;
import io.helidon.security.jwt.Jwt;
import io.helidon.security.jwt.SignedJwt;

final class OidcCookieStateHandler {
    private static final String PROTECTED_COOKIE_VERSION = "v1";
    private static final int AES_GCM_KEY_BYTES = 32;
    private static final int AES_GCM_TAG_BITS = 128;
    private static final int AES_GCM_IV_BYTES = 12;

    private final OidcCookieConfig cookieConfig;
    private final byte[] encryptionKey;
    private final SecureRandom secureRandom;

    private OidcCookieStateHandler(OidcCookieConfig cookieConfig,
                                   byte[] encryptionKey,
                                   SecureRandom secureRandom) {
        this.cookieConfig = cookieConfig;
        this.encryptionKey = encryptionKey;
        this.secureRandom = secureRandom;
    }

    static OidcCookieStateHandler create(OidcCookieConfig cookieConfig) {
        return new OidcCookieStateHandler(cookieConfig,
                                          encryptionKey(cookieConfig),
                                          new SecureRandom());
    }

    OidcCookieConfig cookieConfig() {
        return cookieConfig;
    }

    SetCookie createAuthenticationRequestCookie(OidcAuthenticationRequestState state) {
        return cookieBuilder(cookieConfig.authenticationRequestCookieName(), protect(toJson(state).toString()))
                .maxAge(cookieConfig.authenticationRequestLifetime())
                .build();
    }

    SetCookie createLocalAuthenticationResultCookie(OidcLocalAuthenticationResult result) {
        Duration maxAge = Duration.between(result.createdAt(), result.expiresAt());
        if (maxAge.isNegative()) {
            maxAge = Duration.ZERO;
        }
        return cookieBuilder(cookieConfig.localAuthenticationCookieName(), protect(toJson(result).toString()))
                .maxAge(maxAge)
                .build();
    }

    SetCookie removeLocalAuthenticationResultCookie() {
        return removeCookie(cookieConfig.localAuthenticationCookieName());
    }

    SetCookie removeAuthenticationRequestCookie() {
        return removeCookie(cookieConfig.authenticationRequestCookieName());
    }

    private SetCookie.Builder cookieBuilder(String name, String value) {
        return SetCookie.builder(name, value)
                .path("/")
                .httpOnly(true)
                .secure(true)
                .sameSite(SetCookie.SameSite.LAX);
    }

    private SetCookie removeCookie(String name) {
        return cookieBuilder(name, "")
                .maxAge(Duration.ZERO)
                .expires(Instant.EPOCH)
                .build();
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

    Optional<OidcAuthenticationRequestState> decodeAuthenticationRequestState(String cookieValue) {
        try {
            JsonObject json = JsonParser.create(unprotect(cookieValue)).readJsonObject();
            return Optional.of(authenticationRequestStateFromJson(json));
        } catch (RuntimeException _) {
            return Optional.empty();
        }
    }

    Optional<OidcLocalAuthenticationResult> decodeLocalAuthenticationResult(String cookieValue,
                                                                            OidcIdTokenDecryptor idTokenDecryptor) {
        try {
            JsonObject json = JsonParser.create(unprotect(cookieValue)).readJsonObject();
            return Optional.of(localAuthenticationResultFromJson(json, idTokenDecryptor));
        } catch (RuntimeException _) {
            return Optional.empty();
        }
    }

    private JsonObject toJson(OidcAuthenticationRequestState state) {
        JsonObject.Builder builder = JsonObject.builder()
                .set("tenant_id", state.tenantId())
                .set("state", state.state())
                .set("nonce", state.nonce())
                .set("expected_issuer", state.expectedIssuer())
                .set("original_uri", state.originalUri().toString())
                .set("redirection_endpoint_uri", state.redirectionEndpointUri().toString())
                .set("created_at", state.createdAt().toString())
                .set("expires_at", state.expiresAt().toString());
        state.pkceVerifier().ifPresent(pkceVerifier -> builder.set("pkce_verifier", pkceVerifier));
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
                json.stringValue("nonce").orElseThrow(),
                json.stringValue("pkce_verifier").orElse(null),
                json.stringValue("expected_issuer").orElseThrow(),
                URI.create(json.stringValue("original_uri").orElseThrow()),
                URI.create(json.stringValue("redirection_endpoint_uri").orElseThrow()),
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
                .scope(json.stringValue("scope"))
                .userInfo(json.objectValue("userinfo"))
                .createdAt(createdAt)
                .expiresAt(expiresAt)
                .accessTokenExpiresAt(accessTokenExpiresAt)
                .buildPrototype();
        return OidcLocalAuthenticationResult.fromStoredValues(state);
    }

    private String protect(String value) {
        byte[] iv = new byte[AES_GCM_IV_BYTES];
        secureRandom.nextBytes(iv);
        try {
            byte[] ciphertext = cipher(Cipher.ENCRYPT_MODE, iv).doFinal(value.getBytes(StandardCharsets.UTF_8));
            return PROTECTED_COOKIE_VERSION + "."
                    + encode(iv) + "."
                    + encode(ciphertext);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to protect OIDC cookie state", e);
        }
    }

    private String unprotect(String value) {
        String[] parts = value.split("\\.");
        if (parts.length != 3 || !PROTECTED_COOKIE_VERSION.equals(parts[0])) {
            throw new IllegalArgumentException("Unsupported OIDC cookie format");
        }
        byte[] iv = decode(parts[1]);
        byte[] ciphertext = decode(parts[2]);
        try {
            byte[] plaintext = cipher(Cipher.DECRYPT_MODE, iv).doFinal(ciphertext);
            return new String(plaintext, StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Failed to read OIDC cookie state", e);
        }
    }

    private Cipher cipher(int mode, byte[] iv) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(mode, new SecretKeySpec(encryptionKey, "AES"), new GCMParameterSpec(AES_GCM_TAG_BITS, iv));
            return cipher;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to initialize OIDC cookie state protection", e);
        }
    }

    private static byte[] encryptionKey(OidcCookieConfig cookieConfig) {
        return cookieConfig.encryptionSecret()
                .map(secret -> sha256(secret.getBytes(StandardCharsets.UTF_8)))
                .orElseGet(OidcCookieStateHandler::randomKey);
    }

    private static byte[] randomKey() {
        byte[] bytes = new byte[AES_GCM_KEY_BYTES];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    private static byte[] sha256(byte[] value) {
        try {
            return Arrays.copyOf(MessageDigest.getInstance("SHA-256").digest(value), AES_GCM_KEY_BYTES);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    private static String encode(byte[] value) {
        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(value);
    }

    private static byte[] decode(String value) {
        return Base64.getUrlDecoder().decode(value);
    }
}
