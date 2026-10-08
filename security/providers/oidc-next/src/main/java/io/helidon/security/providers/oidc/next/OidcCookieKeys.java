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

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import javax.crypto.KDF;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.HKDFParameterSpec;
import javax.crypto.spec.PBEKeySpec;

/**
 * Derives tenant-bound, purpose-specific cookie keys from the configured password.
 * <p>
 * PBKDF2 provides the intentionally expensive password-hardening stage. HKDF then provides cryptographic domain
 * separation: Authentication Request, local authentication, and browser-session generation cookies never use the same
 * AES key. This object is created behind {@link io.helidon.common.LazyValue}; derivation therefore happens on first
 * cookie use, not during server startup, and a retained handler performs it only once.
 */
final class OidcCookieKeys {
    static final int MIN_PASSWORD_LENGTH = 16;
    static final int MAX_PASSWORD_LENGTH = 1024;
    private static final int PBKDF2_ITERATIONS = 600_000;
    private static final int SALT_BYTES = 16;

    private static final int AES_KEY_BITS = 256;
    private static final int AES_KEY_BYTES = AES_KEY_BITS / Byte.SIZE;
    private static final String PASSWORD_SALT_CONTEXT =
            "io.helidon.security.providers.oidc.next/cookie-password-salt/v1";
    private static final String AUTHENTICATION_REQUEST_CONTEXT =
            "io.helidon.security.providers.oidc.next/cookie/aes-256-gcm/authentication-request/v1";
    private static final String LOCAL_AUTHENTICATION_CONTEXT =
            "io.helidon.security.providers.oidc.next/cookie/aes-256-gcm/local-authentication/v1";
    private static final String BROWSER_SESSION_GENERATION_CONTEXT =
            "io.helidon.security.providers.oidc.next/cookie/aes-256-gcm/browser-session-generation/v1";

    private final KeyMaterial authenticationRequest;
    private final KeyMaterial localAuthentication;
    private final KeyMaterial browserSessionGeneration;

    private OidcCookieKeys(KeyMaterial authenticationRequest,
                           KeyMaterial localAuthentication,
                           KeyMaterial browserSessionGeneration) {
        this.authenticationRequest = authenticationRequest;
        this.localAuthentication = localAuthentication;
        this.browserSessionGeneration = browserSessionGeneration;
    }

    static Optional<OidcCookieKeys> create(String tenantId, OidcTenantConfig tenantConfig) {
        return tenantConfig.cookies()
                .password()
                .map(password -> create(tenantId,
                                        tenantConfig.clientId().orElseThrow(() -> new IllegalArgumentException(
                                                "client-id must be configured when cookies.password is configured")),
                                        password));
    }

    KeyMaterial keyMaterial(Purpose purpose) {
        return switch (purpose) {
        case AUTHENTICATION_REQUEST -> authenticationRequest;
        case LOCAL_AUTHENTICATION -> localAuthentication;
        case BROWSER_SESSION_GENERATION -> browserSessionGeneration;
        };
    }

    private static OidcCookieKeys create(String tenantId,
                                         String clientId,
                                         String passwordValue) {
        /*
         * The salt is deterministic so independently started replicas derive identical keys without shared storage.
         * Each deployment must use its own strong cookie password to prevent sharing keys with another deployment.
         */
        byte[] salt = derivedSalt(tenantId, clientId);
        char[] password = passwordValue.toCharArray();
        PBEKeySpec keySpec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, AES_KEY_BITS);
        byte[] masterKey = null;
        try {
            masterKey = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(keySpec)
                    .getEncoded();
            KDF hkdf = KDF.getInstance("HKDF-SHA256");
            byte[] authenticationRequestContext = context(AUTHENTICATION_REQUEST_CONTEXT, tenantId, clientId);
            byte[] localAuthenticationContext = context(LOCAL_AUTHENTICATION_CONTEXT, tenantId, clientId);
            byte[] browserSessionGenerationContext = context(BROWSER_SESSION_GENERATION_CONTEXT, tenantId, clientId);
            /*
             * Each full extract-and-expand operation deliberately uses a distinct context value. Reusing an AES key
             * across cookie types would allow a value valid in one protocol role to reach another role's parser.
             */
            return new OidcCookieKeys(
                    new KeyMaterial(deriveKey(hkdf, masterKey, authenticationRequestContext),
                                    authenticationRequestContext),
                    new KeyMaterial(deriveKey(hkdf, masterKey, localAuthenticationContext),
                                    localAuthenticationContext),
                    new KeyMaterial(deriveKey(hkdf, masterKey, browserSessionGenerationContext),
                                    browserSessionGenerationContext));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to derive OIDC cookie protection keys", e);
        } finally {
            // The generated configuration retains the password String; clear every additional mutable copy we own.
            keySpec.clearPassword();
            Arrays.fill(password, '\0');
            if (masterKey != null) {
                Arrays.fill(masterKey, (byte) 0);
            }
        }
    }

    private static SecretKey deriveKey(KDF hkdf, byte[] masterKey, byte[] context) throws GeneralSecurityException {
        HKDFParameterSpec parameters = HKDFParameterSpec.ofExtract()
                .addIKM(masterKey)
                .thenExpand(context, AES_KEY_BYTES);
        return hkdf.deriveKey("AES", parameters);
    }

    private static byte[] derivedSalt(String tenantId, String clientId) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(context(PASSWORD_SALT_CONTEXT, tenantId, clientId));
            return Arrays.copyOf(digest, SALT_BYTES);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to derive OIDC cookie protection salt", e);
        }
    }

    /**
     * Length prefixes make the context unambiguous. Without them, identities such as tenant {@code ab}, client
     * {@code c} and tenant {@code a}, client {@code bc} would have the same byte concatenation. The context is used
     * both for HKDF domain separation and as AES-GCM additional authenticated data, so a cookie cannot be moved to a
     * different tenant, client, cookie purpose, algorithm, or format version.
     */
    private static byte[] context(String domain, String tenantId, String clientId) {
        List<byte[]> components = List.of(domain, tenantId, clientId)
                .stream()
                .map(value -> value.getBytes(StandardCharsets.UTF_8))
                .toList();
        int length = components.stream()
                .mapToInt(component -> Math.addExact(Integer.BYTES, component.length))
                .reduce(0, Math::addExact);
        ByteBuffer buffer = ByteBuffer.allocate(length);
        components.forEach(component -> buffer.putInt(component.length).put(component));
        return buffer.array();
    }

    enum Purpose {
        AUTHENTICATION_REQUEST,
        LOCAL_AUTHENTICATION,
        BROWSER_SESSION_GENERATION
    }

    record KeyMaterial(SecretKey key, byte[] additionalAuthenticatedData) {
        KeyMaterial {
            additionalAuthenticatedData = additionalAuthenticatedData.clone();
        }

        @Override
        public byte[] additionalAuthenticatedData() {
            return additionalAuthenticatedData.clone();
        }
    }
}
