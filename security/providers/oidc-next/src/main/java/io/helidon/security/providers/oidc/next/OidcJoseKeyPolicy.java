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

import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import io.helidon.common.Errors;
import io.helidon.common.configurable.ResourceConfig;
import io.helidon.json.JsonObject;
import io.helidon.security.jwt.Jwt;
import io.helidon.security.jwt.SignedJwt;
import io.helidon.security.jwt.jwk.Jwk;
import io.helidon.security.jwt.jwk.JwkEC;
import io.helidon.security.jwt.jwk.JwkKeys;
import io.helidon.security.jwt.jwk.JwkOctet;
import io.helidon.security.jwt.jwk.JwkRSA;

/**
 * Central JOSE algorithm, key-strength, and local key-source policy for OIDC operations.
 * <p>
 * RFC 7518 requires HMAC keys to contain at least as many bits as the hash output and RSA keys to contain at least
 * 2048 bits. RFC 7517 makes the JWK {@code alg} member optional. A declared algorithm therefore constrains a key, while
 * an omitted algorithm allows the separately validated operation algorithm to select a compatible use of that key.
 */
final class OidcJoseKeyPolicy {
    static final int MINIMUM_RSA_KEY_BITS = 2048;

    private static final Set<String> RSA_SIGNATURE_ALGORITHMS = Set.of(
            JwkRSA.ALG_RS256,
            JwkRSA.ALG_RS384,
            JwkRSA.ALG_RS512);
    private static final Set<String> RSA_KEY_MANAGEMENT_ALGORITHMS = Set.of(
            "RSA1_5",
            "RSA-OAEP",
            "RSA-OAEP-256");

    private OidcJoseKeyPolicy() {
    }

    static void validateLocalKeyResource(ResourceConfig resource, String configKey) {
        // Inspect the description before building a Resource; URI-backed Resource construction already opens the URL.
        if (resource.uri().isPresent()) {
            throw new IllegalArgumentException(configKey + " does not support URI sources; use path, resource-path, "
                                                       + "content, or content-plain");
        }
        if (resource.path().isEmpty() && resource.resourcePath().isEmpty()
                && resource.content().isEmpty() && resource.contentPlain().isEmpty()) {
            throw new IllegalArgumentException(configKey + " must configure path, resource-path, content, or content-plain");
        }
    }

    static void validateClientSecret(String clientSecret, String algorithm, String description) {
        byte[] key = clientSecret.getBytes(StandardCharsets.UTF_8);
        try {
            requireHmacKeyLength(key.length, algorithm, description, " UTF-8 octets");
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    static Jwk signingKey(Jwk jwk, Optional<String> configuredAlgorithm, String description) {
        String algorithm = configuredAlgorithm
                .or(jwk::declaredAlgorithm)
                .orElseGet(() -> defaultSigningAlgorithm(jwk));
        jwk.declaredAlgorithm()
                .filter(declared -> !declared.equals(algorithm))
                .ifPresent(declared -> {
                    throw new IllegalArgumentException(
                            description + " algorithm " + algorithm + " conflicts with JWK alg " + declared);
                });
        validateSigningKey(jwk, algorithm, description);
        return jwk.algorithm().equals(algorithm) ? jwk : withAlgorithm(jwk, algorithm);
    }

    static Errors verifySignature(SignedJwt signedJwt, Jwt jwt, JwkKeys keys) {
        String algorithm = jwt.algorithm()
                .orElseThrow(() -> new IllegalArgumentException(
                        "JWS alg header is required for signature verification"));
        Optional<String> keyId = jwt.keyId();
        if (keyId.isEmpty()) {
            List<Jwk> eligible = keys.keys()
                    .stream()
                    .filter(jwk -> isEligibleVerificationKey(jwk, algorithm))
                    .toList();
            if (eligible.size() != 1) {
                Errors.Collector collector = Errors.collector();
                collector.fatal(keys,
                                eligible.isEmpty()
                                        ? "JWK Set contains no eligible key for JWS without kid"
                                        : "JWK Set contains multiple eligible keys for JWS without kid");
                return collector.collect();
            }
            Jwk selected = eligible.getFirst();
            Jwk effectiveJwk = selected.algorithm().equals(algorithm)
                    ? selected
                    : withAlgorithm(selected, algorithm);
            return signedJwt.verifySignature(JwkKeys.builder().build(), effectiveJwk);
        }
        Optional<Jwk> selected = keys.forKeyId(keyId.orElseThrow());
        if (selected.isEmpty()) {
            return signedJwt.verifySignature(keys);
        }
        Jwk jwk = selected.orElseThrow();
        if (jwk.declaredAlgorithm().filter(declared -> !declared.equals(algorithm)).isPresent()) {
            return signedJwt.verifySignature(keys);
        }
        validateVerificationKey(jwk, algorithm);
        Jwk effectiveJwk = jwk.algorithm().equals(algorithm) ? jwk : withAlgorithm(jwk, algorithm);
        return signedJwt.verifySignature(JwkKeys.builder().addKey(effectiveJwk).build());
    }

    static Errors verifyOidcSignature(SignedJwt signedJwt, Jwt jwt, JwkKeys keys) {
        /*
         * OpenID Connect Core 1.0, 10.1 Signing, requires kid when the referenced JWK Set contains multiple keys.
         */
        if (jwt.keyId().isEmpty() && keys.keys().size() != 1) {
            Errors.Collector collector = Errors.collector();
            collector.fatal(keys,
                            "OpenID Connect JWS without kid requires a JWK Set containing exactly one key");
            return collector.collect();
        }
        return verifySignature(signedJwt, jwt, keys);
    }

    static void validateConfiguredRsaKey(Jwk jwk, String description) {
        if (jwk instanceof JwkRSA rsa) {
            requireMinimumRsaKey(rsa, description);
        }
    }

    static void validateRsaDecryptionKey(Jwk jwk, String algorithm, String description) {
        if (!(jwk instanceof JwkRSA rsa)) {
            throw new IllegalStateException(description + " must be an RSA key");
        }
        if (!RSA_KEY_MANAGEMENT_ALGORITHMS.contains(algorithm)) {
            throw new IllegalStateException(description + " cannot be used with JWE algorithm " + algorithm);
        }
        if (jwk.declaredAlgorithm().filter(declared -> !declared.equals(algorithm)).isPresent()) {
            throw new IllegalStateException(description + " alg does not match JWE algorithm " + algorithm);
        }
        if (rsa.privateKey().isEmpty()) {
            throw new IllegalStateException(description + " must contain an RSA private key");
        }
        requireMinimumRsaKey(rsa, description);
    }

    static boolean isEligibleRsaEncryptionKey(Jwk jwk, String algorithm) {
        if (!(jwk instanceof JwkRSA rsa)
                || !(rsa.publicKey() instanceof RSAPublicKey)
                || !RSA_KEY_MANAGEMENT_ALGORITHMS.contains(algorithm)
                || rsaKeyBits(rsa) < MINIMUM_RSA_KEY_BITS) {
            return false;
        }
        return jwk.declaredAlgorithm().filter(declared -> !declared.equals(algorithm)).isEmpty();
    }

    private static void validateSigningKey(Jwk jwk, String algorithm, String description) {
        if (jwk.usage().filter(usage -> !Jwk.USE_SIGNATURE.equals(usage)).isPresent()) {
            throw new IllegalArgumentException(description + " JWK use must be sig");
        }
        if (jwk.operations().filter(operations -> !operations.contains(Jwk.OPERATION_SIGN)).isPresent()) {
            throw new IllegalArgumentException(description + " JWK key_ops must allow sign");
        }
        switch (jwk) {
        case JwkRSA rsa -> {
            if (!RSA_SIGNATURE_ALGORITHMS.contains(algorithm)) {
                throw new IllegalArgumentException(description + " RSA key cannot use algorithm " + algorithm);
            }
            if (rsa.privateKey().isEmpty()) {
                throw new IllegalArgumentException(description + " must contain an RSA private key");
            }
            requireMinimumRsaKey(rsa, description);
        }
        case JwkEC ec -> {
            if (ec.privateKey().isEmpty()) {
                throw new IllegalArgumentException(description + " must contain an EC private key");
            }
            requireCompatibleEcAlgorithm(ec, algorithm, description);
        }
        case JwkOctet octet -> validateHmacJwk(octet, algorithm, description);
        default -> throw new IllegalArgumentException(description + " has an unsupported JWK type");
        }
    }

    private static String defaultSigningAlgorithm(Jwk jwk) {
        return switch (jwk) {
        case JwkRSA _ -> JwkRSA.ALG_RS256;
        case JwkEC ec when ec.publicKey() instanceof ECPublicKey publicKey ->
            switch (publicKey.getParams().getCurve().getField().getFieldSize()) {
            case 256 -> JwkEC.ALG_ES256;
            case 384 -> JwkEC.ALG_ES384;
            case 521 -> JwkEC.ALG_ES512;
            default -> throw new IllegalArgumentException("Unsupported EC curve for OIDC signing");
            };
        case JwkOctet _ -> JwkOctet.ALG_HS256;
        default -> throw new IllegalArgumentException("Unsupported JWK type for OIDC signing");
        };
    }

    private static void validateVerificationKey(Jwk jwk, String algorithm) {
        if (jwk.usage().filter(usage -> !Jwk.USE_SIGNATURE.equals(usage)).isPresent()) {
            throw new IllegalArgumentException("Verification JWK use must be sig");
        }
        if (jwk.operations().filter(operations -> !operations.contains(Jwk.OPERATION_VERIFY)).isPresent()) {
            throw new IllegalArgumentException("Verification JWK key_ops must allow verify");
        }
        switch (jwk) {
        case JwkRSA rsa -> {
            if (!RSA_SIGNATURE_ALGORITHMS.contains(algorithm)) {
                throw new IllegalArgumentException("RSA verification JWK cannot use algorithm " + algorithm);
            }
            requireMinimumRsaKey(rsa, "RSA verification JWK");
        }
        case JwkEC ec -> requireCompatibleEcAlgorithm(ec, algorithm, "EC verification JWK");
        case JwkOctet octet -> validateHmacJwk(octet, algorithm, "HMAC verification JWK");
        default -> throw new IllegalArgumentException("Unsupported JWK type for signature verification");
        }
    }

    private static boolean isEligibleVerificationKey(Jwk jwk, String algorithm) {
        if (jwk.declaredAlgorithm().filter(declared -> !declared.equals(algorithm)).isPresent()) {
            return false;
        }
        try {
            validateVerificationKey(jwk, algorithm);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static void validateHmacJwk(JwkOctet jwk, String algorithm, String description) {
        byte[] key = jwk.getKeyBytes();
        try {
            requireHmacKeyLength(key.length, algorithm, description, " octets");
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    private static void requireHmacKeyLength(int keyLength,
                                             String algorithm,
                                             String description,
                                             String unit) {
        int minimum = switch (algorithm) {
        case JwkOctet.ALG_HS256 -> 32;
        case JwkOctet.ALG_HS384 -> 48;
        case JwkOctet.ALG_HS512 -> 64;
        default -> throw new IllegalArgumentException(description + " cannot use HMAC algorithm " + algorithm);
        };
        if (keyLength < minimum) {
            throw new IllegalArgumentException(
                    description + " must contain at least " + minimum + unit + " for " + algorithm);
        }
    }

    private static void requireMinimumRsaKey(JwkRSA rsa, String description) {
        int keyBits = rsaKeyBits(rsa);
        if (keyBits < MINIMUM_RSA_KEY_BITS) {
            throw new IllegalArgumentException(
                    description + " RSA modulus must contain at least " + MINIMUM_RSA_KEY_BITS + " bits");
        }
    }

    private static int rsaKeyBits(JwkRSA rsa) {
        if (rsa.publicKey() instanceof RSAKey rsaKey) {
            return rsaKey.getModulus().bitLength();
        }
        return 0;
    }

    private static void requireCompatibleEcAlgorithm(JwkEC ec, String algorithm, String description) {
        int expectedFieldSize = switch (algorithm) {
        case JwkEC.ALG_ES256 -> 256;
        case JwkEC.ALG_ES384 -> 384;
        case JwkEC.ALG_ES512 -> 521;
        default -> throw new IllegalArgumentException(description + " EC key cannot use algorithm " + algorithm);
        };
        if (!(ec.publicKey() instanceof ECPublicKey publicKey)
                || publicKey.getParams().getCurve().getField().getFieldSize() != expectedFieldSize) {
            throw new IllegalArgumentException(description + " curve does not match algorithm " + algorithm);
        }
    }

    private static Jwk withAlgorithm(Jwk jwk, String algorithm) {
        return switch (jwk) {
        case JwkRSA rsa -> copyRsaWithAlgorithm(rsa, algorithm);
        case JwkEC ec -> copyEcWithAlgorithm(ec, algorithm);
        case JwkOctet octet -> copyOctetWithAlgorithm(octet, algorithm);
        default -> throw new IllegalArgumentException("Unsupported JWK type for algorithm selection");
        };
    }

    private static Jwk copyRsaWithAlgorithm(JwkRSA original, String algorithm) {
        JwkRSA.Builder builder = JwkRSA.builder()
                .publicKey((RSAPublicKey) original.publicKey())
                .algorithm(algorithm);
        original.privateKey().map(RSAPrivateKey.class::cast).ifPresent(builder::privateKey);
        copyRsaMetadata(original, builder);
        return builder.build();
    }

    private static void copyRsaMetadata(Jwk original, JwkRSA.Builder builder) {
        if (original.keyId() != null) {
            builder.keyId(original.keyId());
        }
        original.usage().ifPresent(builder::usage);
        original.operations().ifPresent(builder::operations);
    }

    private static Jwk copyEcWithAlgorithm(JwkEC original, String algorithm) {
        JwkEC.Builder builder = JwkEC.builder()
                .publicKey((ECPublicKey) original.publicKey())
                .algorithm(algorithm);
        original.privateKey().map(ECPrivateKey.class::cast).ifPresent(builder::privateKey);
        if (original.keyId() != null) {
            builder.keyId(original.keyId());
        }
        original.usage().ifPresent(builder::usage);
        original.operations().ifPresent(builder::operations);
        return builder.build();
    }

    private static Jwk copyOctetWithAlgorithm(JwkOctet original, String algorithm) {
        byte[] key = original.getKeyBytes();
        try {
            JsonObject.Builder builder = JsonObject.builder()
                    .set("kty", Jwk.KEY_TYPE_OCT)
                    .set("alg", algorithm)
                    .set("k", Base64.getUrlEncoder().withoutPadding().encodeToString(key));
            if (original.keyId() != null) {
                builder.set("kid", original.keyId());
            }
            original.usage().ifPresent(usage -> builder.set("use", usage));
            original.operations().ifPresent(operations -> builder.setStrings("key_ops", operations));
            return JwkOctet.create(builder.build());
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }
}
