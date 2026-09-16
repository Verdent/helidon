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

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import io.helidon.common.configurable.Resource;
import io.helidon.security.jwt.Jwt;
import io.helidon.security.jwt.SignedJwt;
import io.helidon.security.jwt.jwk.Jwk;
import io.helidon.security.jwt.jwk.JwkKeys;
import io.helidon.security.jwt.jwk.JwkRSA;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class OidcJoseKeyPolicyTest {
    private static KeyPair weakRsa;
    private static KeyPair minimumRsa;

    @BeforeAll
    static void generateKeys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024);
        weakRsa = generator.generateKeyPair();
        generator.initialize(OidcJoseKeyPolicy.MINIMUM_RSA_KEY_BITS);
        minimumRsa = generator.generateKeyPair();
    }

    @Test
    void enforcesHmacHashOutputMinimumInUtf8Octets() {
        for (Map.Entry<String, Integer> requirement : Map.of("HS256", 32, "HS384", 48, "HS512", 64).entrySet()) {
            String algorithm = requirement.getKey();
            int minimumOctets = requirement.getValue();
            IllegalArgumentException failure = assertThrows(
                    IllegalArgumentException.class,
                    () -> OidcJoseKeyPolicy.validateClientSecret("a".repeat(minimumOctets - 1),
                                                                 algorithm,
                                                                 "client-secret"));

            assertThat(failure.getMessage(), containsString(Integer.toString(minimumOctets)));
            assertDoesNotThrow(() -> OidcJoseKeyPolicy.validateClientSecret("a".repeat(minimumOctets),
                                                                           algorithm,
                                                                           "client-secret"));
        }
    }

    @Test
    void hmacMinimumCountsUtf8OctetsRatherThanCharacters() {
        assertThrows(IllegalArgumentException.class,
                     () -> OidcJoseKeyPolicy.validateClientSecret("é".repeat(15), "HS256", "client-secret"));
        assertDoesNotThrow(
                () -> OidcJoseKeyPolicy.validateClientSecret("é".repeat(16), "HS256", "client-secret"));
    }

    @Test
    void omittedJwkAlgorithmUsesConfiguredRsaSigningAndVerificationAlgorithm() {
        for (String algorithm : List.of("RS256", "RS384", "RS512")) {
            Jwk signingKey = OidcJoseKeyPolicy.signingKey(rsa(minimumRsa, null, true),
                                                          Optional.of(algorithm),
                                                          "signing JWK");
            Jwt jwt = Jwt.builder()
                    .algorithm(algorithm)
                    .keyId("rsa")
                    .subject("subject")
                    .build();
            SignedJwt signedJwt = SignedJwt.sign(jwt, signingKey);
            JwkKeys verificationKeys = JwkKeys.builder()
                    .addKey(rsa(minimumRsa, null, false))
                    .build();

            assertThat(signingKey.algorithm(), is(algorithm));
            assertThat(OidcJoseKeyPolicy.verifySignature(signedJwt, jwt, verificationKeys).isValid(), is(true));
        }
    }

    @Test
    void rejectsWeakRsaForEverySignatureAlgorithm() {
        for (String algorithm : List.of("RS256", "RS384", "RS512")) {
            JwkRSA weakUndeclared = rsa(weakRsa, null, true);
            IllegalArgumentException signingFailure = assertThrows(
                    IllegalArgumentException.class,
                    () -> OidcJoseKeyPolicy.signingKey(weakUndeclared, Optional.of(algorithm), "signing JWK"));
            assertThat(signingFailure.getMessage(), containsString("2048"));

            JwkRSA weakDeclared = rsa(weakRsa, algorithm, true);
            Jwt jwt = Jwt.builder()
                    .algorithm(algorithm)
                    .keyId("rsa")
                    .subject("subject")
                    .build();
            SignedJwt weaklySigned = SignedJwt.sign(jwt, weakDeclared);
            JwkKeys weakVerificationKeys = JwkKeys.builder()
                    .addKey(rsa(weakRsa, algorithm, false))
                    .build();

            IllegalArgumentException verificationFailure = assertThrows(
                    IllegalArgumentException.class,
                    () -> OidcJoseKeyPolicy.verifySignature(weaklySigned, jwt, weakVerificationKeys));
            assertThat(verificationFailure.getMessage(), containsString("2048"));
        }
    }

    @Test
    void enforcesRsaMinimumForEveryConfiguredKeyManagementAlgorithm() {
        for (String algorithm : List.of("RSA1_5", "RSA-OAEP", "RSA-OAEP-256")) {
            JwkRSA weakKey = rsa(weakRsa, null, true);
            JwkRSA minimumKey = rsa(minimumRsa, null, true);

            assertThat(OidcJoseKeyPolicy.isEligibleRsaEncryptionKey(weakKey, algorithm), is(false));
            assertThat(OidcJoseKeyPolicy.isEligibleRsaEncryptionKey(minimumKey, algorithm), is(true));
            assertThrows(IllegalArgumentException.class,
                         () -> OidcJoseKeyPolicy.validateRsaDecryptionKey(weakKey, algorithm, "decryption JWK"));
            assertDoesNotThrow(
                    () -> OidcJoseKeyPolicy.validateRsaDecryptionKey(minimumKey, algorithm, "decryption JWK"));
        }
    }

    @Test
    void explicitlyDeclaredAlgorithmStillConstrainsKey() {
        JwkRSA declaredRs256 = rsa(minimumRsa, "RS256", true);

        IllegalArgumentException failure = assertThrows(
                IllegalArgumentException.class,
                () -> OidcJoseKeyPolicy.signingKey(declaredRs256, Optional.of("RS384"), "signing JWK"));

        assertThat(failure.getMessage(), containsString("conflicts with JWK alg RS256"));
    }

    @Test
    void explicitlyDeclaredVerificationAlgorithmMustMatchJwsHeader() {
        Jwt jwt = Jwt.builder()
                .algorithm("RS384")
                .keyId("rsa")
                .subject("subject")
                .build();
        SignedJwt signedJwt = SignedJwt.sign(jwt, rsa(minimumRsa, "RS384", true));
        JwkKeys verificationKeys = JwkKeys.builder()
                .addKey(rsa(minimumRsa, "RS256", false))
                .build();

        assertThat(OidcJoseKeyPolicy.verifySignature(signedJwt, jwt, verificationKeys).isValid(), is(false));
    }

    @Test
    void acceptsRsaAtExactly2048BitsAndRejects1024BitConfiguredKey() {
        assertDoesNotThrow(
                () -> OidcJoseKeyPolicy.validateConfiguredRsaKey(rsa(minimumRsa, null, false), "configured JWK"));
        IllegalArgumentException failure = assertThrows(
                IllegalArgumentException.class,
                () -> OidcJoseKeyPolicy.validateConfiguredRsaKey(rsa(weakRsa, null, false), "configured JWK"));

        assertThat(failure.getMessage(), containsString("2048"));
    }

    @Test
    void configuredJweDecryptionKeysEnforceRsaMinimumDuringConstruction() {
        IllegalArgumentException failure = assertThrows(
                IllegalArgumentException.class,
                () -> OidcJweDecryptor.create(Optional.of(rsaResource(weakRsa)), "decryption-jwk", "token"));

        assertThat(failure.getMessage(), containsString("2048"));
        assertDoesNotThrow(
                () -> OidcJweDecryptor.create(Optional.of(rsaResource(minimumRsa)), "decryption-jwk", "token"));
    }

    private static JwkRSA rsa(KeyPair keyPair, String algorithm, boolean includePrivateKey) {
        JwkRSA.Builder builder = JwkRSA.builder()
                .keyId("rsa")
                .publicKey((RSAPublicKey) keyPair.getPublic());
        if (includePrivateKey) {
            builder.privateKey((RSAPrivateKey) keyPair.getPrivate());
        }
        if (algorithm != null) {
            builder.algorithm(algorithm);
        }
        return builder.build();
    }

    private static Resource rsaResource(KeyPair keyPair) {
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        String json = "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"rsa\",\"n\":\""
                + base64Url(publicKey.getModulus())
                + "\",\"e\":\"" + base64Url(publicKey.getPublicExponent())
                + "\",\"d\":\"" + base64Url(privateKey.getPrivateExponent()) + "\"}]}";
        return Resource.create("RSA test JWK", json);
    }

    private static String base64Url(BigInteger value) {
        byte[] signed = value.toByteArray();
        byte[] unsigned = signed.length > 1 && signed[0] == 0
                ? Arrays.copyOfRange(signed, 1, signed.length)
                : signed;
        return Base64.getUrlEncoder().withoutPadding().encodeToString(unsigned);
    }
}
