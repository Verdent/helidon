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

import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Optional;

import io.helidon.common.configurable.Resource;
import io.helidon.security.jwt.jwk.Jwk;
import io.helidon.security.jwt.jwk.JwkKeys;
import io.helidon.security.jwt.jwk.JwkRSA;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class OidcRequestObjectProcessorTest {
    private static JwkRSA encryptionKey;
    private static Jwk signingKey;

    @BeforeAll
    static void setUpClass() {
        encryptionKey = (JwkRSA) JwkKeys.builder()
                .resource(Resource.create("oidc-next-encrypt-jwk.json"))
                .build()
                .forKeyId("encrypt-rsa")
                .orElseThrow();
        signingKey = JwkKeys.builder()
                .resource(Resource.create("oidc-next-sign-public-jwk.json"))
                .build()
                .forKeyId("sign-rsa")
                .orElseThrow();
    }

    @Test
    void automaticallySelectsFirstEligibleKey() {
        JwkKeys keys = JwkKeys.builder()
                .addKey(signingKey)
                .addKey(encryptionKey)
                .build();

        Jwk selected = OidcRequestObjectProcessor.selectEncryptionJwk(keys,
                                                                      Optional.empty(),
                                                                      "RSA-OAEP-256");

        assertThat(selected, is(encryptionKey));
    }

    @Test
    void selectsPinnedEligibleKey() {
        JwkKeys keys = JwkKeys.builder()
                .addKey(signingKey)
                .addKey(encryptionKey)
                .build();

        Jwk selected = OidcRequestObjectProcessor.selectEncryptionJwk(keys,
                                                                      Optional.of("encrypt-rsa"),
                                                                      "RSA-OAEP-256");

        assertThat(selected, is(encryptionKey));
    }

    @Test
    void rejectsPinnedIneligibleKeyWithoutExposingItsId() {
        JwkKeys keys = JwkKeys.builder()
                .addKey(signingKey)
                .addKey(encryptionKey)
                .build();

        IllegalStateException thrown = assertThrows(
                IllegalStateException.class,
                () -> OidcRequestObjectProcessor.selectEncryptionJwk(keys,
                                                                      Optional.of("sign-rsa"),
                                                                      "RSA-OAEP-256"));

        assertThat(thrown.getMessage(), is("Configured Request Object encryption key is not eligible for the selected "
                                                   + "algorithm"));
        assertThat(thrown.getMessage().contains("sign-rsa"), is(false));
    }

    @Test
    void rejectsWeakRsaKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024);
        Jwk weakKey = JwkRSA.builder()
                .publicKey((RSAPublicKey) generator.generateKeyPair().getPublic())
                .keyId("weak-rsa")
                .usage(Jwk.USE_ENCRYPTION)
                .build();

        assertThat(OidcRequestObjectProcessor.isEligibleEncryptionJwk(weakKey, "RSA-OAEP-256", 1), is(false));
    }

    @Test
    void rejectsConflictingDeclaredAlgorithm() {
        Jwk key = JwkRSA.builder()
                .publicKey((RSAPublicKey) encryptionKey.publicKey())
                .keyId("other-algorithm")
                .usage(Jwk.USE_ENCRYPTION)
                .algorithm("RSA-OAEP")
                .build();

        assertThat(OidcRequestObjectProcessor.isEligibleEncryptionJwk(key, "RSA-OAEP-256", 1), is(false));
    }

    @Test
    void rejectsIncompatibleKeyOperations() {
        Jwk key = JwkRSA.builder()
                .publicKey((RSAPublicKey) encryptionKey.publicKey())
                .keyId("verify-only")
                .addOperation(Jwk.OPERATION_VERIFY)
                .build();

        assertThat(OidcRequestObjectProcessor.isEligibleEncryptionJwk(key, "RSA-OAEP-256", 1), is(false));
    }

    @Test
    void acceptsEncryptionKeyOperations() {
        Jwk key = JwkRSA.builder()
                .publicKey((RSAPublicKey) encryptionKey.publicKey())
                .keyId("wrap-key")
                .addOperation(Jwk.OPERATION_WRAP_KEY)
                .build();

        assertThat(OidcRequestObjectProcessor.isEligibleEncryptionJwk(key, "RSA-OAEP-256", 1), is(true));
    }

    @Test
    void acceptsSingleEncryptionKeyWithoutKeyId() {
        Jwk key = JwkRSA.builder()
                .publicKey((RSAPublicKey) encryptionKey.publicKey())
                .usage(Jwk.USE_ENCRYPTION)
                .build();
        JwkKeys keys = JwkKeys.builder()
                .addKey(key)
                .build();

        assertThat(OidcRequestObjectProcessor.selectEncryptionJwk(keys,
                                                                  Optional.empty(),
                                                                  "RSA-OAEP-256"),
                   is(key));
    }
}
