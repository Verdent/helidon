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

import java.security.interfaces.RSAPublicKey;

import io.helidon.json.JsonObject;
import io.helidon.security.jwt.jwk.JwkKeys;
import io.helidon.security.jwt.jwk.JwkRSA;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.util.Base64URL;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

final class OidcTestJwe {
    private OidcTestJwe() {
    }

    static String encrypt(String payload, JwkKeys keys, boolean nested, JsonObject additionalHeaders) throws JOSEException {
        JsonObject.Builder headers = JsonObject.builder()
                .set("alg", "RSA-OAEP-256")
                .set("enc", "A256GCM")
                .set("kid", "encrypt-rsa");
        if (nested) {
            headers.set("cty", "JWT");
        }
        headers.from(additionalHeaders);

        // Supply the exact protected header bytes as AAD, including intentionally malformed test fields.
        // Altering an already encrypted header would test authentication-tag failure instead of header policy.
        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                .parsedBase64URL(Base64URL.encode(headers.build().toString()))
                .build();
        JwkRSA key = (JwkRSA) keys.forKeyId("encrypt-rsa").orElseThrow();
        JWEObject jwe = new JWEObject(header, new Payload(payload));
        jwe.encrypt(new RSAEncrypter((RSAPublicKey) key.publicKey()));
        String token = jwe.serialize();

        // Check cryptographic integrity without asking Nimbus to interpret the deliberately invalid header fields.
        jwe.decrypt(new RSADecrypter(key.privateKey().orElseThrow()));
        assertThat(jwe.getPayload().toString(), is(payload));
        return token;
    }
}
