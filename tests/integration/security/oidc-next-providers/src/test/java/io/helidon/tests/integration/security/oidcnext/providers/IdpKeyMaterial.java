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

package io.helidon.tests.integration.security.oidcnext.providers;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

import io.helidon.common.configurable.Resource;
import io.helidon.json.JsonObject;
import io.helidon.json.JsonParser;

final class IdpKeyMaterial {
    private IdpKeyMaterial() {
    }

    static String publicSigningPem() {
        return publicPem("client-sign-jwk.json");
    }

    static String publicEncryptionPem() {
        return publicPem("client-encrypt-jwk.json");
    }

    private static String publicPem(String resource) {
        JsonObject key = JsonParser.create(Resource.create(resource).string()).readJsonObject()
                .arrayValue("keys").orElseThrow().values().getFirst().asObject();
        BigInteger modulus = new BigInteger(1, Base64.getUrlDecoder().decode(key.stringValue("n").orElseThrow()));
        BigInteger exponent = new BigInteger(1, Base64.getUrlDecoder().decode(key.stringValue("e").orElseThrow()));
        try {
            byte[] encoded = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, exponent)).getEncoded();
            return "-----BEGIN PUBLIC KEY-----\n" + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(encoded)
                    + "\n-----END PUBLIC KEY-----\n";
        } catch (Exception e) {
            throw new IllegalStateException("Cannot load test RSA public key", e);
        }
    }
}
