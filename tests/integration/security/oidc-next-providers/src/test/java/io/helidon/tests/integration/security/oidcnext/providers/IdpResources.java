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

import java.io.InputStream;
import java.net.InetAddress;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;

import io.helidon.common.configurable.Resource;
import io.helidon.common.pki.Keys;
import io.helidon.common.tls.Tls;
import io.helidon.json.JsonArray;
import io.helidon.json.JsonObject;
import io.helidon.json.JsonParser;
import io.helidon.webclient.api.WebClientConfig;

final class IdpResources {
    private IdpResources() {
    }

    static WebClientConfig webClient(String dockerHost) throws Exception {
        X509Certificate certificate;
        try (InputStream stream = IdpResources.class.getResourceAsStream("/tls-cert.pem")) {
            certificate = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(stream);
        }
        InetAddress address = InetAddress.getByName(dockerHost);
        return WebClientConfig.builder()
                .tls(tls -> tls.trust(List.of(certificate)))
                .dnsResolver((host, _) -> {
                    if (host.equals("auth.authelia.test")) {
                        return address;
                    }
                    try {
                        return InetAddress.getByName(host);
                    } catch (Exception e) {
                        throw new IllegalStateException("Cannot resolve test host " + host, e);
                    }
                })
                .buildPrototype();
    }

    static Tls serverTls() {
        Keys keys = Keys.builder().pem(pem -> pem.key(Resource.create("tls-key.pem"))
                .certChain(Resource.create("tls-cert.pem"))).build();
        return Tls.builder().privateKey(keys).privateKeyCertChain(keys).build();
    }

    static JsonObject publicClientKeys() {
        JsonObject.Builder keys = JsonObject.builder();
        JsonObject.Builder signing = JsonObject.builder();
        JsonObject.Builder encryption = JsonObject.builder();
        for (String resource : List.of("client-sign-jwk.json", "client-encrypt-jwk.json")) {
            JsonObject key = JsonParser.create(Resource.create(resource).string()).readJsonObject()
                    .arrayValue("keys").orElseThrow().values().getFirst().asObject();
            JsonObject.Builder target = resource.contains("sign") ? signing : encryption;
            for (String field : List.of("kty", "kid", "use", "alg", "n", "e")) {
                key.value(field).ifPresent(value -> target.set(field, value));
            }
        }
        encryption.set("alg", "RSA-OAEP-256");
        keys.set("keys", JsonArray.create(List.of(signing.build(), encryption.build())));
        return keys.build();
    }
}
