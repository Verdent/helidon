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

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;

import io.helidon.http.HeaderValues;
import io.helidon.http.Status;
import io.helidon.json.JsonObject;
import io.helidon.json.JsonParser;
import io.helidon.json.JsonValue;
import io.helidon.json.JsonValueType;
import io.helidon.security.jwt.jwk.JwkKeys;
import io.helidon.webclient.api.HttpClientResponse;
import io.helidon.webclient.api.WebClient;

final class OidcJwkSetLoader {
    private static final Set<String> FORBIDDEN_OPENID_PROVIDER_JWK_PARAMETERS =
            Set.of("k", "d", "p", "q", "dp", "dq", "qi", "oth");

    private final WebClient webClient;

    OidcJwkSetLoader(WebClient webClient) {
        this.webClient = webClient;
    }

    JwkKeys load(URI uri, boolean openIdProviderJwkSet) {
        JsonObject jsonObject = loadJson(uri);
        if (openIdProviderJwkSet) {
            validateOpenIdProviderJwkSet(jsonObject);
        }
        return JwkKeys.create(jsonObject);
    }

    private static void validateOpenIdProviderJwkSet(JsonObject jsonObject) {
        /*
         * This validation applies only to the OpenID Provider JWK Set loaded from provider metadata. Explicit local
         * JWK resources, such as client assertion signing keys or ID Token decryption keys, are loaded without this
         * provider-metadata restriction.
         *
         * Spec: OpenID Connect Discovery 1.0, 3 OpenID Provider Metadata, jwks_uri
         * https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
         * Quote: "This contains the signing key(s) the RP uses to validate signatures from the OP."
         * Quote: "The JWK Set MAY also contain the Server's encryption key(s), which are used by RPs to encrypt
         * requests to the Server."
         * Quote: "The JWK Set MUST NOT contain private or symmetric key values."
         */
        jsonObject.arrayValue("keys")
                .ifPresent(keys -> keys.values()
                        .stream()
                        .filter(value -> value.type() == JsonValueType.OBJECT)
                        .map(JsonValue::asObject)
                        .forEach(OidcJwkSetLoader::validateOpenIdProviderJwk));
    }

    private static void validateOpenIdProviderJwk(JsonObject jwk) {
        if (jwk.stringValue("kty").filter("oct"::equals).isPresent()
                || containsAny(jwk, FORBIDDEN_OPENID_PROVIDER_JWK_PARAMETERS)) {
            throw new IllegalStateException("OpenID Provider JWK Set must not contain private or symmetric key values");
        }
    }

    private static boolean containsAny(JsonObject jsonObject, Set<String> names) {
        for (String name : names) {
            if (jsonObject.containsKey(name)) {
                return true;
            }
        }
        return false;
    }

    private JsonObject loadJson(URI uri) {
        String scheme = uri.getScheme();
        if ("file".equalsIgnoreCase(scheme)) {
            return loadFile(uri);
        }
        if ("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme)) {
            return loadRemote(uri);
        }
        throw new IllegalStateException("Unsupported JWK Set URI scheme: " + uri);
    }

    private JsonObject loadFile(URI uri) {
        try (InputStream inputStream = Files.newInputStream(Path.of(uri))) {
            return JsonParser.create(inputStream).readJsonObject();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to load JWK Set", e);
        }
    }

    private JsonObject loadRemote(URI uri) {
        try (HttpClientResponse response = webClient.get()
                .uri(uri)
                .header(HeaderValues.ACCEPT_JSON)
                .request()) {
            if (response.status().family() != Status.Family.SUCCESSFUL) {
                throw new IllegalStateException("JWK Set endpoint returned status: " + response.status());
            }
            return response.as(JsonObject.class);
        }
    }
}
