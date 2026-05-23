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

import io.helidon.http.HeaderValues;
import io.helidon.http.Status;
import io.helidon.json.JsonObject;
import io.helidon.json.JsonParser;
import io.helidon.security.jwt.jwk.JwkKeys;
import io.helidon.webclient.api.HttpClientResponse;
import io.helidon.webclient.api.WebClient;

final class OidcJwkSetLoader {
    private final WebClient webClient;

    OidcJwkSetLoader(WebClient webClient) {
        this.webClient = webClient;
    }

    JwkKeys load(URI uri) {
        JsonObject jsonObject = loadJson(uri);
        return JwkKeys.create(jsonObject);
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
        try (InputStream inputStream = inputStream(uri)) {
            return JsonParser.create(inputStream).readJsonObject();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to load JWK Set", e);
        }
    }

    private InputStream inputStream(URI uri) throws IOException {
        return Files.newInputStream(Path.of(uri));
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
