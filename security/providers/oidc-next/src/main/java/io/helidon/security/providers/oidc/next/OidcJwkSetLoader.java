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
import java.net.URLConnection;
import java.util.Locale;

import io.helidon.json.JsonObject;
import io.helidon.json.JsonParser;
import io.helidon.security.jwt.jwk.JwkKeys;

final class OidcJwkSetLoader {
    private static final int JWK_SET_CONNECT_TIMEOUT_MILLIS = 10_000;
    private static final int JWK_SET_READ_TIMEOUT_MILLIS = 10_000;

    private OidcJwkSetLoader() {
    }

    static OidcJwkSetLoader create() {
        return new OidcJwkSetLoader();
    }

    JwkKeys load(URI uri) {
        validateJwkSetUri(uri);
        try (InputStream inputStream = inputStream(uri)) {
            JsonObject jsonObject = JsonParser.create(inputStream).readJsonObject();
            return JwkKeys.create(jsonObject);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to load JWK Set", e);
        }
    }

    static void validateJwkSetUri(URI uri) {
        /*
         * Spec: OpenID Connect Discovery 1.0, 3 OpenID Provider Metadata
         * https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
         * Quote: "which MUST use the `https` scheme".
         * The `file` scheme is Helidon local/offline key-loading support, not a spec exception.
         */
        String scheme = uri.getScheme();
        if (scheme == null) {
            throw new IllegalArgumentException("jwks-uri must use https or file scheme");
        }
        String normalizedScheme = scheme.toLowerCase(Locale.ROOT);
        if (!"https".equals(normalizedScheme) && !"file".equals(normalizedScheme)) {
            throw new IllegalArgumentException("jwks-uri must use https or file scheme");
        }
    }

    private InputStream inputStream(URI uri) throws IOException {
        URLConnection connection = uri.toURL().openConnection();
        connection.setConnectTimeout(JWK_SET_CONNECT_TIMEOUT_MILLIS);
        connection.setReadTimeout(JWK_SET_READ_TIMEOUT_MILLIS);
        return connection.getInputStream();
    }
}
