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

import java.net.URI;

import io.helidon.http.HeaderValues;
import io.helidon.http.Status;
import io.helidon.json.JsonObject;
import io.helidon.webclient.api.HttpClientResponse;
import io.helidon.webclient.api.WebClient;

final class OidcProviderMetadataLoader {
    private final WebClient webClient;

    OidcProviderMetadataLoader(WebClient webClient) {
        this.webClient = webClient;
    }

    OidcProviderMetadata load(OidcProviderMetadata staticMetadata) {
        URI wellKnownUri = staticMetadata.wellKnownUri()
                .orElseThrow(() -> new IllegalArgumentException("well-known-uri is not configured"));
        try (HttpClientResponse response = webClient.get()
                .uri(wellKnownUri)
                .followRedirects(false)
                .header(HeaderValues.ACCEPT_JSON)
                .header(HeaderValues.CACHE_NO_CACHE)
                .request()) {
            if (response.status().family() != Status.Family.SUCCESSFUL) {
                throw new IllegalStateException("well-known metadata is unavailable");
            }
            /*
             * Spec: OpenID Connect Discovery 1.0, 4.2 OpenID Provider Configuration Response
             * https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse
             * Quotes: "The response is a set of Claims about the OpenID Provider's configuration";
             * "MUST be returned using the `application/json` content type".
             */
            if (!OidcHttpResponseValidation.hasJsonContentType(response)) {
                throw new IllegalStateException("well-known metadata response must be application/json");
            }
            JsonObject json = response.as(JsonObject.class);
            return staticMetadata.mergeWellKnownMetadata(OidcProviderMetadata.fromWellKnownMetadataJson(json));
        } catch (RuntimeException e) {
            throw new IllegalStateException("Failed to load well-known metadata", e);
        }
    }
}
