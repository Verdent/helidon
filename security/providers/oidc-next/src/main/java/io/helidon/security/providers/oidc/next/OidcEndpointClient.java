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
import java.time.Duration;
import java.util.Optional;
import java.util.function.Function;

import io.helidon.common.parameters.Parameters;
import io.helidon.http.HeaderNames;
import io.helidon.http.HeaderValues;
import io.helidon.http.Status;
import io.helidon.json.JsonObject;
import io.helidon.webclient.api.HttpClientRequest;
import io.helidon.webclient.api.HttpClientResponse;
import io.helidon.webclient.api.WebClient;

final class OidcEndpointClient {
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(10);

    private final OidcTenantConfig tenantConfig;
    private final OidcProviderMetadata metadata;
    private final WebClient webClient;

    private OidcEndpointClient(OidcTenantConfig tenantConfig,
                               OidcProviderMetadata metadata,
                               WebClient webClient) {
        this.tenantConfig = tenantConfig;
        this.metadata = metadata;
        this.webClient = webClient;
    }

    static OidcEndpointClient create(OidcTenantConfig tenantConfig, OidcProviderMetadata metadata) {
        return new OidcEndpointClient(tenantConfig, metadata, WebClient.create());
    }

    OidcTokenEndpointResult exchangeAuthorizationCode(String authorizationCode,
                                                      URI redirectionEndpointUri,
                                                      Optional<String> pkceVerifier) {
        Optional<URI> endpointUri = metadata.tokenEndpointUri();
        if (endpointUri.isEmpty()) {
            return OidcTokenEndpointResult.failure("Token Endpoint is not configured");
        }

        /*
         * Spec: RFC 6749, 4.1.3 Access Token Request
         * https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.3
         * Quotes: "The client makes a request to the token endpoint"; "using the `application/x-www-form-urlencoded`
         * format"; "`grant_type` REQUIRED"; "`code` REQUIRED"; "`redirect_uri` REQUIRED".
         */
        Parameters.Builder form = Parameters.builder("oidc-token-endpoint-form")
                .add("grant_type", "authorization_code")
                .add("code", authorizationCode)
                .add("redirect_uri", redirectionEndpointUri.toString());
        pkceVerifier.ifPresent(verifier -> {
            /*
             * Spec: RFC 7636, 4.5 Client Sends the Authorization Code and the Code Verifier to the Token Endpoint
             * https://www.rfc-editor.org/rfc/rfc7636.html#section-4.5
             * Quote: "The client sends the authorization code as well as the `code_verifier`".
             */
            form.add("code_verifier", verifier);
        });

        return submit(form, OidcTokenResponse::fromAuthorizationCodeJson);
    }

    OidcTokenEndpointResult refreshAccessToken(String refreshToken) {
        Optional<URI> endpointUri = metadata.tokenEndpointUri();
        if (endpointUri.isEmpty()) {
            return OidcTokenEndpointResult.failure("Token Endpoint is not configured");
        }

        /*
         * Spec: RFC 6749, 6 Refreshing an Access Token
         * https://www.rfc-editor.org/rfc/rfc6749.html#section-6
         * Quotes: "The client makes a refresh request to the token endpoint"; "`grant_type` REQUIRED. Value MUST be
         * set to `refresh_token`"; "`refresh_token` REQUIRED".
         */
        Parameters.Builder form = Parameters.builder("oidc-refresh-token-endpoint-form")
                .add("grant_type", "refresh_token")
                .add("refresh_token", refreshToken);

        return submit(form, OidcTokenResponse::fromRefreshJson);
    }

    private OidcTokenEndpointResult submit(Parameters.Builder form,
                                           Function<JsonObject, OidcTokenResponse> responseParser) {
        URI endpointUri = metadata.tokenEndpointUri()
                .orElseThrow();
        HttpClientRequest request = webClient.post()
                .uri(endpointUri)
                .readTimeout(REQUEST_TIMEOUT)
                .header(HeaderValues.ACCEPT_JSON)
                .header(HeaderValues.CACHE_NO_CACHE)
                .header(HeaderNames.CONTENT_TYPE, "application/x-www-form-urlencoded");
        OidcClientAuthenticationSupport.applyTokenEndpointAuthentication(tenantConfig, form, request);

        try (HttpClientResponse response = request.submit(form.build())) {
            if (response.status().family() == Status.Family.SUCCESSFUL) {
                return success(response, responseParser);
            }
            return error(response);
        } catch (RuntimeException e) {
            return OidcTokenEndpointResult.failure("Token Endpoint is unavailable", e);
        }
    }

    private OidcTokenEndpointResult success(HttpClientResponse response,
                                            Function<JsonObject, OidcTokenResponse> responseParser) {
        try {
            return OidcTokenEndpointResult.success(responseParser.apply(response.as(JsonObject.class)));
        } catch (RuntimeException e) {
            return OidcTokenEndpointResult.failure("Token Endpoint response is invalid", e);
        }
    }

    private OidcTokenEndpointResult error(HttpClientResponse response) {
        try {
            return OidcTokenEndpointResult.error(OidcTokenErrorResponse.fromJson(response.as(JsonObject.class)));
        } catch (RuntimeException e) {
            return OidcTokenEndpointResult.failure("Token Endpoint Error Response is invalid", e);
        }
    }
}
