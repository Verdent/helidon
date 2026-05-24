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
import java.util.Optional;
import java.util.function.Function;

import io.helidon.common.parameters.Parameters;
import io.helidon.http.HeaderNames;
import io.helidon.http.HeaderValues;
import io.helidon.http.HttpMediaTypes;
import io.helidon.http.Status;
import io.helidon.json.JsonObject;
import io.helidon.webclient.api.HttpClientRequest;
import io.helidon.webclient.api.HttpClientResponse;
import io.helidon.webclient.api.WebClient;

final class OidcEndpointClient {
    private final OidcProviderMetadata metadata;
    private final WebClient webClient;
    private final OidcClientAuthenticationSupport clientAuthentication;

    OidcEndpointClient(OidcTenantConfig tenantConfig,
                       OidcProviderMetadata metadata,
                       WebClient webClient) {
        this.metadata = metadata;
        this.webClient = webClient;
        this.clientAuthentication = OidcClientAuthenticationSupport.create(tenantConfig);
    }

    OidcTokenEndpointResult exchangeAuthorizationCode(String authorizationCode,
                                                      URI redirectionEndpointUri,
                                                      Optional<String> pkceVerifier) {
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

    OidcTokenEndpointResult clientCredentialsToken() {
        /*
         * Spec: RFC 6749, 4.4.2 Access Token Request
         * https://www.rfc-editor.org/rfc/rfc6749.html#section-4.4.2
         * Quotes: "The client makes a request to the token endpoint"; "using the
         * `application/x-www-form-urlencoded` format"; "`grant_type` REQUIRED.  Value MUST be set to
         * `client_credentials`."
         */
        Parameters.Builder form = Parameters.builder("oidc-client-credentials-token-endpoint-form")
                .add("grant_type", "client_credentials");

        return submit(form, OidcTokenResponse::fromClientCredentialsJson);
    }

    Optional<JsonObject> userInfo(String accessToken) {
        Optional<URI> endpointUri = metadata.userInfoEndpointUri();
        if (endpointUri.isEmpty()) {
            return Optional.empty();
        }

        /*
         * Spec: OpenID Connect Core 1.0, 5.3.1 UserInfo Request
         * https://openid.net/specs/openid-connect-core-1_0.html#UserInfoRequest
         * Quotes: "The UserInfo Endpoint is an OAuth 2.0 Protected Resource";
         * "Clients MUST send requests with a valid Access Token".
         */
        try (HttpClientResponse response = webClient.get()
                .uri(endpointUri.orElseThrow())
                .followRedirects(false)
                .header(HeaderValues.ACCEPT_JSON)
                .header(HeaderValues.CACHE_NO_CACHE)
                .header(HeaderNames.AUTHORIZATION, "Bearer " + accessToken)
                .request()) {
            if (response.status().family() == Status.Family.SUCCESSFUL) {
                /*
                 * Spec: OpenID Connect Core 1.0, 5.3.2 Successful UserInfo Response
                 * https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
                 * Quotes: "The UserInfo Endpoint MUST return a content-type header to indicate which format is being
                 * returned"; "The content-type of the HTTP response MUST be `application/json` if the response body is
                 * a text JSON object".
                 */
                if (response.headers().contentType().filter(HttpMediaTypes.JSON_PREDICATE::test).isEmpty()) {
                    return Optional.empty();
                }
                return Optional.of(response.as(JsonObject.class));
            }
            return Optional.empty();
        } catch (RuntimeException e) {
            return Optional.empty();
        }
    }

    private OidcTokenEndpointResult submit(Parameters.Builder form,
                                           Function<JsonObject, OidcTokenResponse> responseParser) {
        /*
         * Spec: RFC 8705, 5 Metadata for Mutual TLS Endpoint Aliases
         * https://www.rfc-editor.org/rfc/rfc8705.html#section-5
         * Quote: "MUST use the alias URL of the endpoint within the "mtls_endpoint_aliases", when present, in
         * preference to the endpoint URL of the same name at the top level of metadata".
         */
        Optional<URI> endpointUri = clientAuthentication.usesMutualTls()
                ? metadata.mutualTlsTokenEndpointUri().or(metadata::tokenEndpointUri)
                : metadata.tokenEndpointUri();
        if (endpointUri.isEmpty()) {
            return OidcTokenEndpointResult.failure("Token Endpoint is not configured");
        }
        try {
            HttpClientRequest request = webClient.post()
                    .uri(endpointUri.orElseThrow())
                    .followRedirects(false)
                    .header(HeaderValues.ACCEPT_JSON)
                    .header(HeaderValues.CACHE_NO_CACHE)
                    .header(HeaderNames.CONTENT_TYPE, "application/x-www-form-urlencoded");
            clientAuthentication.applyTokenEndpointAuthentication(endpointUri.orElseThrow(), form, request);

            try (HttpClientResponse response = request.submit(form.build())) {
                if (response.status().family() == Status.Family.SUCCESSFUL) {
                    try {
                        return OidcTokenEndpointResult.success(responseParser.apply(response.as(JsonObject.class)));
                    } catch (RuntimeException e) {
                        return OidcTokenEndpointResult.failure("Token Endpoint response is invalid", e);
                    }
                }
                try {
                    return OidcTokenEndpointResult.error(OidcTokenErrorResponse.fromJson(response.as(JsonObject.class)));
                } catch (RuntimeException e) {
                    return OidcTokenEndpointResult.failure("Token Endpoint Error Response is invalid", e);
                }
            }
        } catch (RuntimeException e) {
            return OidcTokenEndpointResult.failure("Token Endpoint is unavailable", e);
        }
    }
}
