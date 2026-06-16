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
import java.util.List;
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
    private final OidcProviderMetadata metadata;
    private final WebClient webClient;
    private final OidcClientAuthenticationSupport clientAuthentication;
    private final List<String> authorizationCodeResources;

    OidcEndpointClient(OidcTenantConfig tenantConfig,
                       OidcProviderMetadata metadata,
                       WebClient webClient) {
        this.metadata = metadata;
        this.webClient = webClient;
        this.clientAuthentication = OidcClientAuthenticationSupport.create(tenantConfig);
        this.authorizationCodeResources = List.copyOf(tenantConfig.authorizationCode()
                                                              .map(OidcAuthorizationCodeConfig::resources)
                                                              .orElseGet(List::of));
    }

    OidcTokenEndpointResult exchangeAuthorizationCode(String authorizationCode,
                                                      URI redirectionEndpointUri,
                                                      Optional<String> pkceVerifier) {
        /*
         * Spec: RFC 6749, 4.1.3 Access Token Request
         * https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.3
         * Quote: "The client makes a request to the token endpoint by sending the following parameters using the
         * `application/x-www-form-urlencoded` format per Appendix B with a character encoding of UTF-8 in the HTTP
         * request entity-body:"
         * Quote: "`grant_type` REQUIRED. Value MUST be set to `authorization_code`."
         * Quote: "`code` REQUIRED. The authorization code received from the authorization server."
         * Quote: "`redirect_uri` REQUIRED, if the `redirect_uri` parameter was included in the authorization request as
         * described in Section 4.1.1, and their values MUST be identical."
         */
        Parameters.Builder form = Parameters.builder("oidc-token-endpoint-form")
                .add("grant_type", "authorization_code")
                .add("code", authorizationCode)
                .add("redirect_uri", redirectionEndpointUri.toString());
        if (!authorizationCodeResources.isEmpty()) {
            /*
             * Spec: RFC 8707, 2.2 Access Token Request
             * https://www.rfc-editor.org/rfc/rfc8707.html#section-2.2
             * Quote: "for all grant types, it indicates the target service or protected resource where the client
             * intends to use the requested access token."
             * Quote: "In the case of a `refresh_token` or `authorization_code` grant type request, such policy may
             * limit the acceptable resources to those that were originally granted by the resource owner or a subset
             * thereof."
             */
            authorizationCodeResources.forEach(resource -> form.add("resource", resource));
        }
        pkceVerifier.ifPresent(verifier -> {
            /*
             * Spec: RFC 7636, 4.5 Client Sends the Authorization Code and the Code Verifier to the Token Endpoint
             * https://www.rfc-editor.org/rfc/rfc7636.html#section-4.5
             * Quote: "In addition to the parameters defined in the OAuth 2.0 Access Token Request (Section 4.1.3 of
             * [RFC6749]), it sends the following parameter: `code_verifier` REQUIRED. Code verifier"
             */
            form.add("code_verifier", verifier);
        });

        return submit(form, OidcTokenResponse::fromAuthorizationCodeJson);
    }

    OidcTokenEndpointResult refreshAccessToken(String refreshToken) {
        /*
         * Spec: RFC 6749, 6 Refreshing an Access Token
         * https://www.rfc-editor.org/rfc/rfc6749.html#section-6
         * Quote: "If the authorization server issued a refresh token to the client, the client makes a refresh request
         * to the token endpoint by adding the following parameters using the `application/x-www-form-urlencoded` format
         * per Appendix B with a character encoding of UTF-8 in the HTTP request entity-body:"
         * Quote: "`grant_type` REQUIRED. Value MUST be set to `refresh_token`."
         * Quote: "`refresh_token` REQUIRED. The refresh token issued to the client."
         */
        Parameters.Builder form = Parameters.builder("oidc-refresh-token-endpoint-form")
                .add("grant_type", "refresh_token")
                .add("refresh_token", refreshToken);
        if (!authorizationCodeResources.isEmpty()) {
            /*
             * Spec: RFC 8707, 2.2 Access Token Request
             * https://www.rfc-editor.org/rfc/rfc8707.html#section-2.2
             * Quote: "for all grant types, it indicates the target service or protected resource where the client
             * intends to use the requested access token."
             * Quote: "In the case of a `refresh_token` or `authorization_code` grant type request, such policy may
             * limit the acceptable resources to those that were originally granted by the resource owner or a subset
             * thereof."
             */
            authorizationCodeResources.forEach(resource -> form.add("resource", resource));
        }

        return submit(form, OidcTokenResponse::fromRefreshJson);
    }

    OidcTokenEndpointResult clientCredentialsToken(Optional<String> scope, List<String> resources) {
        /*
         * Spec: RFC 6749, 4.4.2 Access Token Request
         * https://www.rfc-editor.org/rfc/rfc6749.html#section-4.4.2
         * Quote: "The client makes a request to the token endpoint by adding the following parameters using the
         * `application/x-www-form-urlencoded` format per Appendix B with a character encoding of UTF-8 in the HTTP
         * request entity-body:"
         * Quote: "`grant_type` REQUIRED. Value MUST be set to `client_credentials`."
         * Quote: "`scope` OPTIONAL. The scope of the access request as described by Section 3.3."
         *
         * Spec: RFC 8707, 2 Resource Parameter
         * https://www.rfc-editor.org/rfc/rfc8707.html#section-2
         * Quote: "The client MAY send multiple `resource` parameters to indicate that the requested token is intended
         * to be used at multiple resources."
         */
        Parameters.Builder form = Parameters.builder("oidc-client-credentials-token-endpoint-form")
                .add("grant_type", "client_credentials");
        scope.ifPresent(value -> form.add("scope", value));
        resources.forEach(resource -> form.add("resource", resource));

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
         * Quote: "The UserInfo Endpoint is an OAuth 2.0 Protected Resource that returns Claims about the authenticated
         * End-User."
         * Quote: "Clients MUST send requests with a valid Access Token."
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
                 * Quote: "The UserInfo Endpoint MUST return a content-type header to indicate which format is being
                 * returned."
                 * Quote: "The content-type of the HTTP response MUST be `application/json` if the response body is a
                 * text JSON object; the response body SHOULD be encoded using UTF-8."
                 */
                if (!OidcHttpResponseValidation.hasJsonContentType(response)) {
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
         * Quote: "An OAuth client intending to do mutual TLS (for OAuth client authentication and/or to acquire or use
         * certificate-bound tokens) when making a request directly to the authorization server MUST use the alias URL
         * of the endpoint within the `mtls_endpoint_aliases`, when present, in preference to the endpoint URL of the
         * same name at the top level of metadata."
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
                    if (!OidcHttpResponseValidation.hasJsonContentType(response)
                            || !OidcHttpResponseValidation.hasNoStoreCacheControl(response)
                            || !OidcHttpResponseValidation.hasNoCachePragma(response)) {
                        return OidcTokenEndpointResult.failure("Token Endpoint response is invalid");
                    }
                    try {
                        return OidcTokenEndpointResult.success(responseParser.apply(response.as(JsonObject.class)));
                    } catch (RuntimeException e) {
                        return OidcTokenEndpointResult.failure("Token Endpoint response is invalid", e);
                    }
                }
                if (!OidcHttpResponseValidation.hasJsonContentType(response)) {
                    return OidcTokenEndpointResult.failure("Token Endpoint Error Response is invalid");
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
