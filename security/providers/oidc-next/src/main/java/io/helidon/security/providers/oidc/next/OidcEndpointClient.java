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
    private static final String TOKEN_EXCHANGE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange";

    private final OidcProviderMetadata metadata;
    private final WebClient webClient;
    private final OidcClientAuthenticationSupport clientAuthentication;
    private final List<String> authorizationCodeResources;
    private final String userInfoAccept;

    OidcEndpointClient(OidcTenantConfig tenantConfig,
                       OidcProviderMetadata metadata,
                       WebClient webClient) {
        this.metadata = metadata;
        this.webClient = webClient;
        this.clientAuthentication = OidcClientAuthenticationSupport.tokenEndpoint(tenantConfig);
        this.authorizationCodeResources = List.copyOf(tenantConfig.authorizationCode()
                                                              .map(OidcAuthorizationCodeConfig::resources)
                                                              .orElseGet(List::of));
        this.userInfoAccept = tenantConfig.userInfo()
                .flatMap(OidcUserInfoConfig::jwt)
                .isPresent()
                        ? "application/jwt"
                        : "application/json";
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

    OidcTokenExchangeResult tokenExchange(String subjectToken,
                                          Optional<String> scope,
                                          Optional<String> resource,
                                          Optional<String> audience) {
        /*
         * Spec: RFC 8693, 2.1 Request
         * https://www.rfc-editor.org/rfc/rfc8693.html#section-2.1
         * Quote: "The client makes a token exchange request to the token endpoint with an extension grant type using
         * the HTTP `POST` method."
         * Quote: "`grant_type` REQUIRED. The value `urn:ietf:params:oauth:grant-type:token-exchange` indicates that a
         * token exchange is being performed."
         * Quote: "`subject_token` REQUIRED. A security token that represents the identity of the party on behalf of
         * whom the request is being made."
         */
        Parameters.Builder form = Parameters.builder("oidc-token-exchange-endpoint-form")
                .add("grant_type", TOKEN_EXCHANGE_GRANT_TYPE)
                .add("requested_token_type", OidcTokenExchangeResponse.ACCESS_TOKEN_TYPE)
                .add("subject_token", subjectToken)
                .add("subject_token_type", OidcTokenExchangeResponse.ACCESS_TOKEN_TYPE);
        scope.ifPresent(value -> form.add("scope", value));
        resource.ifPresent(value -> {
            /*
             * Spec: RFC 8693, 2.1 Request
             * https://www.rfc-editor.org/rfc/rfc8693.html#section-2.1
             * Quote: "`resource` OPTIONAL. A URI that indicates the target service or resource where the client
             * intends to use the requested security token."
             */
            form.add("resource", value);
        });
        audience.ifPresent(value -> {
            /*
             * Spec: RFC 8693, 2.1 Request
             * https://www.rfc-editor.org/rfc/rfc8693.html#section-2.1
             * Quote: "`audience` OPTIONAL. The logical name of the target service where the client intends to use the
             * requested security token."
             */
            form.add("audience", value);
        });

        return submit(form,
                      json -> OidcTokenExchangeResult.success(OidcTokenExchangeResponse.fromJson(json)),
                      OidcTokenExchangeResult::error,
                      OidcTokenExchangeResult::failure);
    }

    OidcPushedAuthorizationRequestResult pushedAuthorizationRequest(Parameters authorizationRequestParameters) {
        /*
         * Spec: RFC 8705, 5 Metadata for Mutual TLS Endpoint Aliases
         * https://www.rfc-editor.org/rfc/rfc8705.html#section-5
         * Quote: "An OAuth client intending to do mutual TLS [...] MUST use the alias URL of the endpoint within the
         * `mtls_endpoint_aliases`, when present, in preference to the endpoint URL of the same name at the top level of
         * metadata."
         */
        Optional<URI> endpointUri = clientAuthentication.usesMutualTls()
                ? metadata.mutualTlsPushedAuthorizationRequestEndpointUri()
                        .or(metadata::pushedAuthorizationRequestEndpointUri)
                : metadata.pushedAuthorizationRequestEndpointUri();
        if (endpointUri.isEmpty()) {
            return OidcPushedAuthorizationRequestResult.failure(
                    "Pushed Authorization Request Endpoint is not configured");
        }
        URI uri = endpointUri.orElseThrow();
        if (authorizationRequestParameters.names().contains("request_uri")) {
            return OidcPushedAuthorizationRequestResult.failure(
                    "Pushed Authorization Request form must not contain request_uri");
        }

        /*
         * Spec: RFC 9126, 2.1 Request and 2.2 Successful Response
         * https://www.rfc-editor.org/rfc/rfc9126.html#section-2.1
         * https://www.rfc-editor.org/rfc/rfc9126.html#section-2.2
         * Quote: "The `request_uri` authorization request parameter is one exception, and it MUST NOT be provided."
         * Quote: "the server MUST generate a request URI and provide it in the response with a `201` HTTP status code."
         */
        Parameters.Builder form = Parameters.builder("oidc-pushed-authorization-request-form");
        copyParameters(authorizationRequestParameters, form);
        boolean clientIdAlreadyPresent = authorizationRequestParameters.names().contains("client_id");
        try {
            HttpClientRequest request = webClient.post()
                    .uri(uri)
                    .followRedirects(false)
                    .header(HeaderValues.ACCEPT_JSON)
                    .header(HeaderValues.CACHE_NO_CACHE)
                    .header(HeaderNames.CONTENT_TYPE, "application/x-www-form-urlencoded");
            clientAuthentication.applyPushedAuthorizationRequestAuthentication(uri,
                                                                               metadata.issuer(),
                                                                               form,
                                                                               request,
                                                                               clientIdAlreadyPresent);

            try (HttpClientResponse response = request.submit(form.build())) {
                if (response.status() == Status.CREATED_201) {
                    if (!OidcHttpResponseValidation.hasJsonContentType(response)) {
                        return OidcPushedAuthorizationRequestResult.failure(
                                "Pushed Authorization Request Endpoint response is invalid");
                    }
                    try {
                        return OidcPushedAuthorizationRequestResult.success(
                                OidcPushedAuthorizationResponse.fromJson(response.as(JsonObject.class)));
                    } catch (RuntimeException e) {
                        return OidcPushedAuthorizationRequestResult.failure(
                                "Pushed Authorization Request Endpoint response is invalid",
                                e);
                    }
                }
                /*
                 * Spec: RFC 9126, 2.3 Error Response
                 * https://www.rfc-editor.org/rfc/rfc9126.html#section-2.3
                 * Quote: "The authorization server returns an error response with the same format as is specified for
                 * error responses from the token endpoint".
                 */
                if (!OidcHttpResponseValidation.hasJsonContentType(response)) {
                    return OidcPushedAuthorizationRequestResult.failure(
                            "Pushed Authorization Request Endpoint Error Response is invalid");
                }
                try {
                    return OidcPushedAuthorizationRequestResult.error(
                            OidcTokenErrorResponse.fromJson(response.as(JsonObject.class)));
                } catch (RuntimeException e) {
                    return OidcPushedAuthorizationRequestResult.failure(
                            "Pushed Authorization Request Endpoint Error Response is invalid",
                            e);
                }
            }
        } catch (RuntimeException e) {
            return OidcPushedAuthorizationRequestResult.failure(
                    "Pushed Authorization Request Endpoint is unavailable",
                    e);
        }
    }

    OidcUserInfoEndpointResult userInfo(String accessToken) {
        Optional<URI> endpointUri = metadata.userInfoEndpointUri();
        if (endpointUri.isEmpty()) {
            return OidcUserInfoEndpointResult.failure("UserInfo Endpoint is not configured");
        }
        URI uri = endpointUri.orElseThrow();

        /*
         * Spec: OpenID Connect Core 1.0, 5.3.1 UserInfo Request
         * https://openid.net/specs/openid-connect-core-1_0.html#UserInfoRequest
         * Quote: "The UserInfo Endpoint is an OAuth 2.0 Protected Resource that returns Claims about the authenticated
         * End-User."
         * Quote: "Clients MUST send requests with a valid Access Token."
         */
        try (HttpClientResponse response = webClient.get()
                .uri(uri)
                .followRedirects(false)
                .header(HeaderNames.ACCEPT, userInfoAccept)
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
                 * Quote: "If the UserInfo Response is signed and/or encrypted, then the Claims are returned in a JWT
                 * and the content-type MUST be `application/jwt`."
                 */
                if (OidcHttpResponseValidation.hasJsonContentType(response)) {
                    try {
                        return OidcUserInfoEndpointResult.json(response.as(JsonObject.class));
                    } catch (RuntimeException e) {
                        return OidcUserInfoEndpointResult.failure("UserInfo Endpoint response is invalid", e);
                    }
                }
                if (OidcHttpResponseValidation.hasJwtContentType(response)) {
                    try {
                        return OidcUserInfoEndpointResult.jwt(response.as(String.class));
                    } catch (RuntimeException e) {
                        return OidcUserInfoEndpointResult.failure("UserInfo Endpoint response is invalid", e);
                    }
                }
                return OidcUserInfoEndpointResult.failure("UserInfo Endpoint response is invalid");
            }
            return OidcUserInfoEndpointResult.failure("UserInfo Endpoint returned an Error Response");
        } catch (RuntimeException e) {
            return OidcUserInfoEndpointResult.failure("UserInfo Endpoint is unavailable", e);
        }
    }

    private static void copyParameters(Parameters source, Parameters.Builder target) {
        for (String name : source.names()) {
            for (String value : source.all(name)) {
                target.add(name, value);
            }
        }
    }

    private OidcTokenEndpointResult submit(Parameters.Builder form,
                                           Function<JsonObject, OidcTokenResponse> responseParser) {
        return submit(form,
                      json -> OidcTokenEndpointResult.success(responseParser.apply(json)),
                      OidcTokenEndpointResult::error,
                      OidcTokenEndpointResult::failure);
    }

    private <R> R submit(Parameters.Builder form,
                         Function<JsonObject, R> successResult,
                         Function<OidcTokenErrorResponse, R> errorResult,
                         FailureFactory<R> failureResult) {
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
            return failureResult.create("Token Endpoint is not configured", null);
        }
        URI uri = endpointUri.orElseThrow();
        try {
            HttpClientRequest request = webClient.post()
                    .uri(uri)
                    .followRedirects(false)
                    .header(HeaderValues.ACCEPT_JSON)
                    .header(HeaderValues.CACHE_NO_CACHE)
                    .header(HeaderNames.CONTENT_TYPE, "application/x-www-form-urlencoded");
            clientAuthentication.applyTokenEndpointAuthentication(uri, form, request);

            try (HttpClientResponse response = request.submit(form.build())) {
                if (response.status().family() == Status.Family.SUCCESSFUL) {
                    if (!OidcHttpResponseValidation.hasJsonContentType(response)
                            || !OidcHttpResponseValidation.hasNoStoreCacheControl(response)
                            || !OidcHttpResponseValidation.hasNoCachePragma(response)) {
                        return failureResult.create("Token Endpoint response is invalid", null);
                    }
                    try {
                        return successResult.apply(response.as(JsonObject.class));
                    } catch (RuntimeException e) {
                        return failureResult.create("Token Endpoint response is invalid", e);
                    }
                }
                if (!OidcHttpResponseValidation.hasJsonContentType(response)) {
                    return failureResult.create("Token Endpoint Error Response is invalid", null);
                }
                try {
                    return errorResult.apply(OidcTokenErrorResponse.fromJson(response.as(JsonObject.class)));
                } catch (RuntimeException e) {
                    return failureResult.create("Token Endpoint Error Response is invalid", e);
                }
            }
        } catch (RuntimeException e) {
            return failureResult.create("Token Endpoint is unavailable", e);
        }
    }

    @FunctionalInterface
    private interface FailureFactory<R> {
        R create(String description, Throwable cause);
    }
}
