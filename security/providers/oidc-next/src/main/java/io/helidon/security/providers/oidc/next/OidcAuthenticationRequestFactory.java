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
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

import io.helidon.common.parameters.Parameters;
import io.helidon.common.uri.UriQueryWriteable;
import io.helidon.http.HeaderNames;
import io.helidon.http.SetCookie;
import io.helidon.security.SecurityEnvironment;

final class OidcAuthenticationRequestFactory {
    private static final int RANDOM_VALUE_BYTES = 32;
    private static final String OFFLINE_ACCESS_SCOPE = "offline_access";
    private static final String PROMPT_CONSENT = "consent";

    private final SecureRandom secureRandom;

    OidcAuthenticationRequestFactory() {
        this(new SecureRandom());
    }

    private OidcAuthenticationRequestFactory(SecureRandom secureRandom) {
        this.secureRandom = secureRandom;
    }

    OidcAuthenticationRequest create(OidcRequestContext context) {
        OidcTenantContext tenantContext = context.tenantContext().orElseThrow();
        OidcTenantConfig tenantConfig = tenantContext.tenantConfig();
        OidcAuthorizationCodeConfig authorizationCode = tenantConfig.authorizationCode().orElseThrow();
        URI authorizationEndpointUri = tenantContext.metadata()
                .authorizationEndpointUri()
                .orElseThrow(() -> new IllegalStateException("authorization-endpoint-uri is not configured"));
        String expectedIssuer = tenantContext.metadata()
                .issuer()
                .orElseThrow(() -> new IllegalStateException("issuer is not configured"));
        URI redirectionEndpointUri = resolveRedirectionEndpointUri(
                OidcEndpointUris.redirectionEndpointUri(authorizationCode),
                context.environment());
        if (tenantConfig.endpoints().tlsRequired() && !"https".equalsIgnoreCase(redirectionEndpointUri.getScheme())) {
            throw new IllegalStateException(
                    "redirection-endpoint-uri must use https unless endpoints.tls-required is disabled: "
                            + redirectionEndpointUri);
        }

        String state = randomValue();
        String nonce = randomValue();
        String pkceVerifier = authorizationCode.pkceRequired() ? randomValue() : null;
        SecurityEnvironment environment = context.environment();
        Instant createdAt = environment.time().toInstant();

        OidcAuthenticationRequestState requestState = new OidcAuthenticationRequestState(
                tenantContext.tenantId(),
                state,
                nonce,
                pkceVerifier,
                expectedIssuer,
                originalUri(environment),
                redirectionEndpointUri,
                createdAt,
                createdAt.plus(tenantContext.cookieStateHandler().cookieConfig().authenticationRequestLifetime()));
        SetCookie stateCookie = tenantContext.cookieStateHandler()
                .createAuthenticationRequestCookie(requestState);
        String clientId = tenantConfig.clientId().orElseThrow();
        Parameters authorizationParameters = authorizationParameters(clientId,
                                                                    redirectionEndpointUri,
                                                                    authorizationCode,
                                                                    state,
                                                                    nonce,
                                                                    pkceVerifier);
        Parameters requestParameters = requestObjectParameters(tenantContext,
                                                               authorizationCode,
                                                               clientId,
                                                               authorizationParameters,
                                                               createdAt);
        URI authorizationUri = pushedAuthorizationRequestsEnabled(tenantConfig, authorizationCode, tenantContext.metadata())
                ? pushedAuthorizationUri(authorizationEndpointUri,
                                         clientId,
                                         pushedAuthorizationRequest(tenantContext,
                                                                    pushedAuthorizationRequestParameters(requestParameters)))
                : authorizationUri(authorizationEndpointUri, requestParameters);

        return new OidcAuthenticationRequest(authorizationUri, stateCookie.toString());
    }

    static String codeChallenge(String verifier, OidcPkceMethod method) {
        return switch (method) {
        case PLAIN -> verifier;
        case S256 -> base64Url(sha256(verifier));
        };
    }

    private Parameters authorizationParameters(String clientId,
                                               URI redirectionEndpointUri,
                                               OidcAuthorizationCodeConfig authorizationCode,
                                               String state,
                                               String nonce,
                                               String pkceVerifier) {
        /*
         * Spec: OpenID Connect Core 1.0, 3.1.2.1 Authentication Request
         * https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
         * Quote: "OpenID Connect requests MUST contain the `openid` scope value."
         * Quote: "When using the Authorization Code Flow, this value is `code`."
         * Quote: "`state` RECOMMENDED. Opaque value used to maintain state between the request and the callback."
         * Quote: "Sufficient entropy MUST be present in the `nonce` values used to prevent attackers from guessing
         * values."
         */
        Parameters.Builder parameters = Parameters.builder("oidc-authorization-request")
                .add("response_type", "code")
                .add("client_id", clientId)
                .add("redirect_uri", redirectionEndpointUri.toString())
                .add("scope", OidcScopeSupport.serializeScopes(authorizationCode.scopes()))
                .add("state", state)
                .add("nonce", nonce);
        List<String> prompts = prompts(authorizationCode);
        if (!prompts.isEmpty()) {
            parameters.add("prompt", String.join(" ", prompts));
        }
        if (!authorizationCode.resources().isEmpty()) {
            /*
             * Spec: RFC 8707, 2 Resource Parameter and 2.1 Authorization Request
             * https://www.rfc-editor.org/rfc/rfc8707.html#section-2
             * https://www.rfc-editor.org/rfc/rfc8707.html#section-2.1
             * Quote: "Indicates the target service or resource to which access is being requested."
             * Quote: "the requested resource is applicable to the full authorization grant."
             */
            authorizationCode.resources().forEach(resource -> parameters.add("resource", resource));
        }
        if (pkceVerifier != null) {
            /*
             * Spec: RFC 7636, 4.1 Client Creates a Code Verifier, 4.2 Client Creates the Code Challenge, and 7.1
             * Entropy of the code_verifier
             * https://www.rfc-editor.org/rfc/rfc7636.html#section-4.1
             * https://www.rfc-editor.org/rfc/rfc7636.html#section-4.2
             * https://www.rfc-editor.org/rfc/rfc7636.html#section-7.1
             * RFC 7636 section 4.1 quote: "The client first creates a code verifier, `code_verifier`, for each OAuth
             * 2.0 Authorization Request."
             * RFC 7636 section 7.1 quote: "The client SHOULD create a `code_verifier` with a minimum of 256 bits of
             * entropy."
             * RFC 7636 section 4.2 quotes: "code_challenge = code_verifier";
             * "code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))";
             * "If the client is capable of using \"S256\", it MUST use \"S256\", as \"S256\" is Mandatory To
             * Implement (MTI) on the server."
             */
            parameters.add("code_challenge", codeChallenge(pkceVerifier, authorizationCode.pkceMethod()))
                    .add("code_challenge_method", authorizationCode.pkceMethod().wireName());
        }

        return parameters.build();
    }

    private Parameters requestObjectParameters(OidcTenantContext tenantContext,
                                               OidcAuthorizationCodeConfig authorizationCode,
                                               String clientId,
                                               Parameters authorizationParameters,
                                               Instant createdAt) {
        if (!OidcRequestObjectSigner.shouldUse(authorizationCode, tenantContext.metadata())) {
            return authorizationParameters;
        }
        String requestObject = tenantContext.requestObjectSigner()
                .orElseThrow(() -> new IllegalStateException(
                        "Request Object signing is enabled but no signing key is configured"))
                .sign(clientId,
                      tenantContext.metadata().issuer().orElseThrow(),
                      authorizationParameters,
                      createdAt);

        /*
         * Spec: OpenID Connect Core 1.0, 6.1 Passing a Request Object by Value
         * https://openid.net/specs/openid-connect-core-1_0.html#RequestObject
         * Quote: "The `request` parameter is used by the OpenID Connect authentication request to pass a Request
         * Object by value."
         * Quote: "The parameters `request` and `request_uri` MUST NOT be included in Request Objects."
         * Quote: "However, even if a Request Object is used, a `scope` parameter MUST always be passed using the
         * OAuth 2.0 request syntax containing the `openid` scope value."
         * Quote: "The values for the `response_type` and `client_id` parameters MUST be included using the OAuth 2.0
         * request syntax, since they are REQUIRED by OAuth 2.0."
         */
        return Parameters.builder("oidc-request-object-authorization-request")
                .add("response_type", requiredParameter(authorizationParameters, "response_type"))
                .add("client_id", requiredParameter(authorizationParameters, "client_id"))
                .add("scope", requiredParameter(authorizationParameters, "scope"))
                .add("request", requestObject)
                .build();
    }

    private Parameters pushedAuthorizationRequestParameters(Parameters requestParameters) {
        if (!requestParameters.names().contains("request")) {
            return requestParameters;
        }

        /*
         * Spec: RFC 9126, 3 The "request" Request Parameter
         * https://www.rfc-editor.org/rfc/rfc9126.html#section-3
         * Quote: "Request parameters required by a given client authentication method are included in the
         * `application/x-www-form-urlencoded` request directly and are the only parameters other than `request` in the
         * form body".
         * Quote: "All other request parameters, i.e., those pertaining to the authorization request itself, MUST appear
         * as claims of the JWT representing the authorization request."
         */
        return Parameters.builder("oidc-pushed-request-object-authorization-request")
                .add("request", requiredParameter(requestParameters, "request"))
                .build();
    }

    private URI authorizationUri(URI authorizationEndpointUri, Parameters authorizationParameters) {
        UriQueryWriteable query = UriQueryWriteable.create();
        for (String name : authorizationParameters.names()) {
            for (String value : authorizationParameters.all(name)) {
                query.add(name, value);
            }
        }
        return authorizationUri(authorizationEndpointUri, query);
    }

    private URI pushedAuthorizationUri(URI authorizationEndpointUri,
                                       String clientId,
                                       OidcPushedAuthorizationResponse pushedAuthorizationResponse) {
        /*
         * Spec: RFC 9126, 4 Authorization Request
         * https://www.rfc-editor.org/rfc/rfc9126.html#section-4
         * Quote: "The client uses the `request_uri` value returned by the authorization server to build an
         * authorization request".
         * Quote: "the client MUST only use a `request_uri` value once."
         */
        UriQueryWriteable query = UriQueryWriteable.create()
                .add("client_id", clientId)
                .add("request_uri", pushedAuthorizationResponse.requestUri());
        return authorizationUri(authorizationEndpointUri, query);
    }

    private URI authorizationUri(URI authorizationEndpointUri, UriQueryWriteable query) {
        return URI.create(authorizationEndpointUri
                                  + (authorizationEndpointUri.getRawQuery() == null ? "?" : "&")
                                  + query.rawValue());
    }

    private boolean pushedAuthorizationRequestsEnabled(OidcTenantConfig tenantConfig,
                                                       OidcAuthorizationCodeConfig authorizationCode,
                                                       OidcProviderMetadata metadata) {
        return switch (authorizationCode.pushedAuthorizationRequests()) {
        case DISABLED -> false;
        case AUTO -> pushedAuthorizationRequestEndpointUri(tenantConfig, metadata).isPresent()
                || metadata.requirePushedAuthorizationRequests();
        case REQUIRED -> true;
        };
    }

    private static Optional<URI> pushedAuthorizationRequestEndpointUri(OidcTenantConfig tenantConfig,
                                                                       OidcProviderMetadata metadata) {
        OidcClientAuthenticationMethod method =
                OidcClientAuthenticationSupport.tokenEndpointAuthenticationMethod(tenantConfig);
        if (method == OidcClientAuthenticationMethod.TLS_CLIENT_AUTH
                || method == OidcClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH) {
            return metadata.mutualTlsPushedAuthorizationRequestEndpointUri()
                    .or(metadata::pushedAuthorizationRequestEndpointUri);
        }
        return metadata.pushedAuthorizationRequestEndpointUri();
    }

    private OidcPushedAuthorizationResponse pushedAuthorizationRequest(OidcTenantContext tenantContext,
                                                                       Parameters authorizationParameters) {
        OidcPushedAuthorizationRequestResult result = tenantContext.endpointClient()
                .pushedAuthorizationRequest(authorizationParameters);
        if (result.succeeded()) {
            return result.response().orElseThrow();
        }
        if (result.errorResponse()) {
            OidcTokenErrorResponse error = result.error().orElseThrow();
            throw new IllegalStateException(result.description()
                                                    + ": "
                                                    + error.error()
                                                    + error.errorDescription()
                                                            .map(description -> " (" + description + ")")
                                                            .orElse(""));
        }
        if (result.cause().isPresent()) {
            throw new IllegalStateException(result.description(), result.cause().orElseThrow());
        }
        throw new IllegalStateException(result.description());
    }

    private String requiredParameter(Parameters parameters, String name) {
        List<String> values = parameters.all(name);
        if (values.size() != 1) {
            throw new IllegalStateException("Authorization Request parameter must have exactly one value: " + name);
        }
        return values.getFirst();
    }

    private List<String> prompts(OidcAuthorizationCodeConfig authorizationCode) {
        List<String> prompts = authorizationCode.prompts();
        if (authorizationCode.scopes().contains(OFFLINE_ACCESS_SCOPE) && !prompts.contains(PROMPT_CONSENT)) {
            /*
             * Spec: OpenID Connect Core 1.0, 11 Offline Access
             * https://openid.net/specs/openid-connect-core-1_0.html#OfflineAccess
             * Quote: "When offline access is requested, a `prompt` parameter value of `consent` MUST be used".
             * Quote: "MUST ensure that the prompt parameter contains `consent`".
             */
            if (prompts.isEmpty()) {
                return List.of(PROMPT_CONSENT);
            }
            List<String> updatedPrompts = new ArrayList<>(prompts);
            updatedPrompts.add(PROMPT_CONSENT);
            return updatedPrompts;
        }
        return prompts;
    }

    private URI originalUri(SecurityEnvironment environment) {
        URI targetUri = environment.targetUri();
        if (targetUri != null) {
            return OidcUri.localReference(targetUri);
        }
        return OidcUri.localReference(environment.path().orElse("/"), null);
    }

    private URI resolveRedirectionEndpointUri(URI configuredUri, SecurityEnvironment environment) {
        if (configuredUri.isAbsolute()) {
            return configuredUri;
        }
        return requestOrigin(environment).resolve(configuredUri);
    }

    private URI requestOrigin(SecurityEnvironment environment) {
        URI targetUri = environment.targetUri();
        if (targetUri != null && targetUri.getScheme() != null && targetUri.getRawAuthority() != null) {
            return URI.create(targetUri.getScheme() + "://" + targetUri.getRawAuthority());
        }

        List<String> host = environment.headers().get(HeaderNames.HOST.defaultCase());
        if (host != null && !host.isEmpty()) {
            return URI.create(environment.transport().toLowerCase(Locale.ROOT) + "://" + host.getFirst());
        }

        throw new IllegalStateException(
                "Host header or target URI is required when redirection-endpoint-uri is configured as a local path");
    }

    private String randomValue() {
        byte[] bytes = new byte[RANDOM_VALUE_BYTES];
        secureRandom.nextBytes(bytes);
        return base64Url(bytes);
    }

    private static byte[] sha256(String value) {
        try {
            return MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.US_ASCII));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    private static String base64Url(byte[] bytes) {
        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(bytes);
    }
}
