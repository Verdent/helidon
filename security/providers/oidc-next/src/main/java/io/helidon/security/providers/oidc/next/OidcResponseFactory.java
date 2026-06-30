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

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import io.helidon.http.HeaderNames;
import io.helidon.http.Status;
import io.helidon.security.AuthenticationResponse;
import io.helidon.security.OutboundSecurityResponse;
import io.helidon.security.SecurityResponse;
import io.helidon.security.Subject;

final class OidcResponseFactory {
    private static final String WWW_AUTHENTICATE = HeaderNames.WWW_AUTHENTICATE.defaultCase();
    private static final String INVALID_REQUEST = "invalid_request";
    private static final String INVALID_TOKEN = "invalid_token";
    private static final String INVALID_REQUEST_DESCRIPTION = "Bearer Token request is invalid";
    private static final String INVALID_TOKEN_DESCRIPTION = "Bearer Token is invalid";
    private static final String AUTHORIZATION_CODE_FLOW_UNAVAILABLE_DESCRIPTION = "OIDC authentication is unavailable";
    private static final String TENANT_UNAVAILABLE_DESCRIPTION = "OIDC tenant is unavailable";
    private static final String CLIENT_CREDENTIALS_FAILURE_DESCRIPTION = "Client Credentials Grant failed";
    private static final String TOKEN_EXCHANGE_FAILURE_DESCRIPTION = "Token Exchange failed";
    private static final String DEFAULT_CHALLENGE_REALM =
            OidcProtectedResourceConfigBlueprint.DEFAULT_CHALLENGE_REALM;

    private OidcResponseFactory() {
    }

    static AuthenticationResponse missingBearerToken(String realm) {
        return missingBearerToken(realm, Optional.empty());
    }

    static AuthenticationResponse missingBearerToken(String realm,
                                                     Optional<String> localAuthenticationRemovalCookie) {
        AuthenticationResponse.Builder builder = AuthenticationResponse.builder()
                .status(SecurityResponse.SecurityStatus.FAILURE)
                .statusCode(401)
                .description("Bearer Token is required")
                .responseHeader(WWW_AUTHENTICATE, bearerChallenge(realm));
        localAuthenticationRemovalCookie.ifPresent(cookie -> builder.responseHeader(
                HeaderNames.SET_COOKIE.defaultCase(),
                cookie));
        return builder.build();
    }

    static AuthenticationResponse missingAuthenticationCredential(Optional<String> localAuthenticationRemovalCookie) {
        AuthenticationResponse.Builder builder = AuthenticationResponse.builder()
                .status(SecurityResponse.SecurityStatus.FAILURE)
                .statusCode(401)
                .description("Authentication is required");
        localAuthenticationRemovalCookie.ifPresent(cookie -> builder.responseHeader(
                HeaderNames.SET_COOKIE.defaultCase(),
                cookie));
        return builder.build();
    }

    static AuthenticationResponse bearerTokenValidationNotConfigured(String realm) {
        return AuthenticationResponse.builder()
                .status(SecurityResponse.SecurityStatus.FAILURE)
                .statusCode(401)
                .description(INVALID_TOKEN_DESCRIPTION)
                .responseHeader(WWW_AUTHENTICATE, bearerChallenge(realm, INVALID_TOKEN, INVALID_TOKEN_DESCRIPTION))
                .build();
    }

    static AuthenticationResponse invalidBearerToken(String description, String realm) {
        return AuthenticationResponse.builder()
                .status(SecurityResponse.SecurityStatus.FAILURE)
                .statusCode(401)
                .description(INVALID_TOKEN_DESCRIPTION)
                .responseHeader(WWW_AUTHENTICATE, bearerChallenge(realm, INVALID_TOKEN, INVALID_TOKEN_DESCRIPTION))
                .build();
    }

    static AuthenticationResponse authorizationCodeFlowInitiated(OidcAuthenticationRequest request,
                                                                 Optional<String> localAuthenticationRemovalCookie) {
        List<String> cookies = new ArrayList<>(2);
        localAuthenticationRemovalCookie.ifPresent(cookies::add);
        cookies.add(request.stateCookie());
        return AuthenticationResponse.builder()
                .status(SecurityResponse.SecurityStatus.FAILURE_FINISH)
                .statusCode(Status.SEE_OTHER_303.code())
                .description("Redirecting to OpenID Provider Authorization Endpoint")
                .responseHeader(HeaderNames.LOCATION.defaultCase(), request.authorizationUri().toString())
                .responseHeader(HeaderNames.SET_COOKIE.defaultCase(),
                                List.copyOf(cookies))
                .build();
    }

    static AuthenticationResponse authorizationCodeFlowUnavailable(Optional<String> localAuthenticationRemovalCookie) {
        AuthenticationResponse.Builder builder = AuthenticationResponse.builder()
                .status(SecurityResponse.SecurityStatus.FAILURE)
                .statusCode(Status.SERVICE_UNAVAILABLE_503.code())
                .description(AUTHORIZATION_CODE_FLOW_UNAVAILABLE_DESCRIPTION);
        localAuthenticationRemovalCookie.ifPresent(cookie -> builder.responseHeader(
                HeaderNames.SET_COOKIE.defaultCase(),
                cookie));
        return builder.build();
    }

    static AuthenticationResponse localAuthenticationSucceeded(Subject subject, Optional<String> authenticationCookie) {
        AuthenticationResponse.Builder builder = AuthenticationResponse.builder()
                .status(SecurityResponse.SecurityStatus.SUCCESS)
                .user(subject);
        authenticationCookie.ifPresent(cookie -> builder.responseHeader(HeaderNames.SET_COOKIE.defaultCase(), cookie));
        return builder.build();
    }

    static AuthenticationResponse invalidBearerTokenRequest(String description, String realm) {
        return AuthenticationResponse.builder()
                .status(SecurityResponse.SecurityStatus.FAILURE)
                .statusCode(400)
                .description(INVALID_REQUEST_DESCRIPTION)
                .responseHeader(WWW_AUTHENTICATE, bearerChallenge(realm, INVALID_REQUEST, INVALID_REQUEST_DESCRIPTION))
                .build();
    }

    static AuthenticationResponse optional(String description) {
        return AuthenticationResponse.builder()
                .status(SecurityResponse.SecurityStatus.ABSTAIN)
                .description(description)
                .build();
    }

    static AuthenticationResponse tenantUnavailable(OidcTenantContext tenantContext) {
        return AuthenticationResponse.builder()
                .status(SecurityResponse.SecurityStatus.FAILURE)
                .statusCode(503)
                .description(TENANT_UNAVAILABLE_DESCRIPTION)
                .build();
    }

    static OutboundSecurityResponse clientCredentialsGrantFailed(OidcTokenEndpointResult result) {
        return OutboundSecurityResponse.builder()
                .status(SecurityResponse.SecurityStatus.FAILURE)
                .description(CLIENT_CREDENTIALS_FAILURE_DESCRIPTION)
                .build();
    }

    static OutboundSecurityResponse tokenExchangeFailed(OidcTokenExchangeResult result) {
        return OutboundSecurityResponse.builder()
                .status(SecurityResponse.SecurityStatus.FAILURE)
                .description(TOKEN_EXCHANGE_FAILURE_DESCRIPTION)
                .build();
    }

    static OutboundSecurityResponse ambiguousOutboundRequest() {
        return OutboundSecurityResponse.builder()
                .status(SecurityResponse.SecurityStatus.FAILURE)
                .description("OIDC outbound request is ambiguous")
                .build();
    }

    static OutboundSecurityResponse tenantUnavailableForOutbound(OidcTenantContext tenantContext) {
        return OutboundSecurityResponse.builder()
                .status(SecurityResponse.SecurityStatus.FAILURE)
                .description(TENANT_UNAVAILABLE_DESCRIPTION)
                .build();
    }

    private static String bearerChallenge(String realm) {
        /*
         * Spec: RFC 6750, 3 The WWW-Authenticate Response Header Field
         * https://www.rfc-editor.org/rfc/rfc6750.html#section-3
         * Quote: "This scheme MUST be followed by one or more auth-param values."
         * Quote: "If the request lacks any authentication information (e.g., the client was unaware that authentication
         * is necessary or attempted using an unsupported authentication method), the resource server SHOULD NOT include
         * an error code or other error information."
         */
        return "Bearer realm=\"" + quotedString(challengeValue(realm, DEFAULT_CHALLENGE_REALM)) + "\"";
    }

    private static String bearerChallenge(String realm, String error, String description) {
        String safeError = OidcOAuthErrorFields.validError(error) ? error : INVALID_TOKEN;
        return bearerChallenge(realm)
                + ", error=\"" + quotedString(safeError)
                + "\", error_description=\"" + quotedString(challengeValue(description,
                                                                           defaultDescription(safeError))) + "\"";
    }

    private static String challengeValue(String value, String fallback) {
        if (value != null && !value.isBlank() && OidcOAuthErrorFields.validErrorDescription(value)) {
            return value;
        }
        return fallback;
    }

    private static String defaultDescription(String error) {
        return INVALID_REQUEST.equals(error) ? INVALID_REQUEST_DESCRIPTION : INVALID_TOKEN_DESCRIPTION;
    }

    private static String quotedString(String value) {
        return value.replace("\\", "\\\\")
                .replace("\"", "\\\"");
    }
}
