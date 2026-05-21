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

import io.helidon.http.HeaderNames;
import io.helidon.http.Status;
import io.helidon.security.AuthenticationResponse;
import io.helidon.security.OutboundSecurityResponse;
import io.helidon.security.SecurityResponse;

final class OidcResponseFactory {
    private static final String WWW_AUTHENTICATE = "WWW-Authenticate";

    private OidcResponseFactory() {
    }

    static OidcResponseFactory create() {
        return new OidcResponseFactory();
    }

    AuthenticationResponse missingBearerToken() {
        return AuthenticationResponse.builder()
                .status(SecurityResponse.SecurityStatus.FAILURE)
                .statusCode(401)
                .description("Bearer Token is required")
                .responseHeader(WWW_AUTHENTICATE, "Bearer")
                .build();
    }

    AuthenticationResponse bearerTokenValidationNotImplemented() {
        String description = "Bearer Token validation is not implemented yet";
        return AuthenticationResponse.builder()
                .status(SecurityResponse.SecurityStatus.FAILURE)
                .statusCode(401)
                .description(description)
                .responseHeader(WWW_AUTHENTICATE, bearerChallenge("invalid_token", description))
                .build();
    }

    AuthenticationResponse invalidBearerToken(String description) {
        return AuthenticationResponse.builder()
                .status(SecurityResponse.SecurityStatus.FAILURE)
                .statusCode(401)
                .description(description)
                .responseHeader(WWW_AUTHENTICATE, bearerChallenge("invalid_token", description))
                .build();
    }

    AuthenticationResponse authorizationCodeFlowInitiated(OidcAuthenticationRequest request) {
        return AuthenticationResponse.builder()
                .status(SecurityResponse.SecurityStatus.FAILURE_FINISH)
                .statusCode(Status.SEE_OTHER_303.code())
                .description("Redirecting to OpenID Provider Authorization Endpoint")
                .responseHeader(HeaderNames.LOCATION.defaultCase(), request.authorizationUri().toString())
                .responseHeader(HeaderNames.SET_COOKIE.defaultCase(), request.stateCookie())
                .build();
    }

    AuthenticationResponse ambiguousRequest() {
        return AuthenticationResponse.builder()
                .status(SecurityResponse.SecurityStatus.FAILURE)
                .statusCode(400)
                .description("OIDC request cannot be classified by protocol operation")
                .build();
    }

    AuthenticationResponse invalidBearerTokenRequest(String description) {
        return AuthenticationResponse.builder()
                .status(SecurityResponse.SecurityStatus.FAILURE)
                .statusCode(400)
                .description(description)
                .responseHeader(WWW_AUTHENTICATE, bearerChallenge("invalid_request", description))
                .build();
    }

    AuthenticationResponse optional(String description) {
        return AuthenticationResponse.builder()
                .status(SecurityResponse.SecurityStatus.ABSTAIN)
                .description(description)
                .build();
    }

    AuthenticationResponse tenantUnavailable(OidcTenantContext tenantContext) {
        return AuthenticationResponse.builder()
                .status(SecurityResponse.SecurityStatus.FAILURE)
                .statusCode(503)
                .description(tenantUnavailableDescription(tenantContext))
                .build();
    }

    OutboundSecurityResponse tokenPropagationNotImplemented() {
        return OutboundSecurityResponse.builder()
                .status(SecurityResponse.SecurityStatus.FAILURE)
                .description("Token Propagation is not implemented yet")
                .build();
    }

    OutboundSecurityResponse clientCredentialsGrantNotImplemented() {
        return OutboundSecurityResponse.builder()
                .status(SecurityResponse.SecurityStatus.FAILURE)
                .description("Client Credentials Grant is not implemented yet")
                .build();
    }

    OutboundSecurityResponse ambiguousOutboundRequest() {
        return OutboundSecurityResponse.builder()
                .status(SecurityResponse.SecurityStatus.FAILURE)
                .description("OIDC outbound request cannot be classified by protocol operation")
                .build();
    }

    OutboundSecurityResponse tenantUnavailableForOutbound(OidcTenantContext tenantContext) {
        return OutboundSecurityResponse.builder()
                .status(SecurityResponse.SecurityStatus.FAILURE)
                .description(tenantUnavailableDescription(tenantContext))
                .build();
    }

    private String tenantUnavailableDescription(OidcTenantContext tenantContext) {
        return switch (tenantContext.state()) {
            case NOT_READY -> "OIDC tenant is not ready: " + tenantContext.tenantId();
            case DISABLED -> "OIDC tenant is disabled: " + tenantContext.tenantId();
            case FAILED -> "OIDC tenant initialization failed: " + tenantContext.tenantId();
            case READY -> "OIDC tenant is ready: " + tenantContext.tenantId();
        };
    }

    private String bearerChallenge(String error, String description) {
        return "Bearer error=\"" + quotedString(error)
                + "\", error_description=\"" + quotedString(description) + "\"";
    }

    private String quotedString(String value) {
        return value.replace("\\", "\\\\")
                .replace("\"", "\\\"");
    }
}
