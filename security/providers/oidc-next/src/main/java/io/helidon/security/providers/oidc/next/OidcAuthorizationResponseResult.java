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

import java.util.List;
import java.util.Optional;

import io.helidon.http.SetCookie;

final class OidcAuthorizationResponseResult {
    private final OidcAuthorizationResponseStatus status;
    private final String description;
    private final OidcTenantContext tenantContext;
    private final OidcAuthenticationRequestState authenticationRequestState;
    private final String authorizationCode;
    private final String error;
    private final String errorDescription;
    private final String errorUri;
    private final List<SetCookie> stateCookies;

    private OidcAuthorizationResponseResult(OidcAuthorizationResponseStatus status,
                                            String description,
                                            OidcTenantContext tenantContext,
                                            OidcAuthenticationRequestState authenticationRequestState,
                                            String authorizationCode,
                                            String error,
                                            String errorDescription,
                                            String errorUri,
                                            List<SetCookie> stateCookies) {
        this.status = status;
        this.description = description;
        this.tenantContext = tenantContext;
        this.authenticationRequestState = authenticationRequestState;
        this.authorizationCode = authorizationCode;
        this.error = error;
        this.errorDescription = errorDescription;
        this.errorUri = errorUri;
        this.stateCookies = List.copyOf(stateCookies);
    }

    static OidcAuthorizationResponseResult invalid(String description, List<SetCookie> stateCookies) {
        return new OidcAuthorizationResponseResult(OidcAuthorizationResponseStatus.INVALID,
                                                   description,
                                                   null,
                                                   null,
                                                   null,
                                                   null,
                                                   null,
                                                   null,
                                                   stateCookies);
    }

    static OidcAuthorizationResponseResult authorizationError(String error,
                                                              String errorDescription,
                                                              String errorUri,
                                                              OidcTenantContext tenantContext,
                                                              OidcAuthenticationRequestState state,
                                                              List<SetCookie> stateCookies) {
        return new OidcAuthorizationResponseResult(OidcAuthorizationResponseStatus.AUTHORIZATION_ERROR,
                                                   "OpenID Provider returned an Authorization Error Response",
                                                   tenantContext,
                                                   state,
                                                   null,
                                                   error,
                                                   errorDescription,
                                                   errorUri,
                                                   stateCookies);
    }

    static OidcAuthorizationResponseResult validated(String authorizationCode,
                                                     OidcTenantContext tenantContext,
                                                     OidcAuthenticationRequestState state,
                                                     List<SetCookie> stateCookies) {
        return new OidcAuthorizationResponseResult(OidcAuthorizationResponseStatus.VALIDATED,
                                                   "Authorization Response state is valid",
                                                   tenantContext,
                                                   state,
                                                   authorizationCode,
                                                   null,
                                                   null,
                                                   null,
                                                   stateCookies);
    }

    boolean stateValidated() {
        return status == OidcAuthorizationResponseStatus.VALIDATED;
    }

    boolean authorizationError() {
        return status == OidcAuthorizationResponseStatus.AUTHORIZATION_ERROR;
    }

    boolean invalid() {
        return status == OidcAuthorizationResponseStatus.INVALID;
    }

    String description() {
        return description;
    }

    Optional<OidcTenantContext> tenantContext() {
        return Optional.ofNullable(tenantContext);
    }

    Optional<OidcAuthenticationRequestState> authenticationRequestState() {
        return Optional.ofNullable(authenticationRequestState);
    }

    Optional<String> authorizationCode() {
        return Optional.ofNullable(authorizationCode);
    }

    Optional<String> error() {
        return Optional.ofNullable(error);
    }

    Optional<String> errorDescription() {
        return Optional.ofNullable(errorDescription);
    }

    Optional<String> errorUri() {
        return Optional.ofNullable(errorUri);
    }

    List<SetCookie> stateCookies() {
        return stateCookies;
    }

    private enum OidcAuthorizationResponseStatus {
        VALIDATED,
        AUTHORIZATION_ERROR,
        INVALID
    }
}
