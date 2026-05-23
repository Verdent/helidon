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

import java.util.Optional;

final class OidcTokenEndpointResult {
    private final OidcTokenEndpointStatus status;
    private final String description;
    private final OidcTokenResponse tokenResponse;
    private final OidcTokenErrorResponse errorResponse;
    private final Throwable cause;

    private OidcTokenEndpointResult(OidcTokenEndpointStatus status,
                                    String description,
                                    OidcTokenResponse tokenResponse,
                                    OidcTokenErrorResponse errorResponse,
                                    Throwable cause) {
        this.status = status;
        this.description = description;
        this.tokenResponse = tokenResponse;
        this.errorResponse = errorResponse;
        this.cause = cause;
    }

    static OidcTokenEndpointResult success(OidcTokenResponse tokenResponse) {
        return new OidcTokenEndpointResult(OidcTokenEndpointStatus.SUCCESS,
                                           "Token Endpoint exchange succeeded",
                                           tokenResponse,
                                           null,
                                           null);
    }

    static OidcTokenEndpointResult error(OidcTokenErrorResponse errorResponse) {
        return new OidcTokenEndpointResult(OidcTokenEndpointStatus.ERROR_RESPONSE,
                                           "Token Endpoint returned an Error Response",
                                           null,
                                           errorResponse,
                                           null);
    }

    static OidcTokenEndpointResult failure(String description) {
        return failure(description, null);
    }

    static OidcTokenEndpointResult failure(String description, Throwable cause) {
        return new OidcTokenEndpointResult(OidcTokenEndpointStatus.FAILURE,
                                           description,
                                           null,
                                           null,
                                           cause);
    }

    boolean succeeded() {
        return status == OidcTokenEndpointStatus.SUCCESS;
    }

    boolean errorResponse() {
        return status == OidcTokenEndpointStatus.ERROR_RESPONSE;
    }

    String description() {
        return description;
    }

    Optional<OidcTokenResponse> tokenResponse() {
        return Optional.ofNullable(tokenResponse);
    }

    Optional<OidcTokenErrorResponse> error() {
        return Optional.ofNullable(errorResponse);
    }

    Optional<Throwable> cause() {
        return Optional.ofNullable(cause);
    }

    private enum OidcTokenEndpointStatus {
        SUCCESS,
        ERROR_RESPONSE,
        FAILURE
    }
}
