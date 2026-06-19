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

import java.util.Objects;
import java.util.Optional;

final class OidcPushedAuthorizationRequestResult {
    private final OidcPushedAuthorizationRequestStatus status;
    private final String description;
    private final Optional<OidcPushedAuthorizationResponse> response;
    private final Optional<OidcTokenErrorResponse> errorResponse;
    private final Optional<Throwable> cause;

    private OidcPushedAuthorizationRequestResult(OidcPushedAuthorizationRequestStatus status,
                                                 String description,
                                                 Optional<OidcPushedAuthorizationResponse> response,
                                                 Optional<OidcTokenErrorResponse> errorResponse,
                                                 Optional<Throwable> cause) {
        this.status = status;
        this.description = description;
        this.response = Objects.requireNonNull(response);
        this.errorResponse = Objects.requireNonNull(errorResponse);
        this.cause = Objects.requireNonNull(cause);
    }

    static OidcPushedAuthorizationRequestResult success(OidcPushedAuthorizationResponse response) {
        return new OidcPushedAuthorizationRequestResult(OidcPushedAuthorizationRequestStatus.SUCCESS,
                                                        "Pushed Authorization Request succeeded",
                                                        Optional.of(response),
                                                        Optional.empty(),
                                                        Optional.empty());
    }

    static OidcPushedAuthorizationRequestResult error(OidcTokenErrorResponse errorResponse) {
        return new OidcPushedAuthorizationRequestResult(OidcPushedAuthorizationRequestStatus.ERROR_RESPONSE,
                                                        "Pushed Authorization Request Endpoint returned an Error Response",
                                                        Optional.empty(),
                                                        Optional.of(errorResponse),
                                                        Optional.empty());
    }

    static OidcPushedAuthorizationRequestResult failure(String description) {
        return failure(description, null);
    }

    static OidcPushedAuthorizationRequestResult failure(String description, Throwable cause) {
        return new OidcPushedAuthorizationRequestResult(OidcPushedAuthorizationRequestStatus.FAILURE,
                                                        description,
                                                        Optional.empty(),
                                                        Optional.empty(),
                                                        Optional.ofNullable(cause));
    }

    boolean succeeded() {
        return status == OidcPushedAuthorizationRequestStatus.SUCCESS;
    }

    boolean errorResponse() {
        return status == OidcPushedAuthorizationRequestStatus.ERROR_RESPONSE;
    }

    String description() {
        return description;
    }

    Optional<OidcPushedAuthorizationResponse> response() {
        return response;
    }

    Optional<OidcTokenErrorResponse> error() {
        return errorResponse;
    }

    Optional<Throwable> cause() {
        return cause;
    }

    private enum OidcPushedAuthorizationRequestStatus {
        SUCCESS,
        ERROR_RESPONSE,
        FAILURE
    }
}
