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

final class OidcTokenEndpointResult {
    private final OidcTokenEndpointStatus status;
    private final String description;
    private final Optional<OidcTokenResponse> tokenResponse;
    private final Optional<OidcTokenErrorResponse> errorResponse;
    private final Optional<Throwable> cause;

    private OidcTokenEndpointResult(OidcTokenEndpointStatus status,
                                    String description,
                                    Optional<OidcTokenResponse> tokenResponse,
                                    Optional<OidcTokenErrorResponse> errorResponse,
                                    Optional<Throwable> cause) {
        this.status = status;
        this.description = description;
        this.tokenResponse = Objects.requireNonNull(tokenResponse);
        this.errorResponse = Objects.requireNonNull(errorResponse);
        this.cause = Objects.requireNonNull(cause);
    }

    static OidcTokenEndpointResult success(OidcTokenResponse tokenResponse) {
        return new OidcTokenEndpointResult(OidcTokenEndpointStatus.SUCCESS,
                                           "Token Endpoint exchange succeeded",
                                           Optional.of(tokenResponse),
                                           Optional.empty(),
                                           Optional.empty());
    }

    static OidcTokenEndpointResult error(OidcTokenErrorResponse errorResponse) {
        return new OidcTokenEndpointResult(OidcTokenEndpointStatus.ERROR_RESPONSE,
                                           "Token Endpoint returned an Error Response",
                                           Optional.empty(),
                                           Optional.of(errorResponse),
                                           Optional.empty());
    }

    static OidcTokenEndpointResult failure(String description) {
        return failure(description, null);
    }

    static OidcTokenEndpointResult failure(String description, Throwable cause) {
        return new OidcTokenEndpointResult(OidcTokenEndpointStatus.FAILURE,
                                           description,
                                           Optional.empty(),
                                           Optional.empty(),
                                           Optional.ofNullable(cause));
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
        return tokenResponse;
    }

    Optional<OidcTokenErrorResponse> error() {
        return errorResponse;
    }

    Optional<Throwable> cause() {
        return cause;
    }

    private enum OidcTokenEndpointStatus {
        SUCCESS,
        ERROR_RESPONSE,
        FAILURE
    }
}
