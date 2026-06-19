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

final class OidcTokenExchangeResult {
    private final OidcTokenExchangeStatus status;
    private final String description;
    private final Optional<OidcTokenExchangeResponse> tokenResponse;
    private final Optional<OidcTokenErrorResponse> errorResponse;
    private final Optional<Throwable> cause;

    private OidcTokenExchangeResult(OidcTokenExchangeStatus status,
                                    String description,
                                    Optional<OidcTokenExchangeResponse> tokenResponse,
                                    Optional<OidcTokenErrorResponse> errorResponse,
                                    Optional<Throwable> cause) {
        this.status = status;
        this.description = description;
        this.tokenResponse = Objects.requireNonNull(tokenResponse);
        this.errorResponse = Objects.requireNonNull(errorResponse);
        this.cause = Objects.requireNonNull(cause);
    }

    static OidcTokenExchangeResult success(OidcTokenExchangeResponse tokenResponse) {
        return new OidcTokenExchangeResult(OidcTokenExchangeStatus.SUCCESS,
                                           "Token Exchange succeeded",
                                           Optional.of(tokenResponse),
                                           Optional.empty(),
                                           Optional.empty());
    }

    static OidcTokenExchangeResult error(OidcTokenErrorResponse errorResponse) {
        return new OidcTokenExchangeResult(OidcTokenExchangeStatus.ERROR_RESPONSE,
                                           "Token Endpoint returned an Error Response",
                                           Optional.empty(),
                                           Optional.of(errorResponse),
                                           Optional.empty());
    }

    static OidcTokenExchangeResult failure(String description) {
        return failure(description, null);
    }

    static OidcTokenExchangeResult failure(String description, Throwable cause) {
        return new OidcTokenExchangeResult(OidcTokenExchangeStatus.FAILURE,
                                           description,
                                           Optional.empty(),
                                           Optional.empty(),
                                           Optional.ofNullable(cause));
    }

    boolean succeeded() {
        return status == OidcTokenExchangeStatus.SUCCESS;
    }

    String description() {
        return description;
    }

    Optional<OidcTokenExchangeResponse> tokenResponse() {
        return tokenResponse;
    }

    Optional<OidcTokenErrorResponse> error() {
        return errorResponse;
    }

    Optional<Throwable> cause() {
        return cause;
    }

    private enum OidcTokenExchangeStatus {
        SUCCESS,
        ERROR_RESPONSE,
        FAILURE
    }
}
