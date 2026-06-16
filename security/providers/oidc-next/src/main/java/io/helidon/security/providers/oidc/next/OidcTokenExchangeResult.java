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

final class OidcTokenExchangeResult {
    private final OidcTokenExchangeStatus status;
    private final String description;
    private final OidcTokenExchangeResponse tokenResponse;
    private final OidcTokenErrorResponse errorResponse;
    private final Throwable cause;

    private OidcTokenExchangeResult(OidcTokenExchangeStatus status,
                                    String description,
                                    OidcTokenExchangeResponse tokenResponse,
                                    OidcTokenErrorResponse errorResponse,
                                    Throwable cause) {
        this.status = status;
        this.description = description;
        this.tokenResponse = tokenResponse;
        this.errorResponse = errorResponse;
        this.cause = cause;
    }

    static OidcTokenExchangeResult success(OidcTokenExchangeResponse tokenResponse) {
        return new OidcTokenExchangeResult(OidcTokenExchangeStatus.SUCCESS,
                                           "Token Exchange succeeded",
                                           tokenResponse,
                                           null,
                                           null);
    }

    static OidcTokenExchangeResult error(OidcTokenErrorResponse errorResponse) {
        return new OidcTokenExchangeResult(OidcTokenExchangeStatus.ERROR_RESPONSE,
                                           "Token Endpoint returned an Error Response",
                                           null,
                                           errorResponse,
                                           null);
    }

    static OidcTokenExchangeResult failure(String description) {
        return failure(description, null);
    }

    static OidcTokenExchangeResult failure(String description, Throwable cause) {
        return new OidcTokenExchangeResult(OidcTokenExchangeStatus.FAILURE,
                                           description,
                                           null,
                                           null,
                                           cause);
    }

    boolean succeeded() {
        return status == OidcTokenExchangeStatus.SUCCESS;
    }

    String description() {
        return description;
    }

    Optional<OidcTokenExchangeResponse> tokenResponse() {
        return Optional.ofNullable(tokenResponse);
    }

    Optional<OidcTokenErrorResponse> error() {
        return Optional.ofNullable(errorResponse);
    }

    Optional<Throwable> cause() {
        return Optional.ofNullable(cause);
    }

    private enum OidcTokenExchangeStatus {
        SUCCESS,
        ERROR_RESPONSE,
        FAILURE
    }
}
