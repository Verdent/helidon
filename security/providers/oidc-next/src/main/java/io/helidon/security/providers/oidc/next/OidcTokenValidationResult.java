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

final class OidcTokenValidationResult {
    private final OidcValidatedJwt validatedJwt;
    private final OidcValidatedIntrospection validatedIntrospection;
    private final String errorDescription;
    private final Throwable cause;

    private OidcTokenValidationResult(OidcValidatedJwt validatedJwt,
                                      OidcValidatedIntrospection validatedIntrospection,
                                      String errorDescription,
                                      Throwable cause) {
        this.validatedJwt = validatedJwt;
        this.validatedIntrospection = validatedIntrospection;
        this.errorDescription = errorDescription;
        this.cause = cause;
    }

    static OidcTokenValidationResult success(OidcValidatedJwt validatedJwt) {
        return new OidcTokenValidationResult(validatedJwt, null, null, null);
    }

    static OidcTokenValidationResult success(OidcValidatedIntrospection validatedIntrospection) {
        return new OidcTokenValidationResult(null, validatedIntrospection, null, null);
    }

    static OidcTokenValidationResult failure(String errorDescription) {
        return failure(errorDescription, null);
    }

    static OidcTokenValidationResult failure(String errorDescription, Throwable cause) {
        return new OidcTokenValidationResult(null, null, errorDescription, cause);
    }

    boolean succeeded() {
        return validatedJwt != null || validatedIntrospection != null;
    }

    Optional<OidcValidatedJwt> validatedJwt() {
        return Optional.ofNullable(validatedJwt);
    }

    Optional<OidcValidatedIntrospection> validatedIntrospection() {
        return Optional.ofNullable(validatedIntrospection);
    }

    Optional<String> errorDescription() {
        return Optional.ofNullable(errorDescription);
    }

    Optional<Throwable> cause() {
        return Optional.ofNullable(cause);
    }
}
