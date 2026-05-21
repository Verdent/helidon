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

final class OidcIdTokenValidationResult {
    private final OidcValidatedIdToken validatedToken;
    private final String errorDescription;
    private final Throwable cause;

    private OidcIdTokenValidationResult(OidcValidatedIdToken validatedToken,
                                        String errorDescription,
                                        Throwable cause) {
        this.validatedToken = validatedToken;
        this.errorDescription = errorDescription;
        this.cause = cause;
    }

    static OidcIdTokenValidationResult success(OidcValidatedIdToken validatedToken) {
        return new OidcIdTokenValidationResult(validatedToken, null, null);
    }

    static OidcIdTokenValidationResult failure(String errorDescription) {
        return failure(errorDescription, null);
    }

    static OidcIdTokenValidationResult failure(String errorDescription, Throwable cause) {
        return new OidcIdTokenValidationResult(null, errorDescription, cause);
    }

    boolean succeeded() {
        return validatedToken != null;
    }

    Optional<OidcValidatedIdToken> validatedToken() {
        return Optional.ofNullable(validatedToken);
    }

    Optional<String> errorDescription() {
        return Optional.ofNullable(errorDescription);
    }

    Optional<Throwable> cause() {
        return Optional.ofNullable(cause);
    }
}
