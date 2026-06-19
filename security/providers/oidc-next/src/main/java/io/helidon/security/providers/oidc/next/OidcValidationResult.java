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

final class OidcValidationResult<T> {
    private final Optional<T> validatedToken;
    private final Optional<String> errorDescription;
    private final Optional<Throwable> cause;

    private OidcValidationResult(Optional<T> validatedToken, Optional<String> errorDescription, Optional<Throwable> cause) {
        this.validatedToken = Objects.requireNonNull(validatedToken);
        this.errorDescription = Objects.requireNonNull(errorDescription);
        this.cause = Objects.requireNonNull(cause);
    }

    static <T> OidcValidationResult<T> success(T validatedToken) {
        return new OidcValidationResult<>(Optional.of(validatedToken), Optional.empty(), Optional.empty());
    }

    static <T> OidcValidationResult<T> failure(String errorDescription) {
        return failure(errorDescription, null);
    }

    static <T> OidcValidationResult<T> failure(String errorDescription, Throwable cause) {
        return new OidcValidationResult<>(Optional.empty(),
                                          Optional.of(errorDescription),
                                          Optional.ofNullable(cause));
    }

    boolean succeeded() {
        return validatedToken.isPresent();
    }

    Optional<T> validatedToken() {
        return validatedToken;
    }

    Optional<String> errorDescription() {
        return errorDescription;
    }

    Optional<Throwable> cause() {
        return cause;
    }
}
