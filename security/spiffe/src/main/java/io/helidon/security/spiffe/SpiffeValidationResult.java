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

package io.helidon.security.spiffe;

import java.util.Objects;
import java.util.Optional;

/**
 * Result of SPIFFE SVID validation.
 *
 * @param <T> validated SVID type
 */
public final class SpiffeValidationResult<T extends SpiffeSvid> {
    private final T svid;
    private final String failureMessage;
    private final Throwable cause;

    private SpiffeValidationResult(T svid, String failureMessage, Throwable cause) {
        this.svid = svid;
        this.failureMessage = failureMessage;
        this.cause = cause;
    }

    /**
     * Successful validation result.
     *
     * @param svid validated SVID
     * @param <T> SVID type
     * @return validation result
     */
    public static <T extends SpiffeSvid> SpiffeValidationResult<T> success(T svid) {
        return new SpiffeValidationResult<>(Objects.requireNonNull(svid, "SVID must not be null"), null, null);
    }

    /**
     * Failed validation result.
     *
     * @param message failure message
     * @param <T> SVID type
     * @return validation result
     */
    public static <T extends SpiffeSvid> SpiffeValidationResult<T> failure(String message) {
        return new SpiffeValidationResult<>(null, Objects.requireNonNull(message, "Failure message must not be null"), null);
    }

    /**
     * Failed validation result.
     *
     * @param message failure message
     * @param cause failure cause
     * @param <T> SVID type
     * @return validation result
     */
    public static <T extends SpiffeSvid> SpiffeValidationResult<T> failure(String message, Throwable cause) {
        return new SpiffeValidationResult<>(null,
                                            Objects.requireNonNull(message, "Failure message must not be null"),
                                            cause);
    }

    /**
     * Whether validation succeeded.
     *
     * @return whether validation succeeded
     */
    public boolean isValid() {
        return svid != null;
    }

    /**
     * Validated SVID.
     *
     * @return SVID if validation succeeded
     */
    public Optional<T> svid() {
        return Optional.ofNullable(svid);
    }

    /**
     * Failure message.
     *
     * @return failure message if validation failed
     */
    public Optional<String> failureMessage() {
        return Optional.ofNullable(failureMessage);
    }

    /**
     * Failure cause.
     *
     * @return failure cause if available
     */
    public Optional<Throwable> cause() {
        return Optional.ofNullable(cause);
    }
}
