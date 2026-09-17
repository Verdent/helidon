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

import java.math.BigDecimal;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import io.helidon.json.JsonObject;

final class OidcTokenLifetime {
    private OidcTokenLifetime() {
    }

    static Optional<Long> expiresIn(JsonObject json) {
        /*
         * RFC 6749 section 5.1 and RFC 8693 section 2.2.1 define expires_in as the lifetime in seconds from response
         * generation. Omission is permitted, but an explicit zero denotes an already-expired token, not an unknown
         * lifetime. Reject unusable responses before their access tokens can be sent to UserInfo or another resource.
         * https://www.rfc-editor.org/rfc/rfc6749.html#section-5.1
         * https://www.rfc-editor.org/rfc/rfc8693.html#section-2.2.1
         */
        return json.numberValue("expires_in")
                .map(BigDecimal::longValueExact)
                .map(value -> {
                    if (value <= 0) {
                        throw new IllegalArgumentException("Token Endpoint response expires_in must be positive");
                    }
                    return value;
                });
    }

    static Instant expiresAt(Instant referenceTime, long expiresIn) {
        // The difference between any two Instant epoch seconds fits in a long. Saturating a positive lifetime at the
        // representable bound shortens, never extends, the advertised lifetime and avoids overflowing the addition.
        long maximumSeconds = Instant.MAX.getEpochSecond() - referenceTime.getEpochSecond();
        return expiresIn > maximumSeconds ? Instant.MAX : referenceTime.plusSeconds(expiresIn);
    }

    static boolean activeAt(Instant expiresAt, Instant now, Duration clockSkew) {
        // Compare remaining time instead of adding/subtracting a potentially overflowing clock-skew duration.
        return Duration.between(now, expiresAt).compareTo(clockSkew) > 0;
    }
}
