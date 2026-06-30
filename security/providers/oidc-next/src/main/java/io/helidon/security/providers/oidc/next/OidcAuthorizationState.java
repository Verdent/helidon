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

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Objects;
import java.util.Optional;

/**
 * Versioned Authorization Request state that carries an untrusted tenant-routing hint and a random request identifier.
 * The routed tenant must not be trusted until the protected Authentication Request cookie confirms both the tenant id
 * and the complete state value.
 */
record OidcAuthorizationState(String value, String routedTenantId, String requestId) {
    private static final String VERSION_PREFIX = "s1.";
    private static final int REQUEST_ID_BYTES = 32;
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

    OidcAuthorizationState {
        Objects.requireNonNull(value);
        Objects.requireNonNull(routedTenantId);
        Objects.requireNonNull(requestId);
    }

    static OidcAuthorizationState create(String tenantId, String requestId) {
        Objects.requireNonNull(tenantId);
        if (tenantId.isEmpty()) {
            throw new IllegalArgumentException("OIDC tenant id must not be empty");
        }
        if (!validRequestId(requestId)) {
            throw new IllegalArgumentException("OIDC Authorization Request state identifier must contain 256 bits");
        }
        String encodedTenantId = ENCODER.encodeToString(tenantId.getBytes(StandardCharsets.UTF_8));
        return new OidcAuthorizationState(VERSION_PREFIX + encodedTenantId + "." + requestId,
                                          tenantId,
                                          requestId);
    }

    static Optional<OidcAuthorizationState> parse(String value) {
        Objects.requireNonNull(value);
        if (!value.startsWith(VERSION_PREFIX)) {
            return Optional.empty();
        }
        int separator = value.indexOf('.', VERSION_PREFIX.length());
        if (separator == VERSION_PREFIX.length()
                || separator == value.length() - 1
                || value.indexOf('.', separator + 1) >= 0) {
            return Optional.empty();
        }

        String encodedTenantId = value.substring(VERSION_PREFIX.length(), separator);
        String requestId = value.substring(separator + 1);
        if (!validRequestId(requestId)) {
            return Optional.empty();
        }
        try {
            byte[] tenantIdBytes = DECODER.decode(encodedTenantId);
            String tenantId = new String(tenantIdBytes, StandardCharsets.UTF_8);
            if (tenantId.isEmpty()
                    || !ENCODER.encodeToString(tenantId.getBytes(StandardCharsets.UTF_8)).equals(encodedTenantId)) {
                return Optional.empty();
            }
            return Optional.of(new OidcAuthorizationState(value, tenantId, requestId));
        } catch (IllegalArgumentException _) {
            return Optional.empty();
        }
    }

    private static boolean validRequestId(String requestId) {
        if (requestId == null) {
            return false;
        }
        try {
            byte[] bytes = DECODER.decode(requestId);
            return bytes.length == REQUEST_ID_BYTES && ENCODER.encodeToString(bytes).equals(requestId);
        } catch (IllegalArgumentException _) {
            return false;
        }
    }
}
