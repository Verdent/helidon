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

import io.helidon.builder.api.Option;
import io.helidon.builder.api.Prototype;

/**
 * Password-based protection for cookies containing OIDC state and local authentication data.
 */
@Prototype.Blueprint
@Prototype.Configured
interface OidcCookieProtectionConfigBlueprint {
    /**
     * Password from which cookie encryption keys are derived.
     * <p>
     * The password must contain between 16 and 1024 characters. It is processed with
     * PBKDF2-HMAC-SHA-256 before purpose-specific AES-256-GCM keys are derived. Use a strong, deployment-specific
     * password and provide the same value to every replica that must accept the same browser session.
     *
     * @return cookie protection password
     */
    @Option.Configured
    @Option.Confidential
    String password();

    /**
     * PBKDF2 salt as the canonical, unpadded Base64URL encoding of exactly 16 bytes.
     * <p>
     * A salt is public and does not need to be kept confidential. When omitted, a stable salt is derived from the
     * tenant id and client id. Configure a random salt when independent deployments using the same tenant, client,
     * and password must derive different keys. All replicas of one deployment must use the same value.
     *
     * @return explicitly configured PBKDF2 salt
     */
    @Option.Configured
    Optional<String> salt();

    /**
     * Number of PBKDF2-HMAC-SHA-256 iterations.
     * <p>
     * The value must be between 600,000 and 10,000,000, inclusive. All replicas of one deployment must use the same
     * value.
     *
     * @return PBKDF2 iteration count
     */
    @Option.Configured
    @Option.DefaultInt(600_000)
    int iterations();
}
