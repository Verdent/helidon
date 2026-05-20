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

import java.time.Duration;
import java.util.Optional;

import io.helidon.builder.api.Option;
import io.helidon.builder.api.Prototype;

/**
 * Cookie configuration used by stateful OIDC flows.
 */
@Prototype.Blueprint
@Prototype.Configured
interface OidcCookieConfigBlueprint {
    /**
     * Authentication Request state cookie name.
     *
     * @return cookie name
     */
    @Option.Configured
    @Option.Default("__Host-helidon-oidc-state")
    String authenticationRequestCookieName();

    /**
     * Authentication Request state lifetime.
     *
     * @return Authentication Request state lifetime
     */
    @Option.Configured
    @Option.Default("PT5M")
    Duration authenticationRequestLifetime();

    /**
     * Cookie encryption secret.
     *
     * @return cookie encryption secret
     */
    @Option.Configured
    @Option.Confidential
    Optional<String> encryptionSecret();
}
