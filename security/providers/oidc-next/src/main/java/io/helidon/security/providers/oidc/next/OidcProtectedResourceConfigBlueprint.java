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

import io.helidon.builder.api.Option;
import io.helidon.builder.api.Prototype;

/**
 * OAuth 2.0 Protected Resource configuration.
 */
@Prototype.Blueprint
@Prototype.Configured
interface OidcProtectedResourceConfigBlueprint {
    /**
     * Default realm for Bearer {@code WWW-Authenticate} challenges.
     */
    String DEFAULT_CHALLENGE_REALM = "helidon";

    /**
     * Whether Bearer Token authentication is enabled for Protected Resource requests.
     *
     * @return whether Bearer Token authentication is enabled
     */
    @Option.Configured
    @Option.DefaultBoolean(true)
    boolean enabled();

    /**
     * Access-token validation configuration.
     * <p>
     * Used for Protected Resource Bearer Token requests when {@link #enabled()} is {@code true}, and for refreshed
     * Authorization Code Flow access tokens when a validation method is configured.
     *
     * @return token validation configuration
     */
    @Option.Configured
    @Option.Default("create()")
    OidcTokenValidationConfig tokenValidation();

    /**
     * Realm value used in Bearer {@code WWW-Authenticate} challenges for Protected Resource requests.
     *
     * @return Bearer challenge realm
     */
    @Option.Configured("challenge-realm")
    @Option.Default(DEFAULT_CHALLENGE_REALM)
    String challengeRealm();
}
