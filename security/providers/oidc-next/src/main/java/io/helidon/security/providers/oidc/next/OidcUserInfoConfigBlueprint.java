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

import java.util.List;
import java.util.Optional;

import io.helidon.builder.api.Option;
import io.helidon.builder.api.Prototype;

/**
 * UserInfo request configuration.
 */
@Prototype.Blueprint
@Prototype.Configured
interface OidcUserInfoConfigBlueprint {
    /**
     * Whether UserInfo requests are enabled when {@code user-info} is configured.
     *
     * @return whether UserInfo requests are enabled
     */
    @Option.Configured
    @Option.DefaultBoolean(true)
    boolean enabled();

    /**
     * Expected signed and/or encrypted JWT UserInfo response configuration.
     * <p>
     * When omitted, the UserInfo response must be a JSON object. When present, its registered signing and encryption
     * algorithms determine whether a signed JWT, directly encrypted Claims Set, or signed-then-encrypted Nested JWT is
     * required.
     *
     * @return UserInfo JWT response configuration
     */
    @Option.Configured
    Optional<OidcUserInfoJwtConfig> jwt();

    /**
     * UserInfo claims stored in the protected local authentication result cookie.
     *
     * @return UserInfo storage policy
     */
    @Option.Configured
    @Option.Default("MAPPED")
    OidcUserInfoStoragePolicy storagePolicy();

    /**
     * Additional UserInfo claim paths stored by the mapped storage policy.
     * <p>
     * The provider always stores {@code sub} and claim paths used by subject mapping. Configure this list for additional
     * UserInfo claims that must be exposed as principal attributes.
     *
     * @return additional UserInfo claim paths to store
     */
    @Option.Configured
    @Option.Singular("attributeClaim")
    List<String> attributeClaimPaths();
}
