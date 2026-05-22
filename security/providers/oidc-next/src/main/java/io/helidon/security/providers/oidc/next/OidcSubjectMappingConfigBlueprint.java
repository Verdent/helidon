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

import io.helidon.builder.api.Option;
import io.helidon.builder.api.Prototype;

/**
 * Subject mapping configuration.
 */
@Prototype.Blueprint
@Prototype.Configured
interface OidcSubjectMappingConfigBlueprint {
    /**
     * Principal id claim paths, in preference order.
     *
     * @return principal id claim paths
     */
    @Option.Configured
    @Option.Default({"sub", "username", "client_id"})
    @Option.Singular("principalIdClaim")
    List<String> principalIdClaimPaths();

    /**
     * Principal name claim paths, in preference order.
     *
     * @return principal name claim paths
     */
    @Option.Configured
    @Option.Default({"preferred_username", "username"})
    @Option.Singular("principalNameClaim")
    List<String> principalNameClaimPaths();

    /**
     * Role claim paths.
     *
     * @return role claim paths
     */
    @Option.Configured
    @Option.Default({"groups"})
    @Option.Singular("roleClaim")
    List<String> roleClaimPaths();

    /**
     * Scope claim paths.
     *
     * @return scope claim paths
     */
    @Option.Configured
    @Option.Default({"scope"})
    @Option.Singular("scopeClaim")
    List<String> scopeClaimPaths();

    /**
     * Whether scope claims are mapped to scope grants.
     *
     * @return whether scope grants are enabled
     */
    @Option.Configured
    @Option.DefaultBoolean(true)
    boolean scopeGrantsEnabled();
}
