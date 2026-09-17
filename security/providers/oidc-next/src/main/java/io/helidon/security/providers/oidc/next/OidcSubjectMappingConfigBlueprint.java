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
 * Subject mapping configuration.
 */
@Prototype.Blueprint
@Prototype.Configured
interface OidcSubjectMappingConfigBlueprint {
    /**
     * Protected Resource principal id claim paths, in preference order.
     * <p>
     * Defaults to {@code sub}. The selected claim is qualified by its issuer and claim path, so equal values from
     * different issuers or different claim paths are distinct identities. Alternative claims require an explicit
     * application-specific uniqueness and stability contract with the authorization server. Selecting {@code client_id}
     * identifies the requesting client, not the resource owner, and does not infer the token's grant type.
     * <p>
     * Authorization Code Flow always identifies the End-User by the ID Token's {@code iss} and {@code sub} claims, as
     * specified by OpenID Connect Core 1.0, section 5.7. These paths do not replace that OIDC identity.
     *
     * @return principal id claim paths
     */
    @Option.Configured
    @Option.Default({"sub"})
    @Option.Singular("principalIdClaim")
    List<String> principalIdClaimPaths();

    /**
     * Fallback principal id namespace for introspection without a configured or discovered issuer.
     * <p>
     * RFC 7662 permits introspection responses without {@code iss}. When an issuer is configured or discovered, that
     * issuer qualifies the principal id regardless of whether the response includes {@code iss}. Otherwise this
     * property must define a stable, application-controlled namespace for the trusted introspection endpoint's
     * identities. Values must be unique across independent identity authorities used by the application.
     * <p>
     * This local namespace is distinct from an OIDC issuer, does not populate the {@code iss} claim, and is ignored when
     * an issuer is configured or discovered. Response claims never change this namespace. The value must not be blank,
     * padded, or contain unpaired surrogates. JWT and Authorization Code Flow identities do not use this property.
     *
     * @return local introspection identity namespace
     */
    @Option.Configured
    Optional<String> principalIdNamespace();

    /**
     * Principal name claim paths, in preference order.
     * <p>
     * Falls back to the raw identity claim value, not the opaque, qualified principal id.
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
