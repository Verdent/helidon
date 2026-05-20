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
import java.util.List;
import java.util.Optional;

import io.helidon.builder.api.Option;
import io.helidon.builder.api.Prototype;

/**
 * Access-token validation configuration.
 */
@Prototype.Blueprint
@Prototype.Configured
interface OidcTokenValidationConfigBlueprint {
    /**
     * Access-token validation method.
     *
     * @return token validation method
     */
    @Option.Configured
    Optional<OidcTokenValidationMethod> method();

    /**
     * Access-token audience expected when audience validation is required.
     *
     * @return expected audience
     */
    @Option.Configured
    Optional<String> audience();

    /**
     * Whether access-token audience validation is enabled.
     *
     * @return whether access-token audience validation is enabled
     */
    @Option.Configured
    @Option.DefaultBoolean(true)
    boolean audienceValidationEnabled();

    /**
     * Allowed JWS algorithms for JWT access tokens.
     *
     * @return allowed algorithms
     */
    @Option.Configured
    @Option.Default({"RS256"})
    @Option.Singular("allowedAlgorithm")
    List<String> allowedAlgorithms();

    /**
     * Token time validation clock skew.
     *
     * @return clock skew
     */
    @Option.Configured
    @Option.Default("PT1M")
    Duration clockSkew();
}
