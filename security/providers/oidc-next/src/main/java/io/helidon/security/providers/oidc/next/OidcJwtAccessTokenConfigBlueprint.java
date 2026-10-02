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
import java.util.Map;

import io.helidon.builder.api.Option;
import io.helidon.builder.api.Prototype;

/**
 * JWT access-token layout requirements, independent of signature and issuer validation.
 */
@Prototype.Blueprint(decorator = OidcJwtAccessTokenConfigDecorator.class)
@Prototype.Configured
interface OidcJwtAccessTokenConfigBlueprint {
    /**
     * Token layout profile. Defaults to the RFC 9068 JWT Access Token Profile.
     *
     * @return access-token layout profile
     */
    @Option.Configured
    @Option.Default("RFC_9068")
    OidcJwtAccessTokenProfile profile();

    /**
     * Accepted JOSE header {@code typ} values, compared without regard to case.
     * <p>
     * The list must be nonempty and contain no blank or padded values. The header is required in both profiles.
     * RFC 9068 permits only {@code at+jwt} and {@code application/at+jwt}. A custom profile accepting other types
     * must configure {@link #requiredStringClaims()} with a signed claim that distinguishes access tokens from
     * other JWTs issued by the provider, such as Keycloak's payload {@code typ: Bearer}.
     *
     * @return accepted access-token header types
     */
    @Option.Configured
    @Option.Default({"at+jwt", "application/at+jwt"})
    @Option.Singular("allowedType")
    List<String> allowedTypes();

    /**
     * Additional required top-level payload claims.
     * <p>
     * Required values must be present, non-null, and nonblank when strings. Claim names are case-sensitive and must
     * not be blank or padded. RFC 9068's required claims remain mandatory in that profile. A custom profile always
     * requires issuer and expiration. Audience validation is enabled by default; it can be explicitly disabled using
     * {@code token-validation.audience-validation-enabled}. Issue time and not-before are validated whenever present;
     * include {@code iat} here to require issue time in a custom profile.
     *
     * @return additional required payload claims
     */
    @Option.Configured
    @Option.Singular("requiredClaim")
    List<String> requiredClaims();

    /**
     * Required top-level string payload claims and their exact, case-sensitive values.
     * <p>
     * Names and values must not be blank or padded. Choose a provider-defined access-token discriminator when
     * accepting header types that are also used by ID Tokens. These payload claims are checked after signature
     * verification. For example, Keycloak access tokens use {@code typ: Bearer}, and other providers can use
     * {@code token_use: access}.
     *
     * @return required string payload claims
     */
    @Option.Configured
    @Option.Singular("requiredStringClaim")
    Map<String, String> requiredStringClaims();
}
