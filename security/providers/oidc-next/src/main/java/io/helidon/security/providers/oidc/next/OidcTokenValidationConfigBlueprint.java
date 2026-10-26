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

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Optional;

import io.helidon.builder.api.Option;
import io.helidon.builder.api.Prototype;
import io.helidon.common.configurable.ResourceConfig;

/**
 * Access-token validation configuration for Protected Resource Bearer Token requests.
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
     * Expected access-token issuer, independent of the OpenID Connect issuer used for ID Tokens.
     * <p>
     * Defaults to the configured or discovered tenant issuer. Set this when the resource server trusts access tokens
     * from a different, explicitly identified authority. JWT verification then also needs a separately configured
     * {@link #jwksUri() JWK Set URI} or {@link #verificationJwk() local keys}; it never silently reuses keys discovered
     * for another issuer. A returned introspection {@code iss} must match this value when present.
     *
     * @return trusted access-token issuer
     */
    @Option.Configured
    Optional<String> issuer();

    /**
     * JWT access-token layout requirements.
     * <p>
     * Used with {@link OidcTokenValidationMethod#JWT}. When omitted, the tenant adapter can supply a provider-specific
     * default; otherwise the RFC 9068 profile is used. Explicitly configured layouts take precedence over adapter
     * defaults. A custom profile can validate provider-specific token types and claims while retaining signature,
     * issuer, and expiration checks. Audience validation remains enabled by default; see
     * {@link #audienceValidationEnabled()} for the explicit opt-out.
     *
     * @return configured JWT access-token layout, or the resolved default after tenant configuration, if present
     */
    @Option.Configured
    Optional<OidcJwtAccessTokenConfig> jwt();

    /**
     * Access-token audience expected when audience validation is required.
     * <p>
     * For JWT access-token validation, this should identify the current resource server. RFC 9068 requires JWT access
     * tokens to contain {@code aud}, and requires the resource server to validate that {@code aud} identifies itself.
     * The configured value must not be blank or padded.
     *
     * @return expected audience
     */
    @Option.Configured
    Optional<String> audience();

    /**
     * Whether access-token audience validation is enabled.
     * <p>
     * Defaults to {@code true}. Disabling this option bypasses the local resource audience check for both RFC 9068 and
     * CUSTOM JWT layouts; for the former it is not RFC 9068-conformant. Tokens intended for another resource server
     * could be accepted. Use only for testing, local development, or explicitly risk-accepted legacy deployments.
     * For introspection, disabling this option can be useful when the Authorization Server omits {@code aud}.
     *
     * @return whether access-token audience validation is enabled
     */
    @Option.Configured
    @Option.DefaultBoolean(true)
    boolean audienceValidationEnabled();

    /**
     * RFC 7662 Token Introspection request configuration.
     * <p>
     * Used only when {@link #method()} is {@link OidcTokenValidationMethod#INTROSPECTION}. Authentication defaults to
     * {@link OidcClientAuthenticationMethod#CLIENT_SECRET_BASIC} when a client secret is available either here or at
     * the tenant level.
     *
     * @return Token Introspection request configuration
     */
    @Option.Configured
    @Option.Default("create()")
    OidcIntrospectionConfig introspection();

    /**
     * RFC 8705 certificate-bound access-token validation configuration.
     * <p>
     * Applies to Protected Resource Bearer Token requests.
     *
     * @return certificate-bound access-token validation configuration
     */
    @Option.Configured
    @Option.Default("create()")
    OidcCertificateBoundAccessTokenConfig certificateBoundAccessTokens();

    /**
     * Locally provisioned JWK Set for JWT access-token signature verification.
     * <p>
     * When present, only these keys are used for access tokens; provider JWKS keys are not used as a fallback.
     * This source is required for HMAC access-token algorithms. It is independent of ID Token verification,
     * UserInfo, Request Object encryption, client authentication, and RP decryption keys.
     * The keys must be provisioned by the trusted authorization server. Filesystem, classpath, and inline content
     * sources are supported; URI sources are rejected before opening. The tenant JWK refresh settings apply.
     * <p>
     * When absent, access tokens use {@link #jwksUri()} if configured, otherwise the provider's public JWK Set if its
     * issuer matches the trusted access-token issuer. This option requires {@link #method()} to be
     * {@link OidcTokenValidationMethod#JWT}. A trusted issuer is required with either source.
     *
     * @return local access-token verification JWK Set resource configuration
     */
    @Option.Configured
    @Option.Confidential
    Optional<ResourceConfig> verificationJwk();

    /**
     * Local private JWK Set used to decrypt JWT access tokens issued for this resource server.
     * <p>
     * This is not the issuer's public signing JWK Set, nor the RP's ID Token decryption key. Keys are loaded once per
     * ready tenant, and URI-backed sources are rejected before opening. A configured key requires explicit
     * {@link #allowedEncryptionAlgorithms()} and {@link #allowedContentEncryptionAlgorithms()} matching the algorithms
     * agreed with the authorization server. Without this option, encrypted tokens are rejected by local JWT validation.
     * RSA decryption keys must be at least 2048 bits.
     *
     * @return private access-token decryption JWK Set resource configuration
     */
    @Option.Configured("decryption-jwk")
    @Option.Confidential
    Optional<ResourceConfig> decryptionJwk();

    /**
     * Agreed JWE key management algorithms for encrypted JWT access tokens.
     * <p>
     * Must be nonempty when {@link #decryptionJwk()} is configured; otherwise it must be empty. Supported values are
     * {@code RSA-OAEP-256} and {@code RSA-OAEP}. Values are case-sensitive and unsupported algorithms are rejected
     * when an enabled tenant is built. If more than one algorithm is allowed, every decryption JWK must declare its
     * own {@code alg} so a single key cannot be used with both algorithms.
     *
     * @return allowed access-token JWE key management algorithms
     */
    @Option.Configured
    @Option.Singular("allowedEncryptionAlgorithm")
    List<String> allowedEncryptionAlgorithms();

    /**
     * Agreed JWE content encryption algorithms for encrypted JWT access tokens.
     * <p>
     * Must be nonempty when {@link #decryptionJwk()} is configured; otherwise it must be empty. Supported values are
     * {@code A128GCM}, {@code A192GCM}, {@code A256GCM}, {@code A128CBC-HS256}, {@code A192CBC-HS384}, and
     * {@code A256CBC-HS512}. Values are case-sensitive and unsupported algorithms are rejected for enabled tenants.
     *
     * @return allowed access-token JWE content encryption algorithms
     */
    @Option.Configured
    @Option.Singular("allowedContentEncryptionAlgorithm")
    List<String> allowedContentEncryptionAlgorithms();

    /**
     * Whether to reject signed-only JWT access tokens.
     * <p>
     * Defaults to {@code true} when {@link #decryptionJwk()} is configured, and {@code false} otherwise. Set to
     * {@code false} explicitly only when accepting both signed-only and encrypted access tokens is necessary;
     * RFC 9068 recommends rejecting unencrypted access tokens when encryption was negotiated.
     * {@code true} requires a decryption key and {@link #method()} set to {@link OidcTokenValidationMethod#JWT}.
     *
     * @return explicit encryption requirement, if any
     */
    @Option.Configured
    Optional<Boolean> encryptionRequired();

    /**
     * Public JWK Set URI for independently validated JWT access tokens.
     * <p>
     * Configure this when the access-token issuer differs from the OIDC issuer or uses different signing keys. The
     * tenant WebClient fetches these public keys with the normal JWK refresh policy, without redirects or automatic
     * OP-adapter bearer credentials. Explicitly configured WebClient headers and TLS settings still apply.
     * HTTPS is required unless {@code endpoints.tls-required} is disabled for development. Mutually exclusive with
     * {@link #verificationJwk()}; HMAC keys must instead be provisioned locally.
     *
     * @return access-token JWK Set URI
     */
    @Option.Configured
    Optional<URI> jwksUri();

    /**
     * Allowed JWS algorithms for JWT access tokens.
     * <p>
     * The list must not be empty and must not contain blank, padded, or {@code none} values.
     * A selected RSA verification key must have a modulus of at least 2048 bits. A JWK without the optional {@code alg}
     * member may be used with any compatible allowed algorithm; a declared JWK {@code alg} must match the JWT header.
     * When the JWT omits {@code kid}, exactly one key must remain eligible after all key constraints are applied.
     * HMAC algorithms require {@link #verificationJwk()}; symmetric keys must not be published in the provider JWKS.
     *
     * @return allowed algorithms
     */
    @Option.Configured
    @Option.Default({"RS256"})
    @Option.Singular("allowedAlgorithm")
    List<String> allowedAlgorithms();

    /**
     * Token time validation clock skew.
     * <p>
     * Must not be negative.
     *
     * @return clock skew
     */
    @Option.Configured
    @Option.Default("PT1M")
    Duration clockSkew();
}
