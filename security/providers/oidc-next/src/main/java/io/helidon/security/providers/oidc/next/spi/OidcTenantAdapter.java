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

package io.helidon.security.providers.oidc.next.spi;

import java.net.URI;
import java.util.Optional;

import io.helidon.config.NamedService;
import io.helidon.security.providers.oidc.next.OidcJwtAccessTokenConfig;
import io.helidon.security.providers.oidc.next.OidcTenantConfig;
import io.helidon.webclient.api.WebClient;

/**
 * Tenant-scoped compatibility adapter for provider-specific bootstrap and protected signing keys.
 * <p>
 * An adapter prepares tenant defaults before normal OIDC Next configuration validation. It cannot bypass validation
 * of ID Token signatures, issuers, callbacks, or endpoint transport. The optional key credential is requested only
 * after the configured JWK Set endpoint refuses an unauthenticated GET; OIDC Next performs the retried GET against
 * that same URI and retains its key validation and refresh policy.
 */
public interface OidcTenantAdapter extends NamedService {
    /**
     * Prepare provider-specific tenant defaults. Explicit tenant settings should remain authoritative.
     * This method runs before the tenant prototype is built and must not perform remote I/O.
     *
     * @param tenant tenant builder
     */
    void configure(OidcTenantConfig.BuilderBase<?, ?> tenant);

    /**
     * Provider-specific JWT access-token layout to use when this tenant enables JWT validation without configuring
     * {@code protected-resource.token-validation.jwt}. Explicit tenant layouts always take precedence. The normal
     * RFC 9068 profile is used when this method returns empty.
     *
     * @return provider-specific default JWT access-token layout, if any
     */
    default Optional<OidcJwtAccessTokenConfig> jwtAccessTokenDefaults() {
        return Optional.empty();
    }

    /**
     * Trusted domain namespace for local principal identities when an adapter's provider shares its wire issuer
     * across distinct identity domains. The issuer in tokens is still validated unchanged.
     * <p>
     * The namespace must be stable for the lifetime of a tenant. Other OIDC tenants retain the normal issuer/subject
     * principal identity when this value is empty.
     *
     * @return trusted local identity namespace, if needed
     */
    default Optional<String> principalIdentityNamespace() {
        return Optional.empty();
    }

    /**
     * Obtain a bearer token for the configured JWK Set endpoint after an unauthorized response.
     * <p>
     * The same tenant WebClient is supplied for vendor-specific Token Endpoint grants. Its OIDC outbound security
     * routing is disabled to prevent recursive tenant initialization; callers must not alter its global headers.
     * Returning an empty value retains the original unauthorized response as a failed JWK Set load.
     *
     * @param tenant validated tenant configuration
     * @param jwkSetUri exact JWK Set URI to be retried, without redirects
     * @param webClient tenant protocol WebClient
     * @param clientCredentials standard Client Credentials Grant acquisition using the tenant's configured method
     * @return access token to send only to the same JWK Set URI
     */
    default Optional<String> jwkSetAccessToken(OidcTenantConfig tenant,
                                               URI jwkSetUri,
                                               WebClient webClient,
                                               ClientCredentials clientCredentials) {
        return Optional.empty();
    }

    /**
     * Acquire a Client Credentials access token through the configured Token Endpoint and client authentication.
     */
    @FunctionalInterface
    interface ClientCredentials {
        /**
         * Acquire a token for the given scope. No credentials or token are logged or sent to the JWK Set URI by this call.
         *
         * @param scope scope required to read the JWK Set
         * @return access token
         */
        String accessToken(String scope);
    }
}
