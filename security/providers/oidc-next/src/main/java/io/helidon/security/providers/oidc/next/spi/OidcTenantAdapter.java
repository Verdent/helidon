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

import io.helidon.common.parameters.Parameters;
import io.helidon.config.NamedService;
import io.helidon.json.JsonObject;
import io.helidon.security.SecurityEnvironment;
import io.helidon.security.Subject;
import io.helidon.security.jwt.Jwt;
import io.helidon.security.providers.oidc.next.OidcJwtAccessTokenConfig;
import io.helidon.security.providers.oidc.next.OidcTenantConfig;
import io.helidon.webclient.api.WebClient;

/**
 * Explicitly selected, tenant-scoped extension for provider-specific defaults, protocol values, and checks.
 * <p>
 * All hooks are optional and apply only to the tenant selecting this adapter. The core owns the OIDC flow and checks
 * its configured transport, issuer, callback, signature, and correlation requirements. An adapter may transform
 * requests and token responses or replace mapped identities, so it is trusted security-sensitive application code:
 * install only an adapter that is allowed to decide the tenant's protocol and identity semantics. In particular,
 * successful token responses can contain bearer and refresh credentials and must not be logged or sent elsewhere.
 * The optional JWK Set credential is requested only after an unauthorized response and is retried against that same URI.
 */
public interface OidcTenantAdapter extends NamedService {
    /**
     * Prepare provider-specific tenant defaults. Explicit tenant settings should remain authoritative.
     * This method runs before the tenant prototype is built and must not perform remote I/O.
     *
     * @param tenant tenant builder
     */
    default void configure(OidcTenantConfig.BuilderBase<?, ?> tenant) {
    }

    /**
     * Customize an Authorization Code authentication request before its final values are stored in the protected
     * request cookie and, if enabled, signed as a Request Object or sent through PAR. The returned parameters are the
     * values the core sends and subsequently verifies. Derive a custom {@code state} or {@code nonce} from the supplied
     * cryptographically random default values, or generate equally unpredictable, per-transaction replacements.
     * The {@code state} is required; {@code nonce} is optional only in Authorization Code Flow. The core retains its
     * configured client, redirect URI, {@code openid} scope, PKCE binding, and JAR/PAR transport requirements.
     * Other parameters, such as {@code prompt}, {@code login_hint}, or {@code acr_values}, can be added or changed.
     *
     * @param tenant selected tenant
     * @param tenantId tenant id
     * @param environment initiating request environment
     * @param parameters default authentication request parameters
     * @return final authentication request parameters
     */
    default Parameters authorizationRequest(OidcTenantConfig tenant,
                                            String tenantId,
                                            SecurityEnvironment environment,
                                            Parameters parameters) {
        return parameters;
    }

    /**
     * Customize the RP-Initiated Logout query before redirecting to the selected End Session Endpoint. For example,
     * add a provider-specific {@code logout_hint} or {@code ui_locales}. The core preserves its validated
     * {@code post_logout_redirect_uri}, local ID Token hint, and client id; local cookie clearing is not customizable.
     *
     * @param tenant selected tenant
     * @param parameters default End Session query parameters
     * @return final End Session query parameters
     */
    default Parameters endSessionRequest(OidcTenantConfig tenant, Parameters parameters) {
        return parameters;
    }

    /**
     * Customize a Token Endpoint grant form before client authentication is added and the request is sent.
     * The extension must preserve values needed to complete the selected flow, including the correlation established
     * during the Authentication Request. This form may contain authorization codes, refresh tokens, or subject tokens;
     * do not log them. The core still parses the response for the selected grant.
     *
     * @param tenant selected tenant
     * @param grant grant being requested
     * @param parameters default grant form parameters
     * @return final grant form parameters
     */
    default Parameters tokenRequest(OidcTenantConfig tenant, TokenGrant grant, Parameters parameters) {
        return parameters;
    }

    /**
     * Transform a successful Token Endpoint JSON response before the core parses and validates the selected grant.
     * The core still requires a successful JSON response with no-store and no-cache headers. An adapter changing
     * token semantics takes responsibility for the meaning of any transformed values; ID Tokens still undergo normal
     * OIDC validation, whereas access tokens in browser and outbound grants may remain opaque.
     *
     * @param tenant selected tenant
     * @param grant grant being processed
     * @param response original successful JSON response
     * @return response for normal core processing
     */
    default JsonObject tokenResponse(OidcTenantConfig tenant, TokenGrant grant, JsonObject response) {
        return response;
    }

    /**
     * Customize an access-token introspection form before the resource server's client authentication is added.
     * The exact presented {@code token} must remain in the form; other parameters may be provider-specific.
     * The token is a credential and must not be logged.
     *
     * @param tenant selected tenant
     * @param parameters default introspection form
     * @return final introspection form
     */
    default Parameters introspectionRequest(OidcTenantConfig tenant, Parameters parameters) {
        return parameters;
    }

    /**
     * Normalize a successful JSON introspection response before the core checks its active status, issuer,
     * audience, token binding, and claims. An explicit {@code active: false} response is never transformed into a
     * valid token. The adapter is trusted to preserve the identity and security meaning of other transformed claims.
     *
     * @param tenant selected tenant
     * @param response original introspection response
     * @return response for normal core validation
     */
    default JsonObject introspectionResponse(OidcTenantConfig tenant, JsonObject response) {
        return response;
    }

    /**
     * Check a successful provider-specific Authorization Response after the core has validated the response state,
     * tenant, issuer, and callback URI, but before it redeems an authorization code. Throw
     * {@link IllegalArgumentException} to reject the response.
     *
     * @param tenant selected tenant
     * @param response complete Authorization Response query parameters
     */
    default void validateAuthorizationResponse(OidcTenantConfig tenant, Parameters response) {
    }

    /**
     * Require provider-specific properties of an ID Token after the core has verified its signature, normal OIDC
     * claims, and any refresh-token continuity checks. Throw {@link IllegalArgumentException} to reject the token.
     * This hook does not change the core's issuer, audience, expiration, or nonce validation.
     *
     * @param tenant selected tenant
     * @param jwt verified ID Token
     * @param previousIdToken previously validated ID Token when this token is from a refresh grant
     */
    default void validateIdToken(OidcTenantConfig tenant, Jwt jwt, Optional<Jwt> previousIdToken) {
    }

    /**
     * Require provider-specific claims in a JWT access token or authenticated introspection response after the core
     * has validated the token. Throw {@link IllegalArgumentException} to reject it.
     *
     * @param tenant selected tenant
     * @param claims validated access-token or introspection claims
     */
    default void validateAccessToken(OidcTenantConfig tenant, JsonObject claims) {
    }

    /**
     * Require provider-specific UserInfo properties after the core has validated any registered JWT processing and
     * matched the UserInfo {@code sub} exactly to the ID Token. This is called before the configured storage policy
     * removes unused claims, both on initial login and after refresh. Throw {@link IllegalArgumentException} to reject.
     *
     * @param tenant selected tenant
     * @param claims validated UserInfo claims
     */
    default void validateUserInfo(OidcTenantConfig tenant, JsonObject claims) {
    }

    /**
     * Map or enrich a subject after its underlying credentials and claims have been validated. Applies to browser
     * sessions, JWT bearer tokens, and introspected bearer tokens. The adapter is responsible for the identity and
     * credential semantics of a replacement subject; throwing rejects authentication without issuing a session cookie.
     *
     * @param tenant selected tenant
     * @param subject core-mapped subject
     * @return subject to use for authentication
     */
    default Subject mapSubject(OidcTenantConfig tenant, Subject subject) {
        return subject;
    }

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

    /**
     * Token Endpoint grant types whose forms can be customized.
     */
    enum TokenGrant {
        /** Authorization Code exchange. */
        AUTHORIZATION_CODE,
        /** Refresh-token exchange. */
        REFRESH_TOKEN,
        /** Client Credentials Grant. */
        CLIENT_CREDENTIALS,
        /** OAuth Token Exchange. */
        TOKEN_EXCHANGE
    }
}
