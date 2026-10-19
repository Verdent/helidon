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
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import io.helidon.http.SetCookie;
import io.helidon.security.AuthenticationResponse;
import io.helidon.security.ProviderRequest;
import io.helidon.security.providers.oidc.next.spi.OidcBackChannelLogoutStore;

final class OidcAuthenticationOrchestrator {
    private static final System.Logger LOGGER = System.getLogger(OidcAuthenticationOrchestrator.class.getName());

    private final OidcProviderConfig config;
    private final OidcTenantRuntimeRegistry tenantRuntimeRegistry;
    private final OidcAuthenticationRequestFactory authenticationRequestFactory;
    private final OidcRefreshTokenManager refreshTokenManager;
    private final Map<OidcTokenValidationMethod, OidcAccessTokenValidator> accessTokenValidators;
    private final List<URI> redirectionEndpointUris;
    private final Set<String> backChannelLogoutPaths;

    private OidcAuthenticationOrchestrator(OidcProviderConfig config,
                                           OidcTenantRuntimeRegistry tenantRuntimeRegistry,
                                           OidcAuthenticationRequestFactory authenticationRequestFactory,
                                           OidcRefreshTokenManager refreshTokenManager,
                                           Map<OidcTokenValidationMethod, OidcAccessTokenValidator>
                                                   accessTokenValidators) {
        this.config = config;
        this.tenantRuntimeRegistry = tenantRuntimeRegistry;
        this.authenticationRequestFactory = authenticationRequestFactory;
        this.refreshTokenManager = refreshTokenManager;
        this.accessTokenValidators = accessTokenValidators;
        this.redirectionEndpointUris = OidcEndpointUris.redirectionEndpointUris(config);
        this.backChannelLogoutPaths = OidcEndpointUris.backChannelLogoutPaths(config);
    }

    static OidcAuthenticationOrchestrator create(OidcProviderConfig config,
                                                 OidcTenantRuntimeRegistry tenantRuntimeRegistry) {
        Map<OidcTokenValidationMethod, OidcAccessTokenValidator> accessTokenValidators = accessTokenValidators();
        return new OidcAuthenticationOrchestrator(config,
                                                  tenantRuntimeRegistry,
                                                  new OidcAuthenticationRequestFactory(),
                                                  new OidcRefreshTokenManager(),
                                                  accessTokenValidators);
    }

    AuthenticationResponse authenticate(ProviderRequest providerRequest) {
        URI targetUri = providerRequest.env().targetUri();
        if (targetUri != null && "POST".equals(providerRequest.env().method())
                && backChannelLogoutPaths.contains(OidcUri.path(targetUri))) {
            // The OP authenticates to this feature route with a signed Logout Token, never a browser cookie or Bearer.
            return AuthenticationResponse.abstain();
        }
        Optional<OidcTenantRuntimeRegistry.TenantSelection> selection = tenantRuntimeRegistry.select(providerRequest);
        if (selection.isEmpty()) {
            return AuthenticationResponse.abstain();
        }
        OidcTenantRuntimeRegistry.TenantSelection tenant = selection.orElseThrow();
        Optional<OidcEndpointPolicy> preflightPolicy = tenant.config().enabled()
                ? OidcRequestContext.resolveEndpointPolicy(providerRequest, tenant.config())
                : Optional.empty();
        if (tenant.config().enabled() && preflightPolicy.isEmpty()) {
            // No inbound OIDC policy applies: don't load metadata or keys just to abstain.
            return AuthenticationResponse.abstain();
        }
        OidcRequestContext context = new OidcRequestContext(providerRequest,
                                                              tenantRuntimeRegistry.tenantContext(tenant.tenantId()),
                                                              preflightPolicy);
        if (context.tenantContext().filter(it -> !it.ready()).isPresent()) {
            return OidcResponseFactory.tenantUnavailable();
        }

        if (context.bearerTokenInvalidRequest()) {
            if (LOGGER.isLoggable(System.Logger.Level.DEBUG)) {
                LOGGER.log(System.Logger.Level.DEBUG,
                           "OIDC Bearer token request rejected: reason="
                                   + OidcDiagnostics.sanitizeLogValue(context.bearerTokenErrorDescription()));
            }
            return OidcResponseFactory.invalidBearerTokenRequest(context.bearerChallengeRealm());
        }
        if (context.bearerTokenPresent()) {
            return authenticateBearerToken(context);
        }
        if (context.redirectionEndpointRequest(redirectionEndpointUris)) {
            return AuthenticationResponse.abstain();
        }

        Optional<OidcEndpointPolicy> endpointPolicy = context.endpointPolicy();
        if (endpointPolicy.isEmpty()) {
            return AuthenticationResponse.abstain();
        }
        OidcEndpointPolicy policy = endpointPolicy.orElseThrow();
        if (policy.authenticationCookieAccepted()) {
            return authenticateAuthenticationCookie(context, policy);
        }
        return authenticationFailure(context, policy, List.of());
    }

    AuthenticationResponse refresh(ProviderRequest providerRequest) {
        Optional<OidcTenantRuntimeRegistry.TenantSelection> selection = tenantRuntimeRegistry.select(providerRequest);
        if (selection.isEmpty()) {
            return OidcResponseFactory.missingAuthenticationCredential(List.of());
        }
        OidcTenantRuntimeRegistry.TenantSelection tenant = selection.orElseThrow();
        Optional<OidcEndpointPolicy> policy = tenant.config().enabled()
                ? OidcRequestContext.resolveEndpointPolicy(providerRequest, tenant.config())
                : Optional.empty();
        if (policy.filter(OidcEndpointPolicy::authenticationCookieAccepted).isEmpty()) {
            return OidcResponseFactory.missingAuthenticationCredential(List.of());
        }
        OidcRequestContext context = new OidcRequestContext(providerRequest,
                                                              tenantRuntimeRegistry.tenantContext(tenant.tenantId()),
                                                              policy);
        if (context.tenantContext().filter(it -> !it.ready()).isPresent()) {
            return OidcResponseFactory.tenantUnavailable();
        }
        // On-demand refresh is strictly for the authenticated browser session, even on endpoints that also accept
        // API Bearer tokens. Never allow a bearer credential to select or substitute for the cookie's identity.
        if (context.bearerTokenPresent() || context.bearerTokenInvalidRequest()) {
            return OidcResponseFactory.missingAuthenticationCredential(List.of());
        }
        LocalAuthenticationOutcome outcome = authenticateLocalCookie(context, true);
        return outcome.response()
                .orElseGet(() -> OidcResponseFactory.missingAuthenticationCredential(outcome.removalCookie()));
    }

    private static List<String> removalCookies(OidcCookieStateHandler handler) {
        return handler.removeLocalAuthenticationResultCookies().stream().map(Object::toString).toList();
    }

    private static void debugBearerTokenValidationFailure(OidcTenantContext tenantContext,
                                                          OidcValidationResult<?> validationResult) {
        if (!LOGGER.isLoggable(System.Logger.Level.DEBUG)) {
            return;
        }
        String method = tenantContext.tokenValidation()
                .method()
                .map(Enum::name)
                .orElse("none");
        String description = validationResult.errorDescription()
                .map(OidcDiagnostics::sanitizeLogValue)
                .orElse("Bearer Token validation failed");
        String cause = validationResult.cause()
                .map(OidcDiagnostics::safeExceptionType)
                .orElse("<none>");
        LOGGER.log(System.Logger.Level.DEBUG,
                   "OIDC Bearer token rejected: tenant="
                           + OidcDiagnostics.sanitizeLogValue(tenantContext.tenantId())
                           + ", method=" + method
                           + ", reason=" + description
                           + ", cause=" + cause);
    }

    private static Map<OidcTokenValidationMethod, OidcAccessTokenValidator> accessTokenValidators() {
        return Map.of(OidcTokenValidationMethod.JWT, new OidcJwtAccessTokenValidator(),
                      OidcTokenValidationMethod.INTROSPECTION, new OidcIntrospectionAccessTokenValidator());
    }

    private AuthenticationResponse authenticateAuthenticationCookie(OidcRequestContext context,
                                                                   OidcEndpointPolicy policy) {
        LocalAuthenticationOutcome outcome = authenticateLocalCookie(context, false);
        if (outcome.response().isPresent()) {
            return outcome.response().orElseThrow();
        }
        return authenticationFailure(context, policy, outcome.removalCookie());
    }

    private AuthenticationResponse authenticationFailure(OidcRequestContext context,
                                                        OidcEndpointPolicy policy,
                                                        List<String> localAuthenticationRemovalCookie) {
        return switch (policy.authenticationFailureResponse()) {
        case UNAUTHORIZED -> unauthorizedFailure(context, policy, localAuthenticationRemovalCookie);
        case AUTHORIZATION_CODE_REDIRECT -> authorizationCodeFlow(context, localAuthenticationRemovalCookie);
        };
    }

    private AuthenticationResponse authorizationCodeFlow(OidcRequestContext context,
                                                          List<String> localAuthenticationRemovalCookie) {
        try {
            String tenantId = context.tenantContext().orElseThrow().tenantId();
            return OidcResponseFactory.authorizationCodeFlowInitiated(
                    authenticationRequestFactory.create(context,
                                                        localAuthenticationRemovalCookie,
                                                        tenantRuntimeRegistry.logoutStore(tenantId)));
        } catch (OidcCookieStateHandler.AuthenticationRequestCookieException _) {
            return OidcResponseFactory.authorizationCodeFlowTooLarge(localAuthenticationRemovalCookie);
        } catch (RuntimeException e) {
            if (LOGGER.isLoggable(System.Logger.Level.DEBUG)) {
                String tenantId = context.tenantContext()
                        .map(OidcTenantContext::tenantId)
                        .map(OidcDiagnostics::sanitizeLogValue)
                        .orElse("<none>");
                LOGGER.log(System.Logger.Level.DEBUG,
                           "OIDC authorization request failed: tenant=" + tenantId
                                   + ", reason=request-construction-failed"
                                   + ", cause=" + OidcDiagnostics.safeExceptionType(e));
            }
            return OidcResponseFactory.authorizationCodeFlowUnavailable(localAuthenticationRemovalCookie);
        }
    }

    private AuthenticationResponse unauthorizedFailure(OidcRequestContext context,
                                                      OidcEndpointPolicy policy,
                                                      List<String> localAuthenticationRemovalCookie) {
        String description = policy.bearerTokenAuthenticationEnabled()
                ? "Bearer Token is required"
                : "Authentication is required";
        if (config.optional()) {
            return OidcResponseFactory.optional(description, localAuthenticationRemovalCookie);
        }
        if (policy.bearerTokenAuthenticationEnabled()) {
            return OidcResponseFactory.missingBearerToken(context.bearerChallengeRealm(),
                                                         localAuthenticationRemovalCookie);
        }
        return OidcResponseFactory.missingAuthenticationCredential(localAuthenticationRemovalCookie);
    }

    private LocalAuthenticationOutcome authenticateLocalCookie(OidcRequestContext context, boolean requestedRefresh) {
        Optional<OidcTenantContext> tenantContext = context.tenantContext()
                .filter(OidcTenantContext::ready);
        if (tenantContext.isEmpty()) {
            return LocalAuthenticationOutcome.empty();
        }

        OidcTenantContext readyTenant = tenantContext.orElseThrow();
        OidcCookieStateHandler cookieStateHandler = readyTenant.cookieStateHandler();
        Optional<OidcLocalAuthenticationResult> localAuthenticationResult = readLocalAuthenticationResult(context,
                                                                                                          readyTenant);
        if (localAuthenticationResult.isEmpty()) {
            return cookieStateHandler.localAuthenticationCookiesPresent(context.cookies())
                    ? LocalAuthenticationOutcome.empty(removalCookies(cookieStateHandler))
                    : LocalAuthenticationOutcome.empty();
        }
        OidcLocalAuthenticationResult currentAuthenticationResult = localAuthenticationResult.orElseThrow();
        Instant now = context.environment().time().toInstant();
        if (requestedRefresh && !now.isBefore(currentAuthenticationResult.expiresAt())) {
            return LocalAuthenticationOutcome.empty(removalCookies(cookieStateHandler));
        }
        if (!browserSessionGenerationMatches(context, cookieStateHandler, currentAuthenticationResult)) {
            if (LOGGER.isLoggable(System.Logger.Level.DEBUG)) {
                LOGGER.log(System.Logger.Level.DEBUG,
                           "OIDC local authentication result rejected: tenant="
                                   + OidcDiagnostics.sanitizeLogValue(readyTenant.tenantId())
                                   + ", reason=browser-session-generation-mismatch");
            }
            return LocalAuthenticationOutcome.empty(removalCookies(cookieStateHandler));
        }
        Optional<OidcBackChannelLogoutStore> logoutStore = tenantRuntimeRegistry.logoutStore(readyTenant.tenantId());
        if (logoutStore.isPresent()) {
            try {
                if (OidcBackChannelSessionSupport.revoked(currentAuthenticationResult, logoutStore.orElseThrow())) {
                    return LocalAuthenticationOutcome.empty(removalCookies(cookieStateHandler));
                }
            } catch (OidcBackChannelSessionSupport.StoreUnavailableException _) {
                return LocalAuthenticationOutcome.response(OidcResponseFactory.authorizationCodeFlowUnavailable(List.of()));
            }
        }
        if (requestedRefresh && currentAuthenticationResult.refreshToken().isEmpty()) {
            if (currentAuthenticationResult.accessTokenExpiresAt()
                    .filter(expiry -> !now.isBefore(expiry)).isPresent()) {
                return LocalAuthenticationOutcome.empty(removalCookies(cookieStateHandler));
            }
            return LocalAuthenticationOutcome.response(OidcResponseFactory.refreshTokenUnavailable());
        }
        OidcRefreshTokenManager.RefreshResult refreshResult = refreshTokenManager.refreshIfNeeded(
                currentAuthenticationResult,
                readyTenant,
                now,
                context.cookies(),
                requestedRefresh,
                logoutStore);
        List<String> removalCookie = refreshResult.removeCookie() ? removalCookies(cookieStateHandler) : List.of();
        if (refreshResult.unavailable()) {
            return LocalAuthenticationOutcome.response(
                    requestedRefresh ? OidcResponseFactory.refreshUnavailable(removalCookie)
                            : OidcResponseFactory.authorizationCodeFlowUnavailable(removalCookie));
        }
        if (requestedRefresh && !refreshResult.refreshed() && refreshResult.authenticationResult().isPresent()) {
            // Ordinary authentication may keep an unexpired source token through a transient OP failure. An explicit
            // refresh request must not report success unless it actually obtained and validated replacement tokens.
            return LocalAuthenticationOutcome.response(OidcResponseFactory.refreshUnavailable(List.of()));
        }
        Optional<OidcLocalAuthenticationResult> refreshedAuthenticationResult = refreshResult.authenticationResult();
        if (refreshedAuthenticationResult.isEmpty()) {
            return LocalAuthenticationOutcome.empty(removalCookie);
        }
        OidcLocalAuthenticationResult result = refreshedAuthenticationResult.orElseThrow();
        if (logoutStore.isPresent()) {
            try {
                if (OidcBackChannelSessionSupport.revoked(result, logoutStore.orElseThrow())) {
                    return LocalAuthenticationOutcome.empty(removalCookies(cookieStateHandler));
                }
            } catch (OidcBackChannelSessionSupport.StoreUnavailableException _) {
                return LocalAuthenticationOutcome.response(OidcResponseFactory.authorizationCodeFlowUnavailable(
                        refreshResult.refreshed() ? removalCookies(cookieStateHandler) : List.of()));
            }
        }
        if (OidcSubjectMapper.localPrincipalId(result.idToken().jwt()).isEmpty()) {
            if (LOGGER.isLoggable(System.Logger.Level.DEBUG)) {
                LOGGER.log(System.Logger.Level.DEBUG,
                           "OIDC local authentication result rejected: tenant="
                                   + OidcDiagnostics.sanitizeLogValue(readyTenant.tenantId())
                                   + ", reason=no-principal-claim");
            }
            return LocalAuthenticationOutcome.empty(removalCookies(cookieStateHandler));
        }
        try {
            result.scope()
                    .ifPresent(scope -> OidcScopeSupport.parseScopeString(scope, "local authentication scope"));
        } catch (IllegalArgumentException e) {
            if (LOGGER.isLoggable(System.Logger.Level.DEBUG)) {
                LOGGER.log(System.Logger.Level.DEBUG,
                           "OIDC local authentication result rejected: tenant="
                                   + OidcDiagnostics.sanitizeLogValue(readyTenant.tenantId())
                                   + ", reason=invalid-scope"
                                   + ", cause=" + OidcDiagnostics.safeExceptionType(e));
            }
            return LocalAuthenticationOutcome.empty(removalCookies(cookieStateHandler));
        }
        List<String> authenticationCookie;
        try {
            authenticationCookie = refreshResult.refreshed()
                    ? cookieStateHandler.localAuthenticationResultCookies(refreshResult.preparedSession().orElseThrow(),
                                                                           context.environment().time().toInstant())
                            .stream().map(Object::toString).toList()
                    : List.of();
            cookieStateHandler.validateCookieUpdate(authenticationCookie.stream().map(SetCookie::parse).toList(),
                                                   context.cookies());
        } catch (OidcCookieStateHandler.SessionCookieException _) {
            return LocalAuthenticationOutcome.response(
                    OidcResponseFactory.authorizationCodeFlowUnavailable(removalCookies(cookieStateHandler)));
        }
        try {
            return LocalAuthenticationOutcome.response(OidcResponseFactory.localAuthenticationSucceeded(
                    OidcSubjectMapper.map(result, readyTenant),
                    authenticationCookie));
        } catch (RuntimeException e) {
            // A tenant adapter can reject or fail to map an otherwise valid identity. Remove the session cookies
            // and reject authentication when the mapping hook fails.
            if (LOGGER.isLoggable(System.Logger.Level.DEBUG)) {
                LOGGER.log(System.Logger.Level.DEBUG,
                           "OIDC subject mapping failed: tenant="
                                   + OidcDiagnostics.sanitizeLogValue(readyTenant.tenantId())
                                   + ", cause=" + OidcDiagnostics.safeExceptionType(e));
            }
            return LocalAuthenticationOutcome.response(
                    OidcResponseFactory.authorizationCodeFlowUnavailable(removalCookies(cookieStateHandler)));
        }
    }

    private Optional<OidcLocalAuthenticationResult> readLocalAuthenticationResult(OidcRequestContext context,
                                                                                 OidcTenantContext readyTenant) {
        return readyTenant.cookieStateHandler()
                .readLocalAuthenticationResult(context.cookies(),
                                               context.environment().time().toInstant(),
                                               readyTenant.idTokenDecryptor())
                .filter(result -> readyTenant.tenantId().equals(result.tenantId()));
    }

    private boolean browserSessionGenerationMatches(OidcRequestContext context,
                                                    OidcCookieStateHandler cookieStateHandler,
                                                    OidcLocalAuthenticationResult authenticationResult) {
        List<String> generationCookies = context.cookieValues(cookieStateHandler.browserSessionGenerationCookieName());
        Optional<String> expectedGeneration = authenticationResult.browserSessionGeneration();
        if (generationCookies.isEmpty()) {
            return expectedGeneration.isEmpty();
        }
        if (generationCookies.size() != 1 || expectedGeneration.isEmpty()) {
            return false;
        }
        return cookieStateHandler.readBrowserSessionGeneration(generationCookies.getFirst())
                .filter(expectedGeneration.orElseThrow()::equals)
                .isPresent();
    }

    private AuthenticationResponse authenticateBearerToken(OidcRequestContext context) {
        Optional<String> bearerToken = context.bearerToken();
        if (bearerToken.isEmpty()) {
            if (config.optional()) {
                return OidcResponseFactory.optional("Bearer Token is required", List.of());
            }
            return OidcResponseFactory.missingBearerToken(context.bearerChallengeRealm());
        }

        OidcTenantContext tenantContext = context.tenantContext().orElseThrow();
        Optional<OidcAccessTokenValidator> validator = tenantContext.tokenValidation()
                .method()
                .map(accessTokenValidators::get);
        if (validator.isEmpty()) {
            if (LOGGER.isLoggable(System.Logger.Level.DEBUG)) {
                LOGGER.log(System.Logger.Level.DEBUG,
                           "OIDC Bearer token rejected: tenant="
                                   + OidcDiagnostics.sanitizeLogValue(tenantContext.tenantId())
                                   + ", reason=token-validation-not-configured");
            }
            return OidcResponseFactory.bearerTokenValidationNotConfigured(tenantContext.bearerChallengeRealm());
        }
        return authenticateBearerToken(OidcAccessTokenValidationRequest.protectedResource(bearerToken.orElseThrow(),
                                                                                          context),
                                       validator.orElseThrow());
    }

    private AuthenticationResponse authenticateBearerToken(OidcAccessTokenValidationRequest request,
                                                          OidcAccessTokenValidator validator) {
        OidcTenantContext tenantContext = request.tenantContext();
        OidcValidationResult<OidcValidatedAccessToken> validationResult = validator.validate(request);
        if (validationResult.succeeded()) {
            try {
                return AuthenticationResponse.success(
                        OidcSubjectMapper.map(validationResult.validatedToken().orElseThrow(),
                                              tenantContext));
            } catch (RuntimeException e) {
                if (LOGGER.isLoggable(System.Logger.Level.DEBUG)) {
                    LOGGER.log(System.Logger.Level.DEBUG,
                               "OIDC subject mapping failed: tenant="
                                       + OidcDiagnostics.sanitizeLogValue(tenantContext.tenantId())
                                       + ", cause=" + OidcDiagnostics.safeExceptionType(e));
                }
                return OidcResponseFactory.invalidBearerToken(tenantContext.bearerChallengeRealm());
            }
        }
        debugBearerTokenValidationFailure(tenantContext, validationResult);
        if (validationResult.unavailable()) {
            return OidcResponseFactory.bearerTokenValidationUnavailable();
        }
        return OidcResponseFactory.invalidBearerToken(tenantContext.bearerChallengeRealm());
    }

    private record LocalAuthenticationOutcome(Optional<AuthenticationResponse> response, List<String> removalCookie) {
        private static LocalAuthenticationOutcome response(AuthenticationResponse response) {
            return new LocalAuthenticationOutcome(Optional.of(response), List.of());
        }

        private static LocalAuthenticationOutcome empty() {
            return empty(List.of());
        }

        private static LocalAuthenticationOutcome empty(List<String> removalCookie) {
            return new LocalAuthenticationOutcome(Optional.empty(), removalCookie);
        }
    }
}
