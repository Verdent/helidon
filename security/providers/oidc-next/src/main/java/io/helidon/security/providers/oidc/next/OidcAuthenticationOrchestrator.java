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
import java.util.Optional;

import io.helidon.security.AuthenticationResponse;

final class OidcAuthenticationOrchestrator {
    private static final System.Logger LOGGER = System.getLogger(OidcAuthenticationOrchestrator.class.getName());

    private final OidcProviderConfig config;
    private final OidcTenantRuntimeRegistry tenantRuntimeRegistry;
    private final OidcAuthenticationRequestFactory authenticationRequestFactory;
    private final OidcRefreshTokenManager refreshTokenManager;
    private final Map<OidcTokenValidationMethod, OidcAccessTokenValidator> accessTokenValidators;

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
    }

    static OidcAuthenticationOrchestrator create(OidcProviderConfig config,
                                                 OidcTenantRuntimeRegistry tenantRuntimeRegistry) {
        Map<OidcTokenValidationMethod, OidcAccessTokenValidator> accessTokenValidators = accessTokenValidators();
        return new OidcAuthenticationOrchestrator(config,
                                                  tenantRuntimeRegistry,
                                                  new OidcAuthenticationRequestFactory(),
                                                  new OidcRefreshTokenManager(accessTokenValidators),
                                                  accessTokenValidators);
    }

    AuthenticationResponse authenticate(io.helidon.security.ProviderRequest providerRequest) {
        if (providerRequest == null) {
            return AuthenticationResponse.abstain();
        }

        OidcRequestContext context = new OidcRequestContext(providerRequest, tenantRuntimeRegistry);
        if (context.tenantContext().filter(it -> !it.ready()).isPresent()) {
            return OidcResponseFactory.tenantUnavailable(context.tenantContext().orElseThrow());
        }

        if (context.bearerTokenInvalidRequest()) {
            if (LOGGER.isLoggable(System.Logger.Level.DEBUG)) {
                LOGGER.log(System.Logger.Level.DEBUG,
                           "OIDC Bearer token request rejected: reason="
                                   + OidcDiagnostics.sanitizeLogValue(context.bearerTokenErrorDescription()));
            }
            return OidcResponseFactory.invalidBearerTokenRequest(context.bearerTokenErrorDescription(),
                                                                 context.bearerChallengeRealm());
        }
        if (context.bearerTokenPresent()) {
            return authenticateBearerToken(context);
        }
        if (context.authorizationResponsePresent()) {
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
        return authenticationFailure(context, policy, Optional.empty());
    }

    private AuthenticationResponse authenticateAuthenticationCookie(OidcRequestContext context,
                                                                   OidcEndpointPolicy policy) {
        LocalAuthenticationOutcome outcome = authenticateLocalCookie(context);
        if (outcome.response().isPresent()) {
            return outcome.response().orElseThrow();
        }
        return authenticationFailure(context, policy, outcome.removalCookie());
    }

    private AuthenticationResponse authenticationFailure(OidcRequestContext context,
                                                        OidcEndpointPolicy policy,
                                                        Optional<String> localAuthenticationRemovalCookie) {
        return switch (policy.authenticationFailureResponse()) {
        case UNAUTHORIZED -> unauthorizedFailure(context, policy, localAuthenticationRemovalCookie);
        case AUTHORIZATION_CODE_REDIRECT -> authorizationCodeFlow(context, localAuthenticationRemovalCookie);
        };
    }

    private AuthenticationResponse authorizationCodeFlow(OidcRequestContext context,
                                                          Optional<String> localAuthenticationRemovalCookie) {
        try {
            return OidcResponseFactory.authorizationCodeFlowInitiated(authenticationRequestFactory.create(context),
                                                                      localAuthenticationRemovalCookie);
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
                                                      Optional<String> localAuthenticationRemovalCookie) {
        String description = policy.bearerTokenAuthenticationEnabled()
                ? "Bearer Token is required"
                : "Authentication is required";
        if (config.optional()) {
            return OidcResponseFactory.optional(description);
        }
        if (policy.bearerTokenAuthenticationEnabled()) {
            return OidcResponseFactory.missingBearerToken(context.bearerChallengeRealm(),
                                                         localAuthenticationRemovalCookie);
        }
        return OidcResponseFactory.missingAuthenticationCredential(localAuthenticationRemovalCookie);
    }

    private LocalAuthenticationOutcome authenticateLocalCookie(OidcRequestContext context) {
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
            return LocalAuthenticationOutcome.empty();
        }
        OidcRefreshTokenManager.RefreshResult refreshResult = refreshTokenManager.refreshIfNeeded(
                localAuthenticationResult.orElseThrow(),
                readyTenant,
                context.environment().time().toInstant());
        Optional<String> removalCookie = refreshResult.removeCookie()
                ? Optional.of(cookieStateHandler.removeLocalAuthenticationResultCookie().toString())
                : Optional.empty();
        Optional<OidcLocalAuthenticationResult> refreshedAuthenticationResult = refreshResult.authenticationResult();
        if (refreshedAuthenticationResult.isEmpty()) {
            return LocalAuthenticationOutcome.empty(removalCookie);
        }
        OidcLocalAuthenticationResult result = refreshedAuthenticationResult.orElseThrow();
        if (OidcSubjectMapper.localPrincipalId(result.idToken().jwt(), readyTenant.subjectMapping()).isEmpty()) {
            if (LOGGER.isLoggable(System.Logger.Level.DEBUG)) {
                LOGGER.log(System.Logger.Level.DEBUG,
                           "OIDC local authentication result rejected: tenant="
                                   + OidcDiagnostics.sanitizeLogValue(readyTenant.tenantId())
                                   + ", reason=no-principal-claim");
            }
            return LocalAuthenticationOutcome.empty(Optional.of(cookieStateHandler.removeLocalAuthenticationResultCookie()
                                                                        .toString()));
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
            return LocalAuthenticationOutcome.empty(Optional.of(cookieStateHandler.removeLocalAuthenticationResultCookie()
                                                                        .toString()));
        }
        Optional<String> authenticationCookie = refreshResult.refreshed()
                ? Optional.of(cookieStateHandler.createLocalAuthenticationResultCookie(result).toString())
                : Optional.empty();
        return LocalAuthenticationOutcome.response(OidcResponseFactory.localAuthenticationSucceeded(
                OidcSubjectMapper.map(result, readyTenant.subjectMapping()),
                authenticationCookie));
    }

    private Optional<OidcLocalAuthenticationResult> readLocalAuthenticationResult(OidcRequestContext context,
                                                                                 OidcTenantContext readyTenant) {
        String cookieName = readyTenant.cookieStateHandler()
                .cookieConfig()
                .localAuthenticationCookieName();
        List<String> cookieValues = context.cookieValues(cookieName);
        if (cookieValues.size() != 1) {
            return Optional.empty();
        }
        return readyTenant.cookieStateHandler()
                .readLocalAuthenticationResult(cookieValues.getFirst(), context.environment().time().toInstant())
                .filter(result -> readyTenant.tenantId().equals(result.tenantId()));
    }

    private record LocalAuthenticationOutcome(Optional<AuthenticationResponse> response, Optional<String> removalCookie) {
        private static LocalAuthenticationOutcome response(AuthenticationResponse response) {
            return new LocalAuthenticationOutcome(Optional.of(response), Optional.empty());
        }

        private static LocalAuthenticationOutcome empty() {
            return empty(Optional.empty());
        }

        private static LocalAuthenticationOutcome empty(Optional<String> removalCookie) {
            return new LocalAuthenticationOutcome(Optional.empty(), removalCookie);
        }
    }

    private AuthenticationResponse authenticateBearerToken(OidcRequestContext context) {
        Optional<String> bearerToken = context.bearerToken();
        if (bearerToken.isEmpty()) {
            if (config.optional()) {
                return OidcResponseFactory.optional("Bearer Token is required");
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
            return AuthenticationResponse.success(
                    OidcSubjectMapper.map(validationResult.validatedToken().orElseThrow(),
                                          tenantContext.subjectMapping()));
        }
        debugBearerTokenValidationFailure(tenantContext, validationResult);
        String errorDescription = validationResult.errorDescription().orElse("Bearer Token is invalid");
        return OidcResponseFactory.invalidBearerToken(errorDescription, tenantContext.bearerChallengeRealm());
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
}
