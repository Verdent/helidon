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
                                                  OidcAuthenticationRequestFactory.create(),
                                                  OidcRefreshTokenManager.create(accessTokenValidators),
                                                  accessTokenValidators);
    }

    AuthenticationResponse authenticate(io.helidon.security.ProviderRequest providerRequest) {
        if (providerRequest == null) {
            return AuthenticationResponse.abstain();
        }

        OidcRequestContext context = OidcRequestContext.create(providerRequest, tenantRuntimeRegistry);
        if (context.tenantContext().filter(it -> !it.ready()).isPresent()) {
            return OidcResponseFactory.tenantUnavailable(context.tenantContext().orElseThrow());
        }

        if (context.bearerTokenInvalidRequest()) {
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
        LocalAuthentication localAuthentication = authenticateLocalAuthenticationResult(context);
        if (localAuthentication.response().isPresent()) {
            return localAuthentication.response().orElseThrow();
        }
        return authenticationFailure(context, policy, localAuthentication.removalCookie());
    }

    private AuthenticationResponse authenticationFailure(OidcRequestContext context,
                                                        OidcEndpointPolicy policy,
                                                        Optional<String> localAuthenticationRemovalCookie) {
        return switch (policy.authenticationFailureResponse()) {
        case UNAUTHORIZED -> unauthorizedFailure(context, policy, localAuthenticationRemovalCookie);
        case AUTHORIZATION_CODE_REDIRECT -> OidcResponseFactory.authorizationCodeFlowInitiated(
                authenticationRequestFactory.create(context),
                localAuthenticationRemovalCookie);
        };
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

    private LocalAuthentication authenticateLocalAuthenticationResult(OidcRequestContext context) {
        Optional<OidcTenantContext> tenantContext = context.tenantContext()
                .filter(OidcTenantContext::ready);
        if (tenantContext.isEmpty()) {
            return LocalAuthentication.empty();
        }

        OidcTenantContext readyTenant = tenantContext.orElseThrow();
        OidcCookieStateHandler cookieStateHandler = readyTenant.cookieStateHandler();
        Optional<OidcLocalAuthenticationResult> localAuthenticationResult = localAuthenticationResult(context,
                                                                                                      readyTenant);
        if (localAuthenticationResult.isEmpty()) {
            return LocalAuthentication.empty();
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
            return LocalAuthentication.empty(removalCookie);
        }
        OidcLocalAuthenticationResult result = refreshedAuthenticationResult.orElseThrow();
        if (OidcSubjectMapper.localPrincipalId(result.idToken().jwt(), readyTenant.subjectMapping()).isEmpty()) {
            LOGGER.log(System.Logger.Level.DEBUG, "Local authentication result has no principal claim");
            return LocalAuthentication.empty(Optional.of(cookieStateHandler.removeLocalAuthenticationResultCookie()
                                                                 .toString()));
        }
        try {
            result.scope()
                    .ifPresent(scope -> OidcScopeSupport.parseScopeString(scope, "local authentication scope"));
        } catch (IllegalArgumentException e) {
            LOGGER.log(System.Logger.Level.DEBUG, "Local authentication result has invalid scope", e);
            return LocalAuthentication.empty(Optional.of(cookieStateHandler.removeLocalAuthenticationResultCookie()
                                                                 .toString()));
        }
        Optional<String> authenticationCookie = refreshResult.refreshed()
                ? Optional.of(cookieStateHandler.createLocalAuthenticationResultCookie(result).toString())
                : Optional.empty();
        return LocalAuthentication.response(OidcResponseFactory.localAuthenticationSucceeded(
                OidcSubjectMapper.map(result, readyTenant.subjectMapping()),
                authenticationCookie));
    }

    private Optional<OidcLocalAuthenticationResult> localAuthenticationResult(OidcRequestContext context,
                                                                             OidcTenantContext readyTenant) {
        String cookieName = readyTenant.cookieStateHandler()
                .cookieConfig()
                .localAuthenticationCookieName();
        List<String> cookieValues = context.cookieValues(cookieName);
        if (cookieValues.size() != 1) {
            return Optional.empty();
        }
        return readyTenant.cookieStateHandler()
                .readLocalAuthenticationResult(cookieValues.get(0), context.environment().time().toInstant())
                .filter(result -> readyTenant.tenantId().equals(result.tenantId()));
    }

    private record LocalAuthentication(Optional<AuthenticationResponse> response, Optional<String> removalCookie) {
        private static LocalAuthentication response(AuthenticationResponse response) {
            return new LocalAuthentication(Optional.of(response), Optional.empty());
        }

        private static LocalAuthentication empty() {
            return empty(Optional.empty());
        }

        private static LocalAuthentication empty(Optional<String> removalCookie) {
            return new LocalAuthentication(Optional.empty(), removalCookie);
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
        validationResult.cause()
                .ifPresent(cause -> LOGGER.log(System.Logger.Level.DEBUG,
                                                validationResult.errorDescription()
                                                        .orElse("Bearer Token validation failed"),
                                                cause));
        String errorDescription = validationResult.errorDescription().orElse("Bearer Token is invalid");
        return OidcResponseFactory.invalidBearerToken(errorDescription, tenantContext.bearerChallengeRealm());
    }

    private static Map<OidcTokenValidationMethod, OidcAccessTokenValidator> accessTokenValidators() {
        return Map.of(OidcTokenValidationMethod.JWT, OidcJwtAccessTokenValidator.create(),
                      OidcTokenValidationMethod.INTROSPECTION, OidcIntrospectionAccessTokenValidator.create());
    }
}
