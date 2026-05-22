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

import java.util.EnumMap;
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
        return new OidcAuthenticationOrchestrator(config,
                                                  tenantRuntimeRegistry,
                                                  OidcAuthenticationRequestFactory.create(),
                                                  OidcRefreshTokenManager.create(),
                                                  accessTokenValidators());
    }

    AuthenticationResponse authenticate(io.helidon.security.ProviderRequest providerRequest) {
        if (providerRequest == null) {
            return AuthenticationResponse.abstain();
        }

        OidcRequestContext context = OidcRequestContext.create(providerRequest, tenantRuntimeRegistry);
        if (context.tenantContext().filter(it -> !it.ready()).isPresent()) {
            return OidcResponseFactory.tenantUnavailable(context.tenantContext().orElseThrow());
        }

        OidcProtocolOperation operation = OidcRequestClassifier.classify(context);

        return switch (operation) {
            case BEARER_TOKEN_INVALID_REQUEST -> OidcResponseFactory.invalidBearerTokenRequest(
                    context.bearerTokenErrorDescription());
            case BEARER_TOKEN_AUTHENTICATION -> authenticateBearerToken(context);
            case AUTHORIZATION_CODE_FLOW_INITIATION -> authenticateAuthorizationCodeFlow(context);
            case AUTHORIZATION_RESPONSE, RP_INITIATED_LOGOUT -> AuthenticationResponse.abstain();
            case TOKEN_PROPAGATION, CLIENT_CREDENTIALS_GRANT -> AuthenticationResponse.abstain();
            case AMBIGUOUS -> authenticateAmbiguous(context);
            case ABSTAIN -> AuthenticationResponse.abstain();
        };
    }

    private AuthenticationResponse authenticateAuthorizationCodeFlow(OidcRequestContext context) {
        Optional<AuthenticationResponse> localAuthenticationResult = authenticateLocalAuthenticationResult(context);
        if (localAuthenticationResult.isPresent()) {
            return localAuthenticationResult.orElseThrow();
        }
        return OidcResponseFactory.authorizationCodeFlowInitiated(authenticationRequestFactory.create(context));
    }

    private AuthenticationResponse authenticateAmbiguous(OidcRequestContext context) {
        return authenticateLocalAuthenticationResult(context)
                .orElseGet(OidcResponseFactory::ambiguousRequest);
    }

    private Optional<AuthenticationResponse> authenticateLocalAuthenticationResult(OidcRequestContext context) {
        Optional<OidcTenantContext> tenantContext = context.tenantContext()
                .filter(OidcTenantContext::ready);
        if (tenantContext.isEmpty()) {
            return Optional.empty();
        }

        OidcTenantContext readyTenant = tenantContext.orElseThrow();
        Optional<OidcLocalAuthenticationResult> localAuthenticationResult = localAuthenticationResult(context,
                                                                                                      readyTenant);
        if (localAuthenticationResult.isEmpty()) {
            return Optional.empty();
        }
        OidcRefreshTokenManager.RefreshResult refreshResult = refreshTokenManager.refreshIfNeeded(
                localAuthenticationResult.orElseThrow(),
                readyTenant,
                context.environment().time().toInstant());
        return refreshResult.authenticationResult()
                .map(result -> OidcResponseFactory.localAuthenticationSucceeded(OidcSubjectMapper.map(result),
                                                                                authenticationCookie(refreshResult,
                                                                                                     result,
                                                                                                     readyTenant)));
    }

    private Optional<String> authenticationCookie(OidcRefreshTokenManager.RefreshResult refreshResult,
                                                  OidcLocalAuthenticationResult authenticationResult,
                                                  OidcTenantContext tenantContext) {
        if (!refreshResult.refreshed()) {
            return Optional.empty();
        }
        return Optional.of(tenantContext.cookieStateHandler()
                                   .createLocalAuthenticationResultCookie(authenticationResult)
                                   .toString());
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

    private AuthenticationResponse authenticateBearerToken(OidcRequestContext context) {
        Optional<String> bearerToken = context.bearerToken();
        if (bearerToken.isEmpty()) {
            if (config.optional()) {
                return OidcResponseFactory.optional("Bearer Token is required");
            }
            return OidcResponseFactory.missingBearerToken();
        }

        OidcTenantContext tenantContext = context.tenantContext().orElseThrow();
        Optional<OidcAccessTokenValidator> validator = tenantContext.tokenValidation()
                .method()
                .map(accessTokenValidators::get);
        if (validator.isEmpty()) {
            return OidcResponseFactory.bearerTokenValidationNotImplemented();
        }
        return authenticateBearerToken(bearerToken.orElseThrow(), tenantContext, validator.orElseThrow());
    }

    private AuthenticationResponse authenticateBearerToken(String bearerToken,
                                                          OidcTenantContext tenantContext,
                                                          OidcAccessTokenValidator validator) {
        OidcTokenValidationResult validationResult = validator.validate(bearerToken, tenantContext);
        if (validationResult.succeeded()) {
            return AuthenticationResponse.success(
                    OidcSubjectMapper.map(validationResult.validatedToken().orElseThrow()));
        }
        validationResult.cause()
                .ifPresent(cause -> LOGGER.log(System.Logger.Level.DEBUG,
                                                validationResult.errorDescription()
                                                        .orElse("Bearer Token validation failed"),
                                                cause));
        String errorDescription = validationResult.errorDescription().orElse("Bearer Token is invalid");
        return OidcResponseFactory.invalidBearerToken(errorDescription);
    }

    private static Map<OidcTokenValidationMethod, OidcAccessTokenValidator> accessTokenValidators() {
        EnumMap<OidcTokenValidationMethod, OidcAccessTokenValidator> validators =
                new EnumMap<>(OidcTokenValidationMethod.class);
        addAccessTokenValidator(validators, OidcJwtAccessTokenValidator.create());
        addAccessTokenValidator(validators, OidcIntrospectionAccessTokenValidator.create());
        return Map.copyOf(validators);
    }

    private static void addAccessTokenValidator(Map<OidcTokenValidationMethod, OidcAccessTokenValidator> validators,
                                                OidcAccessTokenValidator validator) {
        if (validators.put(validator.method(), validator) != null) {
            throw new IllegalStateException("Duplicate access token validator for method: " + validator.method());
        }
    }
}
