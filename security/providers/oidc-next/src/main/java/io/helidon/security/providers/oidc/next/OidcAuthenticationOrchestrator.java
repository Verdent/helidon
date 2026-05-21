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
    private final OidcRequestClassifier classifier;
    private final OidcResponseFactory responseFactory;
    private final OidcAuthenticationRequestFactory authenticationRequestFactory;
    private final Map<OidcTokenValidationMethod, OidcAccessTokenValidator> accessTokenValidators;

    private OidcAuthenticationOrchestrator(OidcProviderConfig config,
                                           OidcTenantRuntimeRegistry tenantRuntimeRegistry,
                                           OidcRequestClassifier classifier,
                                           OidcResponseFactory responseFactory,
                                           OidcAuthenticationRequestFactory authenticationRequestFactory,
                                           Map<OidcTokenValidationMethod, OidcAccessTokenValidator>
                                                   accessTokenValidators) {
        this.config = config;
        this.tenantRuntimeRegistry = tenantRuntimeRegistry;
        this.classifier = classifier;
        this.responseFactory = responseFactory;
        this.authenticationRequestFactory = authenticationRequestFactory;
        this.accessTokenValidators = accessTokenValidators;
    }

    static OidcAuthenticationOrchestrator create(OidcProviderConfig config,
                                                 OidcTenantRuntimeRegistry tenantRuntimeRegistry) {
        return new OidcAuthenticationOrchestrator(config,
                                                  tenantRuntimeRegistry,
                                                  OidcRequestClassifier.create(),
                                                  OidcResponseFactory.create(),
                                                  OidcAuthenticationRequestFactory.create(),
                                                  accessTokenValidators());
    }

    AuthenticationResponse authenticate(io.helidon.security.ProviderRequest providerRequest) {
        if (providerRequest == null) {
            return AuthenticationResponse.abstain();
        }

        OidcRequestContext context = OidcRequestContext.create(providerRequest, tenantRuntimeRegistry);
        if (context.tenantContext().filter(it -> !it.ready()).isPresent()) {
            return responseFactory.tenantUnavailable(context.tenantContext().orElseThrow());
        }

        OidcProtocolOperation operation = classifier.classify(context);

        return switch (operation) {
            case BEARER_TOKEN_INVALID_REQUEST -> responseFactory.invalidBearerTokenRequest(
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
        return responseFactory.authorizationCodeFlowInitiated(authenticationRequestFactory.create(context));
    }

    private AuthenticationResponse authenticateAmbiguous(OidcRequestContext context) {
        return authenticateLocalAuthenticationResult(context)
                .orElseGet(responseFactory::ambiguousRequest);
    }

    private Optional<AuthenticationResponse> authenticateLocalAuthenticationResult(OidcRequestContext context) {
        Optional<OidcLocalAuthenticationResult> localAuthenticationResult = localAuthenticationResult(context);
        if (localAuthenticationResult.isEmpty()) {
            return Optional.empty();
        }
        OidcTenantContext tenantContext = context.tenantContext().orElseThrow();
        return Optional.of(AuthenticationResponse.success(tenantContext.subjectMapper()
                                                                  .map(localAuthenticationResult.orElseThrow())));
    }

    private Optional<OidcLocalAuthenticationResult> localAuthenticationResult(OidcRequestContext context) {
        Optional<OidcTenantContext> tenantContext = context.tenantContext()
                .filter(OidcTenantContext::ready);
        if (tenantContext.isEmpty()) {
            return Optional.empty();
        }
        OidcTenantContext readyTenant = tenantContext.orElseThrow();
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
        Optional<OidcBearerTokenEvidence> evidence = context.bearerTokenEvidence();
        if (evidence.isEmpty()) {
            if (config.optional()) {
                return responseFactory.optional("Bearer Token is required");
            }
            return responseFactory.missingBearerToken();
        }

        OidcBearerTokenEvidence bearerTokenEvidence = evidence.orElseThrow();
        OidcTenantContext tenantContext = context.tenantContext().orElseThrow();
        OidcAccessTokenValidator validator = tenantContext.tokenValidationPolicy()
                .method()
                .map(accessTokenValidators::get)
                .orElse(null);
        if (validator == null) {
            return responseFactory.bearerTokenValidationNotImplemented();
        }
        return authenticateBearerToken(bearerTokenEvidence, tenantContext, validator);
    }

    private AuthenticationResponse authenticateBearerToken(OidcBearerTokenEvidence evidence,
                                                          OidcTenantContext tenantContext,
                                                          OidcAccessTokenValidator validator) {
        OidcTokenValidationResult validationResult = validator.validate(evidence.token(), tenantContext);
        if (validationResult.succeeded()) {
            return AuthenticationResponse.success(tenantContext.subjectMapper()
                                                          .map(validationResult.validatedToken().orElseThrow()));
        }
        validationResult.cause()
                .ifPresent(cause -> LOGGER.log(System.Logger.Level.DEBUG,
                                                validationResult.errorDescription()
                                                        .orElse("Bearer Token validation failed"),
                                                cause));
        String errorDescription = validationResult.errorDescription().orElse("Bearer Token is invalid");
        return responseFactory.invalidBearerToken(errorDescription);
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
