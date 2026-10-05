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

import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.Collectors;

import io.helidon.config.Config;
import io.helidon.http.HeaderNames;
import io.helidon.http.Method;
import io.helidon.http.PathMatchers;
import io.helidon.http.Status;
import io.helidon.webserver.WebServer;
import io.helidon.webserver.http.HttpFeature;
import io.helidon.webserver.http.HttpRouting;
import io.helidon.webserver.http.ServerRequest;
import io.helidon.webserver.http.ServerResponse;
import io.helidon.webserver.spi.ServerFeature;

/**
 * OpenID Connect HTTP feature for Redirection Endpoint and logout routes.
 * <p>
 * The feature uses {@link OidcProviderConfig}'s Blueprint builder for the same tenant options as
 * {@link OidcProvider}, instead of exposing a second builder with duplicate configuration.
 * {@link #create(OidcProvider)} explicitly shares an existing provider's runtime.
 */
public final class OidcFeature implements HttpFeature, ServerFeature {
    private static final System.Logger LOGGER = System.getLogger(OidcFeature.class.getName());

    private final OidcProviderConfig config;
    private final OidcTenantRuntimeRegistry tenantRuntimeRegistry;
    private final boolean ownsRuntime;
    private final OidcAuthorizationResponseProcessor authorizationResponseProcessor;
    private final OidcLogoutHandler logoutHandler;
    private final OidcIdTokenValidator idTokenValidator;

    private OidcFeature(OidcProviderConfig config, OidcTenantRuntimeRegistry tenantRuntimeRegistry, boolean ownsRuntime) {
        OidcProviderConfig providerConfig = Objects.requireNonNull(config);
        OidcTenantRuntimeRegistry runtimeRegistry = Objects.requireNonNull(tenantRuntimeRegistry);
        this.config = providerConfig;
        this.tenantRuntimeRegistry = runtimeRegistry;
        this.ownsRuntime = ownsRuntime;
        this.authorizationResponseProcessor = new OidcAuthorizationResponseProcessor(providerConfig, runtimeRegistry);
        this.logoutHandler = new OidcLogoutHandler(providerConfig, runtimeRegistry);
        this.idTokenValidator = new OidcIdTokenValidator();
    }

    /**
     * Create an independent OIDC HTTP feature from configuration.
     * Use {@link #create(OidcProvider)} to share the tenant runtime with a security provider.
     * This feature owns its runtime and releases it when its last active routing registration stops.
     * A disposed feature cannot be started again; create a new feature for a new lifetime.
     *
     * @param config configuration
     * @return OIDC HTTP feature
     */
    public static OidcFeature create(Config config) {
        Objects.requireNonNull(config, "config");
        return create(OidcProviderConfig.create(config));
    }

    /**
     * Create an independent OIDC HTTP feature from provider configuration.
     * Use {@link #create(OidcProvider)} to share the tenant runtime with a security provider.
     * This feature owns its runtime and releases it when its last active routing registration stops.
     * A disposed feature cannot be started again; create a new feature for a new lifetime.
     *
     * @param config provider configuration
     * @return OIDC HTTP feature
     */
    public static OidcFeature create(OidcProviderConfig config) {
        Objects.requireNonNull(config, "config");
        return new OidcFeature(config, OidcTenantRuntimeRegistry.create(config), true);
    }

    /**
     * Create an OIDC HTTP feature sharing the configuration and tenant runtime of an existing provider.
     * The caller owns the provider and must close it after all consumers stop; stopping this feature does not close it.
     *
     * @param provider OIDC security provider
     * @return OIDC HTTP feature
     */
    public static OidcFeature create(OidcProvider provider) {
        Objects.requireNonNull(provider);
        return new OidcFeature(provider.prototype(), provider.tenantRuntimeRegistry(), false);
    }

    @Override
    public void setup(HttpRouting.Builder routing) {
        Objects.requireNonNull(routing, "routing");
        tenantRuntimeRegistry.requireOpen();
        // Create lifecycle state per built routing, including copied/reused builders and direct setup(routing) calls.
        HttpFeature lifecycle = target -> target.addFeature(new RuntimeLifecycle(tenantRuntimeRegistry, ownsRuntime));
        routing.addFeature(lifecycle);
        redirectionEndpointPaths().forEach(path -> routing.get(path, this::processAuthorizationResponse));
        logoutEndpointPaths().forEach(path -> routing.route(Method.POST,
                                                            PathMatchers.exact(path),
                                                            logoutHandler::process));
    }

    @Override
    public void setup(ServerFeatureContext featureContext) {
        Objects.requireNonNull(featureContext, "featureContext");
        String featureSocket = socket();
        if (!featureContext.socketExists(featureSocket)) {
            if (socketRequired()) {
                throw new IllegalArgumentException("OIDC feature is configured to use socket \""
                                                           + featureSocket
                                                           + "\" and it must be present, but it is not");
            }
            featureSocket = WebServer.DEFAULT_SOCKET_NAME;
        }
        setup(featureContext.socket(featureSocket).httpRouting());
    }

    @Override
    public String socket() {
        return config.socket().orElse(WebServer.DEFAULT_SOCKET_NAME);
    }

    @Override
    public boolean socketRequired() {
        return !WebServer.DEFAULT_SOCKET_NAME.equals(socket()) && config.socketRequired();
    }

    @Override
    public String name() {
        return config.providerName();
    }

    @Override
    public String type() {
        return OidcProviderService.PROVIDER_CONFIG_KEY;
    }

    Set<String> redirectionEndpointPaths() {
        Set<String> paths = OidcEndpointUris.redirectionEndpointUris(config).stream()
                .map(OidcUri::path)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        return Collections.unmodifiableSet(paths);
    }

    Set<String> logoutEndpointPaths() {
        return logoutHandler.paths();
    }

    private static void debugUserInfoFailure(OidcTenantContext tenantContext, OidcUserInfoSupport.Result result) {
        if (!LOGGER.isLoggable(System.Logger.Level.DEBUG)) {
            return;
        }
        String reason = result.diagnosticDescription()
                .map(OidcDiagnostics::sanitizeLogValue)
                .orElse("UserInfo failed");
        String cause = result.cause()
                .map(OidcDiagnostics::safeExceptionType)
                .orElse("<none>");
        LOGGER.log(System.Logger.Level.DEBUG,
                   "OIDC UserInfo rejected: tenant="
                           + OidcDiagnostics.sanitizeLogValue(tenantContext.tenantId())
                           + ", reason=" + reason
                           + ", cause=" + cause);
    }

    private void processAuthorizationResponse(ServerRequest request, ServerResponse response) {
        Map<String, List<String>> cookies = request.headers().cookies().toMap();
        OidcAuthorizationResponseResult result;
        try {
            result = authorizationResponseProcessor.process(request.query(),
                                                            cookies,
                                                            request.requestedUri().toUri(),
                                                            Instant.now());
        } catch (OidcTenantRuntimeRegistry.UnavailableException _) {
            // No code was redeemed. Preserve the state cookie so this transaction can resume after initialization.
            response.status(Status.SERVICE_UNAVAILABLE_503).send("OIDC tenant initialization is temporarily unavailable");
            return;
        }
        result.stateCookies().forEach(response.headers()::addCookie);
        if (result.stateValidated()) {
            processTokenEndpointExchange(result, cookies, response);
            return;
        }
        if (result.authorizationError()) {
            if (LOGGER.isLoggable(System.Logger.Level.DEBUG)) {
                LOGGER.log(System.Logger.Level.DEBUG,
                           "OpenID Provider returned an Authorization Error Response: error="
                                   + result.error()
                                           .map(OidcDiagnostics::sanitizeLogValue)
                                           .orElse("unknown"));
            }
            response.status(Status.BAD_REQUEST_400)
                    .send("OpenID Provider returned an Authorization Error Response");
            return;
        }
        response.status(Status.BAD_REQUEST_400)
                .send("Authorization Response is invalid");
    }

    private void processTokenEndpointExchange(OidcAuthorizationResponseResult result,
                                               Map<String, List<String>> requestCookies,
                                               ServerResponse response) {
        OidcTenantContext tenantContext = result.tenantContext().orElseThrow();
        OidcAuthenticationRequestState state = result.authenticationRequestState().orElseThrow();
        OidcTokenEndpointResult tokenResult = tenantContext.endpointClient()
                .exchangeAuthorizationCode(result.authorizationCode().orElseThrow(),
                                           state.redirectionEndpointUri(),
                                           state.pkceVerifier());
        if (!tokenResult.succeeded()) {
            if (tokenResult.errorResponse()) {
                response.status(Status.BAD_GATEWAY_502)
                        .send("Token Endpoint returned an Error Response");
                return;
            }
            response.status(Status.BAD_GATEWAY_502)
                    .send("Token Endpoint exchange failed");
            return;
        }

        OidcTokenResponse tokenResponse = tokenResult.tokenResponse().orElseThrow();
        Instant validationTime = Instant.now();
        OidcValidationResult<OidcValidatedIdToken> idTokenResult = idTokenValidator.validate(
                tokenResponse.idToken().orElseThrow(),
                tenantContext,
                state,
                validationTime);
        if (!idTokenResult.succeeded()) {
            response.status(idTokenResult.unavailable() ? Status.SERVICE_UNAVAILABLE_503 : Status.BAD_GATEWAY_502)
                    .send(idTokenResult.unavailable()
                                  ? "ID Token verification is temporarily unavailable"
                                  : "ID Token is invalid");
            return;
        }

        OidcValidatedIdToken validatedIdToken = idTokenResult.validatedToken().orElseThrow();
        OidcUserInfoSupport.Result userInfoResult = OidcUserInfoSupport.userInfo(tenantContext,
                                                                                  tokenResponse.accessToken(),
                                                                                  validatedIdToken,
                                                                                  validationTime);
        if (!userInfoResult.succeeded()) {
            debugUserInfoFailure(tenantContext, userInfoResult);
            response.status(userInfoResult.unavailable() ? Status.SERVICE_UNAVAILABLE_503 : Status.BAD_GATEWAY_502)
                    .send(userInfoResult.errorDescription().orElseThrow());
            return;
        }

        OidcLocalAuthenticationResult localAuthenticationResult = OidcLocalAuthenticationResult.fromTokenResponse(
                        tenantContext.tenantId(),
                        tokenResponse,
                        validatedIdToken,
                        tenantContext.tenantConfig().authorizationCode().orElseThrow().scopes(),
                        userInfoResult.userInfo(),
                        Instant.now(),
                        tenantContext.cookieStateHandler().cookieConfig().localAuthenticationLifetime())
                .withBrowserSessionGeneration(state.browserSessionGeneration());
        OidcCookieStateHandler cookieHandler = tenantContext.cookieStateHandler();
        try {
            cookieHandler.createLocalAuthenticationResultCookies(
                            localAuthenticationResult,
                            requestCookies,
                            Instant.now())
                    .forEach(response.headers()::addCookie);
        } catch (OidcCookieStateHandler.SessionCookieException e) {
            LOGGER.log(System.Logger.Level.DEBUG, "OIDC session storage failed: " + OidcDiagnostics.safeExceptionType(e));
            cookieHandler.removeLocalAuthenticationResultCookies().forEach(response.headers()::addCookie);
            response.status(Status.SERVICE_UNAVAILABLE_503)
                    .send("OIDC session cannot be stored within the configured cookie limits");
            return;
        }
        response.status(Status.SEE_OTHER_303);
        /*
         * Spec: RFC 9700, 2.1 Redirection URI and 4.11.1 Client as Open Redirector
         * https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1
         * https://www.rfc-editor.org/rfc/rfc9700.html#section-4.11.1
         * Quote: "Clients MUST NOT expose open redirectors."
         * Quote: "In order to prevent open redirection, clients should only redirect if the target URLs are allowed or
         * if the origin and integrity of a request can be authenticated."
         */
        response.headers().add(HeaderNames.LOCATION, OidcUri.localReference(state.originalUri()).toString());
        response.send();
    }

    private static final class RuntimeLifecycle implements HttpFeature {
        private final OidcTenantRuntimeRegistry registry;
        private final boolean ownsRuntime;
        private final ReentrantLock lock = new ReentrantLock();
        private boolean active;

        private RuntimeLifecycle(OidcTenantRuntimeRegistry registry, boolean ownsRuntime) {
            this.registry = registry;
            this.ownsRuntime = ownsRuntime;
        }

        @Override
        public void setup(HttpRouting.Builder routing) {
        }

        @Override
        public void beforeStart() {
            lock.lock();
            try {
                if (active) {
                    return;
                }
                if (ownsRuntime) {
                    registry.retainFeature();
                } else {
                    registry.requireOpen();
                }
                active = true;
            } finally {
                lock.unlock();
            }
        }

        @Override
        public void afterStop() {
            boolean release;
            lock.lock();
            try {
                release = active && ownsRuntime;
                active = false;
            } finally {
                lock.unlock();
            }
            if (release) {
                registry.releaseFeature();
            }
        }
    }
}
