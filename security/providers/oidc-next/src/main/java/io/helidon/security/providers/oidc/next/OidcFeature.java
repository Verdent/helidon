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
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

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
 */
public final class OidcFeature implements HttpFeature, ServerFeature {
    private static final System.Logger LOGGER = System.getLogger(OidcFeature.class.getName());

    private final OidcProviderConfig config;
    private final OidcAuthorizationResponseProcessor authorizationResponseProcessor;
    private final OidcLogoutHandler logoutHandler;
    private final OidcIdTokenValidator idTokenValidator;

    private OidcFeature(OidcProviderConfig config, OidcTenantRuntimeRegistry tenantRuntimeRegistry) {
        OidcProviderConfig providerConfig = Objects.requireNonNull(config);
        OidcTenantRuntimeRegistry runtimeRegistry = Objects.requireNonNull(tenantRuntimeRegistry);
        this.config = providerConfig;
        this.authorizationResponseProcessor = OidcAuthorizationResponseProcessor.create(providerConfig, runtimeRegistry);
        this.logoutHandler = OidcLogoutHandler.create(providerConfig, runtimeRegistry);
        this.idTokenValidator = OidcIdTokenValidator.create();
    }

    /**
     * Create an OIDC HTTP feature from configuration.
     *
     * @param config configuration
     * @return OIDC HTTP feature
     */
    public static OidcFeature create(Config config) {
        return create(OidcProviderConfig.create(config));
    }

    /**
     * Create an OIDC HTTP feature from provider configuration.
     *
     * @param config provider configuration
     * @return OIDC HTTP feature
     */
    public static OidcFeature create(OidcProviderConfig config) {
        return new OidcFeature(config, OidcTenantRuntimeRegistry.create(config));
    }

    @Override
    public void setup(HttpRouting.Builder routing) {
        redirectionEndpointPaths().forEach(path -> routing.get(path, this::processAuthorizationResponse));
        logoutEndpointPaths().forEach(path -> routing.route(Method.POST,
                                                            PathMatchers.exact(path),
                                                            logoutHandler::process));
    }

    @Override
    public void setup(ServerFeatureContext featureContext) {
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
        Set<String> paths = new LinkedHashSet<>();
        config.tenants()
                .values()
                .stream()
                .filter(OidcTenantConfig::enabled)
                .map(OidcTenantConfig::authorizationCode)
                .flatMap(Optional::stream)
                .filter(OidcAuthorizationCodeConfig::enabled)
                .map(OidcConfigSupport::redirectionEndpointUri)
                .map(OidcUri::path)
                .forEach(paths::add);
        return Set.copyOf(paths);
    }

    Set<String> logoutEndpointPaths() {
        return logoutHandler.paths();
    }

    private void processAuthorizationResponse(ServerRequest request, ServerResponse response) {
        OidcAuthorizationResponseResult result = authorizationResponseProcessor.process(
                request.query(),
                request.headers().cookies().toMap(),
                request.requestedUri().toUri(),
                Instant.now());
        result.stateCookies().forEach(response.headers()::addCookie);
        if (result.stateValidated()) {
            processTokenEndpointExchange(result, response);
            return;
        }
        if (result.authorizationError()) {
            LOGGER.log(System.Logger.Level.DEBUG,
                       "OpenID Provider returned an Authorization Error Response: "
                               + result.error().orElse("unknown")
                               + result.errorDescription().map(description -> ": " + description).orElse(""));
            response.status(Status.BAD_REQUEST_400)
                    .send("OpenID Provider returned an Authorization Error Response");
            return;
        }
        response.status(Status.BAD_REQUEST_400)
                .send("Authorization Response is invalid");
    }

    private void processTokenEndpointExchange(OidcAuthorizationResponseResult result, ServerResponse response) {
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
        OidcValidationResult<OidcValidatedIdToken> idTokenResult = idTokenValidator.validate(
                tokenResponse.idToken().orElseThrow(),
                tenantContext,
                state);
        if (!idTokenResult.succeeded()) {
            response.status(Status.BAD_GATEWAY_502)
                    .send("ID Token is invalid");
            return;
        }

        OidcValidatedIdToken validatedIdToken = idTokenResult.validatedToken().orElseThrow();
        OidcUserInfoSupport.Result userInfoResult = OidcUserInfoSupport.userInfo(tenantContext,
                                                                                  tokenResponse.accessToken(),
                                                                                  validatedIdToken);
        if (!userInfoResult.succeeded()) {
            response.status(Status.BAD_GATEWAY_502)
                    .send(userInfoResult.errorDescription().orElseThrow());
            return;
        }

        OidcLocalAuthenticationResult localAuthenticationResult = OidcLocalAuthenticationResult.create(
                tenantContext.tenantId(),
                tokenResponse,
                validatedIdToken,
                tenantContext.tenantConfig().authorizationCode().orElseThrow().scopes(),
                userInfoResult.userInfo(),
                Instant.now(),
                tenantContext.cookieStateHandler().cookieConfig().localAuthenticationLifetime());
        response.headers()
                .addCookie(tenantContext.cookieStateHandler()
                                   .createLocalAuthenticationResultCookie(localAuthenticationResult));
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
}
