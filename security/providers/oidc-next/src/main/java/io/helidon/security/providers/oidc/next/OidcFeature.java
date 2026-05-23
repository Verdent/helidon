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
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import io.helidon.config.Config;
import io.helidon.http.HeaderNames;
import io.helidon.http.Method;
import io.helidon.http.PathMatchers;
import io.helidon.http.Status;
import io.helidon.webserver.http.HttpFeature;
import io.helidon.webserver.http.HttpRouting;
import io.helidon.webserver.http.ServerRequest;
import io.helidon.webserver.http.ServerResponse;

/**
 * OpenID Connect HTTP feature for Redirection Endpoint and logout routes.
 */
public final class OidcFeature implements HttpFeature {
    private final OidcProviderConfig config;
    private final OidcAuthorizationResponseProcessor authorizationResponseProcessor;
    private final OidcIdTokenValidator idTokenValidator;

    private OidcFeature(OidcProviderConfig config, OidcTenantRuntimeRegistry tenantRuntimeRegistry) {
        this.config = Objects.requireNonNull(config);
        this.authorizationResponseProcessor = OidcAuthorizationResponseProcessor.create(config, tenantRuntimeRegistry);
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
        logoutEndpointPaths().forEach(path -> routing.route(Method.POST, PathMatchers.exact(path), this::processLogout));
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
                .flatMap(authorizationCode -> authorizationCode.redirectionEndpointUri().stream())
                .map(OidcFeature::path)
                .forEach(paths::add);
        return Set.copyOf(paths);
    }

    Set<String> logoutEndpointPaths() {
        Set<String> paths = new LinkedHashSet<>();
        logoutTenants().stream()
                .map(Map.Entry::getValue)
                .map(OidcFeature::logoutEndpointPath)
                .forEach(paths::add);
        return Set.copyOf(paths);
    }

    private void processAuthorizationResponse(ServerRequest request, ServerResponse response) {
        OidcAuthorizationResponseResult result = authorizationResponseProcessor.process(
                OidcAuthorizationResponseContext.create(request.query(),
                                                        request.headers().cookies().toMap(),
                                                        request.requestedUri().toUri(),
                                                        Instant.now()));
        result.stateCookies().forEach(response.headers()::addCookie);
        if (result.stateValidated()) {
            processTokenEndpointExchange(result, response);
            return;
        }
        if (result.authorizationError()) {
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
        if (tokenResult.succeeded()) {
            OidcTokenResponse tokenResponse = tokenResult.tokenResponse().orElseThrow();
            OidcIdTokenValidationResult idTokenResult = idTokenValidator.validate(
                    tokenResponse.idToken().orElseThrow(),
                    tenantContext,
                    state);
            if (!idTokenResult.succeeded()) {
                response.status(Status.BAD_GATEWAY_502)
                        .send("ID Token is invalid");
                return;
            }
            OidcLocalAuthenticationResult localAuthenticationResult = OidcLocalAuthenticationResult.create(
                    tenantContext.tenantId(),
                    tokenResponse,
                    idTokenResult.validatedToken().orElseThrow(),
                    tenantContext.tenantConfig().authorizationCode().orElseThrow().scopes(),
                    Instant.now(),
                    tenantContext.cookieStateHandler().cookieConfig().localAuthenticationLifetime());
            response.headers()
                    .addCookie(tenantContext.cookieStateHandler()
                                       .createLocalAuthenticationResultCookie(localAuthenticationResult));
            response.status(Status.SEE_OTHER_303);
            response.headers().add(HeaderNames.LOCATION, state.originalUri().toString());
            response.send();
            return;
        }
        if (tokenResult.errorResponse()) {
            response.status(Status.BAD_GATEWAY_502)
                    .send("Token Endpoint returned an Error Response");
            return;
        }
        response.status(Status.BAD_GATEWAY_502)
                .send("Token Endpoint exchange failed");
    }

    private void processLogout(ServerRequest request, ServerResponse response) {
        if (!sameOrigin(request)) {
            response.status(Status.FORBIDDEN_403)
                    .send("Logout request is not same-origin");
            return;
        }

        String requestPath = path(request.requestedUri().toUri());
        List<Map.Entry<String, OidcTenantConfig>> tenants = logoutTenants()
                .stream()
                .filter(entry -> logoutEndpointPath(entry.getValue()).equals(requestPath))
                .toList();
        if (tenants.isEmpty()) {
            response.status(Status.NOT_FOUND_404).send();
            return;
        }
        Map<String, List<String>> cookies = request.headers().cookies().toMap();
        Instant now = Instant.now();
        List<Map.Entry<String, OidcTenantConfig>> localAuthenticationTenants = tenants.stream()
                .filter(tenant -> localAuthenticationResultMatchesTenant(tenant, cookies, now))
                .toList();
        List<Map.Entry<String, OidcTenantConfig>> tenantsToClear = localAuthenticationTenants.size() == 1
                ? localAuthenticationTenants
                : tenants;

        Set<String> removedCookieNames = new HashSet<>();
        tenantsToClear.stream()
                .map(Map.Entry::getValue)
                .map(OidcCookieStateHandler::create)
                .forEach(cookieStateHandler -> {
                    String localAuthenticationCookieName = cookieStateHandler.cookieConfig()
                            .localAuthenticationCookieName();
                    if (removedCookieNames.add(localAuthenticationCookieName)) {
                        response.headers().addCookie(cookieStateHandler.removeLocalAuthenticationResultCookie());
                    }
                    String authenticationRequestCookieName = cookieStateHandler.cookieConfig()
                            .authenticationRequestCookieName();
                    if (removedCookieNames.add(authenticationRequestCookieName)) {
                        response.headers().addCookie(cookieStateHandler.removeAuthenticationRequestCookie());
                    }
                });

        response.status(Status.NO_CONTENT_204).send();
    }

    private boolean sameOrigin(ServerRequest request) {
        URI requestedUri = request.requestedUri().toUri();
        Optional<String> origin = request.headers().first(HeaderNames.ORIGIN);
        if (origin.isPresent()) {
            return sameOrigin(requestedUri, origin.orElseThrow());
        }
        return request.headers()
                .first(HeaderNames.REFERER)
                .filter(referer -> sameOrigin(requestedUri, referer))
                .isPresent();
    }

    private boolean sameOrigin(URI requestedUri, String originHeader) {
        try {
            URI origin = URI.create(originHeader);
            return sameOrigin(requestedUri, origin);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private boolean sameOrigin(URI requestedUri, URI origin) {
        String requestedScheme = requestedUri.getScheme();
        String originScheme = origin.getScheme();
        String requestedHost = requestedUri.getHost();
        String originHost = origin.getHost();
        return requestedScheme != null
                && originScheme != null
                && requestedHost != null
                && originHost != null
                && requestedScheme.equalsIgnoreCase(originScheme)
                && requestedHost.equalsIgnoreCase(originHost)
                && effectivePort(requestedUri) == effectivePort(origin);
    }

    private int effectivePort(URI uri) {
        int port = uri.getPort();
        if (port != -1) {
            return port;
        }
        String scheme = uri.getScheme();
        if ("https".equalsIgnoreCase(scheme)) {
            return 443;
        }
        if ("http".equalsIgnoreCase(scheme)) {
            return 80;
        }
        return -1;
    }

    private List<Map.Entry<String, OidcTenantConfig>> logoutTenants() {
        return config.tenants()
                .entrySet()
                .stream()
                .filter(entry -> entry.getValue().enabled())
                .filter(entry -> entry.getValue().logout().filter(OidcLogoutConfig::enabled).isPresent())
                .toList();
    }

    private boolean localAuthenticationResultMatchesTenant(Map.Entry<String, OidcTenantConfig> tenant,
                                                           Map<String, List<String>> cookies,
                                                           Instant now) {
        OidcCookieStateHandler cookieStateHandler = OidcCookieStateHandler.create(tenant.getValue());
        return cookies.getOrDefault(cookieStateHandler.cookieConfig().localAuthenticationCookieName(), List.of())
                .stream()
                .flatMap(cookieValue -> cookieStateHandler.readLocalAuthenticationResult(cookieValue, now).stream())
                .map(OidcLocalAuthenticationResult::tenantId)
                .anyMatch(tenant.getKey()::equals);
    }

    private static String logoutEndpointPath(OidcTenantConfig tenant) {
        return path(tenant.logout().orElseThrow().localEndpointUri());
    }

    private static String path(URI uri) {
        String path = uri.getPath();
        if (path == null || path.isEmpty()) {
            return "/";
        }
        return path;
    }
}
