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

import io.helidon.common.uri.UriQueryWriteable;
import io.helidon.http.HeaderNames;
import io.helidon.http.Status;
import io.helidon.webserver.http.ServerRequest;
import io.helidon.webserver.http.ServerResponse;

final class OidcLogoutHandler {
    private final OidcProviderConfig config;
    private final OidcTenantRuntimeRegistry tenantRuntimeRegistry;

    private OidcLogoutHandler(OidcProviderConfig config, OidcTenantRuntimeRegistry tenantRuntimeRegistry) {
        this.config = Objects.requireNonNull(config);
        this.tenantRuntimeRegistry = Objects.requireNonNull(tenantRuntimeRegistry);
    }

    static OidcLogoutHandler create(OidcProviderConfig config, OidcTenantRuntimeRegistry tenantRuntimeRegistry) {
        return new OidcLogoutHandler(config, tenantRuntimeRegistry);
    }

    Set<String> paths() {
        Set<String> paths = new LinkedHashSet<>();
        logoutTenants().stream()
                .map(Map.Entry::getValue)
                .map(OidcLogoutHandler::logoutEndpointPath)
                .forEach(paths::add);
        return Set.copyOf(paths);
    }

    void process(ServerRequest request, ServerResponse response) {
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
        List<LogoutTenant> logoutTenants = tenants.stream()
                .map(entry -> {
                    OidcCookieStateHandler cookieStateHandler = OidcCookieStateHandler.create(entry.getValue());
                    Optional<OidcLocalAuthenticationResult> localAuthenticationResult = cookies
                            .getOrDefault(cookieStateHandler.cookieConfig().localAuthenticationCookieName(), List.of())
                            .stream()
                            .flatMap(cookieValue -> cookieStateHandler.readLocalAuthenticationResult(cookieValue, now)
                                    .stream())
                            .filter(result -> entry.getKey().equals(result.tenantId()))
                            .findFirst();
                    return new LogoutTenant(entry.getKey(),
                                            entry.getValue(),
                                            cookieStateHandler,
                                            localAuthenticationResult);
                })
                .toList();
        List<LogoutTenant> localAuthenticationTenants = logoutTenants.stream()
                .filter(tenant -> tenant.localAuthenticationResult().isPresent())
                .toList();
        List<LogoutTenant> tenantsToClear = localAuthenticationTenants.size() == 1
                ? localAuthenticationTenants
                : logoutTenants;

        Set<String> removedCookieNames = new HashSet<>();
        tenantsToClear.stream()
                .map(LogoutTenant::cookieStateHandler)
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

        Optional<LogoutTenant> endSessionTenant = Optional.empty();
        if (localAuthenticationTenants.size() == 1) {
            endSessionTenant = Optional.of(localAuthenticationTenants.getFirst());
        } else if (logoutTenants.size() == 1) {
            endSessionTenant = Optional.of(logoutTenants.getFirst());
        }
        if (endSessionTenant.isEmpty()) {
            response.status(Status.NO_CONTENT_204).send();
            return;
        }

        LogoutTenant selectedEndSessionTenant = endSessionTenant.orElseThrow();
        Optional<OidcEndSessionConfig> configuredEndSession = selectedEndSessionTenant.tenantConfig()
                .logout()
                .filter(OidcLogoutConfig::enabled)
                .flatMap(OidcLogoutConfig::endSession)
                .filter(OidcEndSessionConfig::enabled);
        if (configuredEndSession.isEmpty()) {
            response.status(Status.NO_CONTENT_204).send();
            return;
        }

        OidcEndSessionConfig endSession = configuredEndSession.orElseThrow();
        Optional<String> idTokenHint = selectedEndSessionTenant
                .localAuthenticationResult()
                .map(OidcLocalAuthenticationResult::idToken)
                .map(OidcValidatedIdToken::rawToken);
        if (idTokenHint.isEmpty() && endSession.idTokenHintRequired()) {
            response.status(Status.FORBIDDEN_403)
                    .send("id_token_hint is required for RP-Initiated Logout");
            return;
        }

        Optional<URI> postLogoutRedirectUri;
        try {
            postLogoutRedirectUri = postLogoutRedirectUri(request, endSession);
        } catch (IllegalArgumentException e) {
            response.status(Status.BAD_REQUEST_400)
                    .send(e.getMessage());
            return;
        }

        OidcTenantContext tenantContext = tenantRuntimeRegistry.tenantContext(selectedEndSessionTenant.tenantId())
                .filter(OidcTenantContext::ready)
                .orElse(null);
        if (tenantContext == null) {
            response.status(Status.BAD_GATEWAY_502)
                    .send("End Session Endpoint is unavailable");
            return;
        }

        URI endSessionEndpointUri = tenantContext.metadata()
                .endSessionEndpointUri()
                .orElse(null);
        if (endSessionEndpointUri == null) {
            response.status(Status.BAD_GATEWAY_502)
                    .send("End Session Endpoint is unavailable");
            return;
        }

        response.status(Status.SEE_OTHER_303);
        response.headers().add(HeaderNames.LOCATION, endSessionLocation(endSessionEndpointUri,
                                                                        idTokenHint,
                                                                        selectedEndSessionTenant.tenantConfig()
                                                                                .clientId(),
                                                                        postLogoutRedirectUri,
                                                                        request).toString());
        response.send();
    }

    private Optional<URI> postLogoutRedirectUri(ServerRequest request, OidcEndSessionConfig endSession) {
        List<String> requestedPostLogoutRedirectUris = request.query()
                .all("post_logout_redirect_uri", List::of);
        if (requestedPostLogoutRedirectUris.isEmpty()) {
            return endSession.postLogoutRedirectUri();
        }
        if (requestedPostLogoutRedirectUris.size() > 1 || requestedPostLogoutRedirectUris.getFirst().isBlank()) {
            throw new IllegalArgumentException("post_logout_redirect_uri is invalid");
        }

        URI requestedUri;
        try {
            requestedUri = URI.create(requestedPostLogoutRedirectUris.getFirst());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("post_logout_redirect_uri is invalid", e);
        }

        if (endSession.postLogoutRedirectUri().filter(requestedUri::equals).isPresent()
                || endSession.allowedPostLogoutRedirectUris().contains(requestedUri)) {
            return Optional.of(requestedUri);
        }
        throw new IllegalArgumentException("post_logout_redirect_uri is not allowed");
    }

    private URI endSessionLocation(URI endSessionEndpointUri,
                                   Optional<String> idTokenHint,
                                   Optional<String> clientId,
                                   Optional<URI> postLogoutRedirectUri,
                                   ServerRequest request) {
        /*
         * Spec: OpenID Connect RP-Initiated Logout 1.0, 2 RP-Initiated Logout
         * https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout
         * Quotes: "redirecting the End-User's User Agent to the OP's Logout Endpoint";
         * "RECOMMENDED. ID Token previously issued by the OP to the RP passed to the Logout Endpoint as a hint";
         * "OPTIONAL. OAuth 2.0 Client Identifier valid at the Authorization Server";
         * "OPTIONAL. URI to which the RP is requesting"; "OPTIONAL. Opaque value used by the RP".
         */
        UriQueryWriteable query = UriQueryWriteable.create();
        idTokenHint.ifPresent(value -> query.set("id_token_hint", value));
        if (idTokenHint.isEmpty()) {
            clientId.ifPresent(value -> query.set("client_id", value));
        }
        postLogoutRedirectUri.ifPresent(uri -> query.set("post_logout_redirect_uri", uri.toString()));
        if (postLogoutRedirectUri.isPresent()) {
            request.query()
                    .first("state")
                    .filter(state -> !state.isBlank())
                    .ifPresent(state -> query.set("state", state));
        }

        String queryValue = query.rawValue();
        if (queryValue.isEmpty()) {
            return endSessionEndpointUri;
        }
        return URI.create(endSessionEndpointUri
                                  + (endSessionEndpointUri.getRawQuery() == null ? "?" : "&")
                                  + queryValue);
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

    private record LogoutTenant(String tenantId,
                                OidcTenantConfig tenantConfig,
                                OidcCookieStateHandler cookieStateHandler,
                                Optional<OidcLocalAuthenticationResult> localAuthenticationResult) {
    }
}
