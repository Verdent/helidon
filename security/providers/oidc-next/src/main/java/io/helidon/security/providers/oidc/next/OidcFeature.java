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
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

import io.helidon.config.Config;
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

    private OidcFeature(OidcProviderConfig config, OidcTenantRuntimeRegistry tenantRuntimeRegistry) {
        this.config = Objects.requireNonNull(config);
        this.authorizationResponseProcessor = OidcAuthorizationResponseProcessor.create(config, tenantRuntimeRegistry);
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
    }

    Set<String> redirectionEndpointPaths() {
        Set<String> paths = new LinkedHashSet<>();
        config.tenants()
                .values()
                .stream()
                .filter(OidcTenantConfig::enabled)
                .map(OidcTenantConfig::authorizationCode)
                .filter(OidcAuthorizationCodeConfig::enabled)
                .flatMap(authorizationCode -> authorizationCode.redirectionEndpointUri().stream())
                .map(OidcFeature::path)
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
            response.status(Status.NOT_IMPLEMENTED_501)
                    .send("Token Endpoint exchange is not implemented yet");
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

    private static String path(URI uri) {
        String path = uri.getPath();
        if (path == null || path.isEmpty()) {
            return "/";
        }
        return path;
    }
}
