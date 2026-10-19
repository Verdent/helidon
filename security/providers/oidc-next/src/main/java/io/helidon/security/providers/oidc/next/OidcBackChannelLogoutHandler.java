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

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.DateTimeException;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import io.helidon.common.uri.UriQuery;
import io.helidon.http.HeaderNames;
import io.helidon.http.Status;
import io.helidon.security.providers.oidc.next.spi.OidcBackChannelLogoutStore;
import io.helidon.webserver.http.ServerRequest;
import io.helidon.webserver.http.ServerResponse;

/**
 * Cookie-less OP-to-RP logout receiver. The separate browser logout handler enforces Origin/Referer, which is not
 * appropriate for a direct OP POST; the validated signed Logout Token authenticates this endpoint instead.
 */
final class OidcBackChannelLogoutHandler {
    private static final System.Logger LOGGER = System.getLogger(OidcBackChannelLogoutHandler.class.getName());
    private static final int MAX_FORM_BYTES = 1024 * 1024;

    private final OidcTenantRuntimeRegistry tenantRuntimeRegistry;
    private final Map<String, RegisteredTenant> routes;
    private final OidcLogoutTokenValidator validator = new OidcLogoutTokenValidator();

    OidcBackChannelLogoutHandler(OidcProviderConfig config, OidcTenantRuntimeRegistry tenantRuntimeRegistry) {
        Objects.requireNonNull(config);
        this.tenantRuntimeRegistry = Objects.requireNonNull(tenantRuntimeRegistry);
        Map<String, RegisteredTenant> mappedRoutes = new HashMap<>();
        config.tenants().forEach((tenantId, tenant) -> {
            if (!tenant.enabled()) {
                return;
            }
            tenant.logout().filter(OidcLogoutConfig::enabled)
                    .flatMap(OidcLogoutConfig::backChannel)
                    .ifPresent(backChannel -> mappedRoutes.put(OidcUri.path(backChannel.uri()),
                                                                new RegisteredTenant(tenantId, backChannel.uri())));
        });
        this.routes = Map.copyOf(mappedRoutes);
    }

    Set<String> paths() {
        return routes.keySet();
    }

    void process(ServerRequest request, ServerResponse response) {
        response.headers().add(HeaderNames.CACHE_CONTROL, "no-store");
        RegisteredTenant registered = routes.get(OidcUri.path(request.requestedUri().toUri()));
        if (registered == null) {
            // Section 2.8 permits an empty error body or a JSON object containing an error parameter, not plain text.
            response.status(Status.BAD_REQUEST_400).send();
            return;
        }
        if (!matchesRegisteredQuery(registered.uri(), request.requestedUri().toUri())) {
            response.status(Status.BAD_REQUEST_400).send();
            return;
        }

        try {
            Optional<OidcRemoteWorkLimiter.Permit> acquired =
                    tenantRuntimeRegistry.logoutWorkLimiter(registered.tenantId()).orElseThrow().acquireActive();
            if (acquired.isEmpty()) {
                response.status(Status.BAD_REQUEST_400).send();
                return;
            }
            try (OidcRemoteWorkLimiter.Permit _ = acquired.orElseThrow()) {
                // Reserve bounded work capacity before buffering or parsing an untrusted form body.
                Optional<String> token = logoutToken(request);
                if (token.isEmpty()) {
                    response.status(Status.BAD_REQUEST_400).send();
                    return;
                }
                processValidatedToken(registered, token.orElseThrow(), response);
            }
        } catch (RuntimeException e) {
            // Section 2.8 requires a failed logout to be rejected. A failed store write must never be acknowledged.
            if (LOGGER.isLoggable(System.Logger.Level.DEBUG)) {
                LOGGER.log(System.Logger.Level.DEBUG,
                           "OIDC back-channel logout failed: cause=" + OidcDiagnostics.safeExceptionType(e));
            }
            response.status(Status.BAD_REQUEST_400).send();
        }
    }

    private void processValidatedToken(RegisteredTenant registered, String token, ServerResponse response) {
        OidcTenantContext tenant = tenantRuntimeRegistry.tenantContext(registered.tenantId()).orElseThrow();
        if (!tenant.ready()) {
            response.status(Status.BAD_REQUEST_400).send();
            return;
        }
        OidcValidationResult<OidcBackChannelLogoutStore.LogoutEvent> result =
                validator.validate(token, tenant, Instant.now());
        if (!result.succeeded()) {
            response.status(Status.BAD_REQUEST_400).send();
            return;
        }
        OidcBackChannelLogoutStore store = tenantRuntimeRegistry.logoutStore(registered.tenantId()).orElseThrow();
        OidcBackChannelLogoutStore.LogoutEvent event = result.validatedToken().orElseThrow();
        store.revoke(event, retainUntil(tenant, event, Instant.now()));
        response.status(Status.OK_200).send();
    }

    private Optional<String> logoutToken(ServerRequest request) {
        String contentType = request.headers().first(HeaderNames.CONTENT_TYPE).orElse("");
        if (!"application/x-www-form-urlencoded".equalsIgnoreCase(contentType.split(";", 2)[0].trim())) {
            return Optional.empty();
        }
        byte[] body;
        try (InputStream stream = request.content().inputStream()) {
            body = stream.readNBytes(MAX_FORM_BYTES + 1);
        } catch (IOException e) {
            return Optional.empty();
        }
        if (body.length > MAX_FORM_BYTES) {
            return Optional.empty();
        }
        String token = null;
        try {
            for (String field : new String(body, StandardCharsets.UTF_8).split("&")) {
                int equals = field.indexOf('=');
                String name = URLDecoder.decode(equals < 0 ? field : field.substring(0, equals), StandardCharsets.UTF_8);
                if (!"logout_token".equals(name)) {
                    // Section 2.5: ignore other form fields rather than reject an otherwise valid request.
                    continue;
                }
                if (token != null || equals < 0) {
                    return Optional.empty();
                }
                token = URLDecoder.decode(field.substring(equals + 1), StandardCharsets.UTF_8);
            }
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
        return Optional.ofNullable(token).filter(value -> !value.isBlank());
    }

    private boolean matchesRegisteredQuery(URI registered, URI incoming) {
        UriQuery expected = UriQuery.create(registered);
        UriQuery actual = UriQuery.create(incoming);
        return expected.names()
                .stream()
                .allMatch(name -> expected.all(name).equals(actual.all(name, java.util.List::of)));
    }

    private Instant retainUntil(OidcTenantContext tenant, OidcBackChannelLogoutStore.LogoutEvent event, Instant now) {
        OidcCookieConfig cookies = tenant.cookieStateHandler().cookieConfig();
        Duration lifetime = cookies.localAuthenticationLifetime().compareTo(cookies.authenticationRequestLifetime()) >= 0
                ? cookies.localAuthenticationLifetime() : cookies.authenticationRequestLifetime();
        Duration clockSkew = tenant.tenantConfig().idToken().clockSkew();
        try {
            // An authorization callback started before this logout can arrive after every existing session expires.
            // Retain its subject revision until both sessions and pending authorization requests have expired.
            Instant lastAffectedExpiry = now.plus(lifetime).plus(clockSkew);
            // Until exp plus the accepted clock skew, a legitimate retry with this jti must be idempotent. Otherwise
            // replaying a subject-only Logout Token could also log out a session established after the first delivery.
            Instant lastAcceptedRetry = event.expiresAt().plus(clockSkew);
            return lastAffectedExpiry.isAfter(lastAcceptedRetry) ? lastAffectedExpiry : lastAcceptedRetry;
        } catch (DateTimeException | ArithmeticException _) {
            return Instant.MAX;
        }
    }

    private record RegisteredTenant(String tenantId, URI uri) {
    }
}
