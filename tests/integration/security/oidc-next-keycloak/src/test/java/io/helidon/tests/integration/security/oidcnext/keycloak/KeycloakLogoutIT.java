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

package io.helidon.tests.integration.security.oidcnext.keycloak;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import io.helidon.common.parameters.Parameters;
import io.helidon.common.uri.UriQuery;
import io.helidon.http.HeaderNames;
import io.helidon.http.HttpMediaTypes;
import io.helidon.http.Method;
import io.helidon.http.SetCookie;
import io.helidon.http.Status;
import io.helidon.security.providers.oidc.next.OidcCookieConfig;
import io.helidon.security.providers.oidc.next.OidcEndpointCredential;
import io.helidon.security.providers.oidc.next.OidcEndpointPolicyConfig;
import io.helidon.security.providers.oidc.next.OidcProviderConfig;
import io.helidon.security.providers.oidc.next.OidcTokenValidationMethod;
import io.helidon.tests.integration.security.oidcnext.keycloak.KeycloakOidcIntegrationSupport.BrowserSession;
import io.helidon.webclient.api.HttpClientResponse;
import io.helidon.webclient.api.WebClient;
import io.helidon.webclient.api.WebClientConfig;
import io.helidon.webclient.api.WebClientServiceRequest;
import io.helidon.webclient.api.WebClientServiceResponse;
import io.helidon.webclient.spi.WebClientService;
import io.helidon.webserver.WebServer;

import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

@Testcontainers(disabledWithoutDocker = true)
class KeycloakLogoutIT {
    private static final long RACE_TIMEOUT_SECONDS = 30;

    @Container
    static final GenericContainer<?> CONTAINER = KeycloakOidcContainer.CONTAINER;

    @Test
    void localLogoutRedirectsToKeycloakEndSessionEndpointAndClearsLocalCookie() {
        OidcProviderConfig providerConfig = KeycloakOidcIntegrationSupport.authorizationCodeProviderConfig(
                authorizationCode -> {
                });
        WebServer rpServer = KeycloakOidcIntegrationSupport.rpServer(
                providerConfig,
                routing -> KeycloakOidcIntegrationSupport.protectedRoute(routing, "/resource"));
        try (BrowserSession browser = new BrowserSession()) {
            URI rpBaseUri = KeycloakOidcIntegrationSupport.rpBaseUri(rpServer);
            URI resourceUri = rpBaseUri.resolve("/resource");
            KeycloakOidcIntegrationSupport.authenticate(browser, resourceUri);

            URI localLogout = rpBaseUri.resolve("/oidc/logout");
            URI endSessionUri;
            try (HttpClientResponse logout = browser.post(localLogout,
                                                          Parameters.empty("logout"),
                                                          request -> request.header(HeaderNames.ORIGIN,
                                                                                    rpBaseUri.toString()))) {
                assertThat(logout.status(), is(Status.SEE_OTHER_303));
                endSessionUri = URI.create(logout.headers().first(HeaderNames.LOCATION).orElseThrow());
            }

            UriQuery endSessionQuery = UriQuery.create(endSessionUri);
            assertThat(endSessionQuery.contains("id_token_hint"), is(true));

            try (HttpClientResponse afterLogout = browser.get(resourceUri)) {
                assertThat(afterLogout.status(), is(Status.SEE_OTHER_303));
                URI authorizationUri = URI.create(afterLogout.headers().first(HeaderNames.LOCATION).orElseThrow());
                assertThat(authorizationUri.getPath().endsWith("/protocol/openid-connect/auth"), is(true));
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void localLogoutCanCompleteKeycloakEndSessionAndReturnToPostLogoutRedirectUri() throws IOException {
        int rpPort = availablePort();
        URI postLogoutRedirectUri = URI.create("http://localhost:" + rpPort + "/logged-out");
        OidcProviderConfig providerConfig = KeycloakOidcIntegrationSupport.authorizationCodeProviderConfig(
                authorizationCode -> {
                },
                tenant -> tenant.logout(logout -> logout.endSession(endSession -> endSession
                        .postLogoutRedirectUri(postLogoutRedirectUri))));
        WebServer rpServer = KeycloakOidcIntegrationSupport.rpServer(
                rpPort,
                providerConfig,
                routing -> {
                    KeycloakOidcIntegrationSupport.protectedRoute(routing, "/resource");
                    routing.get("/logged-out", (request, response) -> {
                        response.headers().contentType(HttpMediaTypes.PLAINTEXT_UTF_8);
                        response.send("logged-out");
                    });
                });
        try (BrowserSession browser = new BrowserSession()) {
            URI rpBaseUri = KeycloakOidcIntegrationSupport.rpBaseUri(rpServer);
            URI resourceUri = rpBaseUri.resolve("/resource");
            KeycloakOidcIntegrationSupport.authenticate(browser, resourceUri);

            URI localLogout = rpBaseUri.resolve("/oidc/logout?state=logout-state");
            URI endSessionUri;
            try (HttpClientResponse logout = browser.post(localLogout,
                                                          Parameters.empty("logout"),
                                                          request -> request.header(HeaderNames.ORIGIN,
                                                                                    rpBaseUri.toString()))) {
                assertThat(logout.status(), is(Status.SEE_OTHER_303));
                endSessionUri = URI.create(logout.headers().first(HeaderNames.LOCATION).orElseThrow());
            }

            UriQuery endSessionQuery = UriQuery.create(endSessionUri);
            assertThat(endSessionQuery.first("post_logout_redirect_uri").orElse(""), is(postLogoutRedirectUri.toString()));
            assertThat(endSessionQuery.first("state").orElse(""), is("logout-state"));

            URI loggedOutUri;
            try (HttpClientResponse endSession = browser.get(endSessionUri)) {
                int status = endSession.status().code();
                assertThat(status == Status.FOUND_302.code() || status == Status.SEE_OTHER_303.code(), is(true));
                loggedOutUri = endSessionUri.resolve(endSession.headers().first(HeaderNames.LOCATION).orElseThrow());
            }

            assertThat(loggedOutUri.getPath(), is("/logged-out"));
            assertThat(UriQuery.create(loggedOutUri).first("state").orElse(""), is("logout-state"));
            try (HttpClientResponse loggedOut = browser.get(loggedOutUri)) {
                assertThat(loggedOut.status(), is(Status.OK_200));
                assertThat(loggedOut.as(String.class), is("logged-out"));
            }
        } finally {
            rpServer.stop();
        }
    }

    @Test
    void inFlightKeycloakRefreshCannotRestoreAuthenticationAfterLocalLogout() throws Exception {
        RefreshResponseGate refreshResponseGate = new RefreshResponseGate();
        OidcEndpointPolicyConfig browserPolicy = OidcEndpointPolicyConfig.builder()
                .acceptedCredentials(List.of(OidcEndpointCredential.AUTHENTICATION_COOKIE))
                .buildPrototype();
        OidcProviderConfig providerConfig = KeycloakOidcIntegrationSupport.authorizationCodeProviderConfig(
                authorizationCode -> {
                },
                tenant -> tenant
                        .protectedResource(resource -> resource
                                .enabled(false)
                                .tokenValidation(validation -> validation
                                        .method(OidcTokenValidationMethod.INTROSPECTION)
                                        .audience(KeycloakOidcIntegrationSupport.API_AUDIENCE)
                                        .introspection(introspection -> introspection
                                                .clientId(KeycloakOidcIntegrationSupport.API_AUDIENCE)
                                                .clientSecret(KeycloakOidcIntegrationSupport.API_CLIENT_SECRET))
                                        .audienceValidationEnabled(false)
                                        .clockSkew(Duration.ofHours(1))))
                        .cookies(OidcCookieConfig.builder(tenant.cookies()).maxCookieSize(1200).maxChunks(16).buildPrototype())
                        .userInfo(userInfo -> userInfo.enabled(false))
                        .logout(logout -> logout.endSession(endSession -> endSession.enabled(false)))
                        .webClient(WebClientConfig.builder()
                                           .connectTimeout(Duration.ofSeconds(10))
                                           .readTimeout(Duration.ofSeconds(20))
                                           .addService(refreshResponseGate)
                                           .buildPrototype()));
        WebServer rpServer = KeycloakOidcIntegrationSupport.rpServer(
                providerConfig,
                routing -> KeycloakOidcIntegrationSupport.protectedRoute(routing, "/resource", browserPolicy));
        try (BrowserSession browser = new BrowserSession()) {
            URI rpBaseUri = KeycloakOidcIntegrationSupport.rpBaseUri(rpServer);
            URI resourceUri = rpBaseUri.resolve("/resource");
            URI localLogoutUri = rpBaseUri.resolve("/oidc/logout");
            String localAuthenticationCookieName = providerConfig.tenants()
                    .get("default")
                    .cookies()
                    .localAuthenticationCookieName();
            String browserSessionGenerationCookieName = localAuthenticationCookieName + "-generation";
            KeycloakOidcIntegrationSupport.authenticate(browser, resourceUri);
            String initialAuthenticationCookie = browser.cookieValue(localAuthenticationCookieName).orElseThrow();
            String initialBrowserSessionGenerationCookie = browser.cookieValue(browserSessionGenerationCookieName)
                    .orElseThrow();
            String initialCookieHeader = browser.cookieHeader().orElseThrow();
            assertThat("the race must exercise a multi-cookie session",
                       browser.cookieValue(localAuthenticationCookieName + ".1").isPresent(), is(true));

            refreshResponseGate.arm();
            ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();
            Future<ResourceResponse> refreshRequest = null;
            try {
                refreshRequest = executor.submit(() -> requestResource(resourceUri, initialCookieHeader));
                refreshResponseGate.awaitKeycloakResponse();
                assertThat(refreshResponseGate.interceptedCount(), is(1));
                assertThat(refreshResponseGate.interceptedUri(), is(KeycloakOidcContainer.tokenEndpointUri()));
                assertThat(refreshResponseGate.interceptedStatus(), is(Status.OK_200));
                assertThat("resource response must remain withheld while logout completes",
                           refreshRequest.isDone(),
                           is(false));

                List<String> logoutCookies;
                try (HttpClientResponse logout = browser.post(
                        localLogoutUri,
                        Parameters.empty("logout"),
                        request -> request.header(HeaderNames.ORIGIN, rpBaseUri.toString()))) {
                    assertThat(logout.status(), is(Status.NO_CONTENT_204));
                    logoutCookies = setCookies(logout);
                }
                SetCookie removalCookie = responseCookie(logoutCookies, localAuthenticationCookieName);
                assertThat(isRemovalCookie(removalCookie), is(true));
                SetCookie logoutGenerationCookie = responseCookie(logoutCookies,
                                                                  browserSessionGenerationCookieName);
                assertThat(isRemovalCookie(logoutGenerationCookie), is(false));
                assertThat(logoutGenerationCookie.value().equals(initialBrowserSessionGenerationCookie), is(false));
                assertThat(browser.cookieValue(localAuthenticationCookieName), is(Optional.empty()));
                for (int index = 1; index < 16; index++) {
                    assertThat(browser.cookieValue(localAuthenticationCookieName + "." + index), is(Optional.empty()));
                }
                assertThat(browser.cookieValue(browserSessionGenerationCookieName),
                           is(Optional.of(logoutGenerationCookie.value())));
                assertThat("logout must finish before the refresh response is released",
                           refreshRequest.isDone(),
                           is(false));

                refreshResponseGate.releaseResponse();
                ResourceResponse lateRefresh = refreshRequest.get(RACE_TIMEOUT_SECONDS, TimeUnit.SECONDS);
                assertThat(lateRefresh.status(), is(Status.OK_200));
                assertThat(lateRefresh.body(),
                           is(KeycloakOidcIntegrationSupport.alicePrincipalResponse()));
                SetCookie replacementCookie = responseCookie(lateRefresh.setCookies(),
                                                             localAuthenticationCookieName);
                assertThat(isRemovalCookie(replacementCookie), is(false));
                assertThat(replacementCookie.value().isBlank(), is(false));
                assertThat(replacementCookie.value().equals(initialAuthenticationCookie), is(false));
                assertThat(lateRefresh.setCookies()
                                   .stream()
                                   .map(SetCookie::parse)
                                   .noneMatch(cookie -> cookie.name().equals(browserSessionGenerationCookieName)),
                           is(true));
                assertThat("receiving the isolated response must not implicitly mutate the browser cookie jar",
                           browser.cookieValue(localAuthenticationCookieName),
                           is(Optional.empty()));
                browser.applySetCookieHeaders(lateRefresh.setCookies());
                assertThat(browser.cookieValue(localAuthenticationCookieName),
                           is(Optional.of(replacementCookie.value())));
                assertThat(browser.cookieValue(browserSessionGenerationCookieName),
                           is(Optional.of(logoutGenerationCookie.value())));

                try (HttpClientResponse rejected = browser.get(resourceUri)) {
                    assertThat("the pre-logout generation must not authenticate after logout",
                               rejected.status(),
                               is(Status.SEE_OTHER_303));
                    assertThat(browser.cookieValue(localAuthenticationCookieName), is(Optional.empty()));
                }
            } finally {
                refreshResponseGate.releaseResponse();
                if (refreshRequest != null) {
                    refreshRequest.cancel(true);
                }
                shutdown(executor);
            }
        } finally {
            rpServer.stop();
        }
    }

    private static ResourceResponse requestResource(URI resourceUri, String cookieHeader) {
        WebClient client = WebClient.builder()
                .followRedirects(false)
                .build();
        try {
            try (HttpClientResponse response = client.get()
                    .uri(resourceUri)
                    .header(HeaderNames.COOKIE, cookieHeader)
                    .readTimeout(Duration.ofSeconds(45))
                    .request()) {
                String body = response.entity().hasEntity() ? response.as(String.class) : "";
                return new ResourceResponse(response.status(), setCookies(response), body);
            }
        } finally {
            client.closeResource();
        }
    }

    private static List<String> setCookies(HttpClientResponse response) {
        return response.headers().contains(HeaderNames.SET_COOKIE)
                ? List.copyOf(response.headers().get(HeaderNames.SET_COOKIE).allValues())
                : List.of();
    }

    private static SetCookie responseCookie(List<String> setCookies, String name) {
        return setCookies.stream()
                .map(SetCookie::parse)
                .filter(cookie -> cookie.name().equals(name))
                .findFirst()
                .orElseThrow(() -> new AssertionError("response did not set cookie: " + name));
    }

    private static boolean isRemovalCookie(SetCookie cookie) {
        return cookie.maxAge()
                .map(maxAge -> maxAge.isZero() || maxAge.isNegative())
                .orElseGet(() -> cookie.expires()
                        .filter(expires -> !expires.toInstant().isAfter(Instant.now()))
                        .isPresent());
    }

    private static void await(CountDownLatch latch, String operation) {
        try {
            if (!latch.await(RACE_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                throw new AssertionError("timed out " + operation);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AssertionError("interrupted " + operation, e);
        }
    }

    private static void shutdown(ExecutorService executor) {
        executor.shutdownNow();
        try {
            if (!executor.awaitTermination(RACE_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                throw new AssertionError("timed out shutting down refresh/logout executor");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AssertionError("interrupted while shutting down refresh/logout executor", e);
        }
    }

    private record ResourceResponse(Status status, List<String> setCookies, String body) {
    }

    private static final class RefreshResponseGate implements WebClientService {
        private final AtomicBoolean armed = new AtomicBoolean();
        private final AtomicInteger interceptedCount = new AtomicInteger();
        private final AtomicReference<URI> interceptedUri = new AtomicReference<>();
        private final AtomicReference<Status> interceptedStatus = new AtomicReference<>();
        private final CountDownLatch keycloakResponseReceived = new CountDownLatch(1);
        private final CountDownLatch releaseResponse = new CountDownLatch(1);

        @Override
        public WebClientServiceResponse handle(Chain chain, WebClientServiceRequest request) {
            URI requestUri = request.uri().toUri();
            if (request.method() != Method.POST
                    || !KeycloakOidcContainer.tokenEndpointUri().equals(requestUri)
                    || !armed.compareAndSet(true, false)) {
                return chain.proceed(request);
            }

            WebClientServiceResponse response = chain.proceed(request);
            interceptedUri.set(requestUri);
            interceptedStatus.set(response.status());
            interceptedCount.incrementAndGet();
            keycloakResponseReceived.countDown();
            try {
                await(releaseResponse, "waiting to release the real Keycloak refresh response");
            } catch (RuntimeException | Error e) {
                try {
                    response.connection().closeResource();
                } catch (RuntimeException closeFailure) {
                    e.addSuppressed(closeFailure);
                }
                throw e;
            }
            return response;
        }

        private void arm() {
            if (!armed.compareAndSet(false, true)) {
                throw new IllegalStateException("refresh response gate is already armed");
            }
        }

        private void awaitKeycloakResponse() {
            await(keycloakResponseReceived, "waiting for the real Keycloak refresh response");
        }

        private void releaseResponse() {
            releaseResponse.countDown();
        }

        private int interceptedCount() {
            return interceptedCount.get();
        }

        private URI interceptedUri() {
            return interceptedUri.get();
        }

        private Status interceptedStatus() {
            return interceptedStatus.get();
        }
    }

    private static int availablePort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }
}
