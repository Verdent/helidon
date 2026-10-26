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

package io.helidon.tests.integration.security.oidcnext.providers;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import io.helidon.common.context.Contexts;
import io.helidon.common.parameters.Parameters;
import io.helidon.http.HeaderNames;
import io.helidon.http.HeaderValues;
import io.helidon.http.SetCookie;
import io.helidon.http.Status;
import io.helidon.json.JsonObject;
import io.helidon.security.AuthenticationResponse;
import io.helidon.security.Security;
import io.helidon.security.SecurityContext;
import io.helidon.security.SecurityResponse;
import io.helidon.security.providers.oidc.next.OidcClientAuthenticationMethod;
import io.helidon.security.providers.oidc.next.OidcCookieConfig;
import io.helidon.security.providers.oidc.next.OidcEndpointCredential;
import io.helidon.security.providers.oidc.next.OidcEndpointPolicyConfig;
import io.helidon.security.providers.oidc.next.OidcFeature;
import io.helidon.security.providers.oidc.next.OidcProvider;
import io.helidon.security.providers.oidc.next.OidcProviderConfig;
import io.helidon.security.providers.oidc.next.OidcTenantConfig;
import io.helidon.webclient.api.HttpClientResponse;
import io.helidon.webclient.api.WebClient;
import io.helidon.webclient.api.WebClientConfig;
import io.helidon.webserver.WebServer;
import io.helidon.webserver.http.HttpRouting;
import io.helidon.webserver.security.SecurityFeature;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

@Execution(ExecutionMode.SAME_THREAD)
class OidcConformanceIT {
    private static final String BASIC_PLAN = "oidcc-client-basic-certification-test-plan";
    private static final String CONFIG_PLAN = "oidcc-client-config-certification-test-plan";
    private static final String REFRESH_PLAN = "oidcc-client-refreshtoken-test-plan";
    private static final String BACK_CHANNEL_PLAN = "oidcc-client-back-channel-logout-rp-basic";
    private static final String RP_INIT_PLAN = "oidcc-client-rp-initiated-logout-rp-basic";
    private static final Set<String> RP_INIT_MODULES = Set.of(
            "oidcc-client-test-rp-init-logout",
            "oidcc-client-test-rp-init-logout-other-state",
            "oidcc-client-test-rp-init-logout-no-state");
    private static final Set<String> BACK_CHANNEL_MODULES = Set.of(
            "oidcc-client-test-rp-backchannel-rpinitlogout",
            "oidcc-client-test-rp-backchannel-rpinitlogout-alg-none",
            "oidcc-client-test-rp-backchannel-rpinitlogout-no-event",
            "oidcc-client-test-rp-backchannel-rpinitlogout-with-nonce",
            "oidcc-client-test-rp-backchannel-rpinitlogout-wrong-alg",
            "oidcc-client-test-rp-backchannel-rpinitlogout-wrong-aud",
            "oidcc-client-test-rp-backchannel-rpinitlogout-wrong-event",
            "oidcc-client-test-rp-backchannel-rpinitlogout-wrong-iss");
    private static final Set<String> REFRESH_MODULES = Set.of(
            "oidcc-client-test-refresh-token",
            "oidcc-client-test-refresh-token-invalid-issuer",
            "oidcc-client-test-refresh-token-invalid-sub");
    private static final Set<String> BASIC_MODULES = Set.of(
            "oidcc-client-test", "oidcc-client-test-invalid-iss", "oidcc-client-test-missing-sub",
            "oidcc-client-test-invalid-aud", "oidcc-client-test-missing-iat",
            "oidcc-client-test-kid-absent-single-jwks", "oidcc-client-test-kid-absent-multiple-jwks",
            "oidcc-client-test-idtoken-sig-rs256", "oidcc-client-test-idtoken-sig-none",
            "oidcc-client-test-invalid-sig-rs256", "oidcc-client-test-userinfo-invalid-sub",
            "oidcc-client-test-nonce-invalid", "oidcc-client-test-scope-userinfo-claims",
            "oidcc-client-test-client-secret-basic");
    private static final Set<String> CONFIG_MODULES = Set.of(
            "oidcc-client-test-discovery-openid-config", "oidcc-client-test-discovery-jwks-uri-keys",
            "oidcc-client-test-discovery-issuer-mismatch", "oidcc-client-test-idtoken-sig-none",
            "oidcc-client-test-signing-key-rotation-just-before-signing",
            "oidcc-client-test-signing-key-rotation");
    private static final Set<String> REJECTION_MODULES = Set.of(
            "oidcc-client-test-invalid-iss", "oidcc-client-test-missing-sub", "oidcc-client-test-invalid-aud",
            "oidcc-client-test-missing-iat", "oidcc-client-test-idtoken-sig-none",
            "oidcc-client-test-invalid-sig-rs256", "oidcc-client-test-userinfo-invalid-sub",
            "oidcc-client-test-nonce-invalid",
            // OIDC Core 10.1 requires a JWS kid when the issuer publishes multiple keys. The official test permits
            // either rejecting that token or trying keys; this RP deliberately rejects the nonconforming token.
            "oidcc-client-test-kid-absent-multiple-jwks");

    private static OidcConformanceSuite suiteEnvironment;

    @BeforeAll
    static void startSuite() throws Exception {
        suiteEnvironment = OidcConformanceSuite.start();
        try {
            suiteEnvironment.createPlan(BASIC_PLAN);
            suiteEnvironment.createPlan(CONFIG_PLAN);
            suiteEnvironment.createPlan(REFRESH_PLAN);
            suiteEnvironment.createPlan(BACK_CHANNEL_PLAN);
            suiteEnvironment.createPlan(RP_INIT_PLAN);
        } catch (Exception | Error failure) {
            try {
                suiteEnvironment.close();
            } catch (Exception cleanupFailure) {
                failure.addSuppressed(cleanupFailure);
            }
            throw failure;
        }
    }

    @AfterAll
    static void stopSuite() throws Exception {
        if (suiteEnvironment != null) {
            suiteEnvironment.close();
        }
    }

    @TestFactory
    Stream<DynamicTest> basicRpPlan() throws Exception {
        return planTests(BASIC_PLAN, BASIC_MODULES);
    }

    @TestFactory
    Stream<DynamicTest> configRpPlan() throws Exception {
        return planTests(CONFIG_PLAN, CONFIG_MODULES);
    }

    @TestFactory
    Stream<DynamicTest> refreshRpPlan() throws Exception {
        return planTests(REFRESH_PLAN, REFRESH_MODULES);
    }

    @TestFactory
    Stream<DynamicTest> backChannelRpPlan() throws Exception {
        return planTests(BACK_CHANNEL_PLAN, BACK_CHANNEL_MODULES);
    }

    @TestFactory
    Stream<DynamicTest> rpInitiatedLogoutPlan() throws Exception {
        return planTests(RP_INIT_PLAN, RP_INIT_MODULES);
    }

    private static Stream<DynamicTest> planTests(String expectedPlan, Set<String> expectedModules) throws Exception {
        JsonObject plan;
        WebClientConfig webClient = suiteEnvironment.webClient();
        URI suite = suiteEnvironment.url();
        String planId = suiteEnvironment.planId(expectedPlan);
        WebClient suiteClient = WebClient.builder().from(webClient).build();
        List<String> modules;
        try {
            JsonObject officialPlan = getJson(suiteClient, suite.resolve("/api/plan/" + planId));
            assertThat(officialPlan.stringValue("planName").orElseThrow(), is(expectedPlan));
            plan = officialPlan.objectValue("config").orElseThrow();
            modules = officialPlan.arrayValue("modules").orElseThrow().values().stream()
                    .map(value -> value.asObject().stringValue("testModule").orElseThrow()).toList();
            assertThat(Set.copyOf(modules), is(expectedModules));
            assertThat(modules.size(), is(expectedModules.size()));
        } finally {
            suiteClient.closeResource();
        }
        return modules.stream()
                .map(module -> DynamicTest.dynamicTest(module,
                                                       () -> {
                                                           if (expectedPlan.equals(CONFIG_PLAN)) {
                                                               runConfigModule(module, suite, planId, plan, webClient);
                                                           } else if (expectedPlan.equals(REFRESH_PLAN)) {
                                                               runRefreshModule(module, suite, planId, plan, webClient);
                                                           } else if (expectedPlan.equals(BACK_CHANNEL_PLAN)
                                                                   || expectedPlan.equals(RP_INIT_PLAN)) {
                                                               runBackChannelModule(module, suite, planId, plan, webClient);
                                                           } else {
                                                               runModule(module, suite, planId, plan, webClient);
                                                           }
                                                       }));
    }

    private static void runBackChannelModule(String module, URI suite, String planId, JsonObject plan,
                                             WebClientConfig webClient) throws Exception {
        StartedModule started = startModule(module, suite, planId, webClient);
        JsonObject client = plan.objectValue("client").orElseThrow();
        URI callback = URI.create(client.stringValue("redirect_uri").orElseThrow());
        URI backChannel = URI.create(client.stringValue("backchannel_logout_uri").orElseThrow());
        URI postLogout = URI.create(client.stringValue("post_logout_redirect_uri").orElseThrow());
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .issuer(started.issuer())
                .clientId(client.stringValue("client_id").orElseThrow())
                .clientSecret(client.stringValue("client_secret").orElseThrow())
                .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .webClient(webClient)
                .authorizationCode(code -> code.scopes(List.of("openid", "profile", "email"))
                        .pkceS256SupportAssured(true))
                .logout(logout -> logout
                        .endSession(endSession -> endSession.postLogoutRedirectUri(postLogout))
                        .backChannel(config -> config.uri(backChannel)))
                .cookies(cookies -> cookies.password("local-only-conformance-cookie-protection-password"))
                .buildPrototype();
        OidcProvider provider = OidcProvider.create(OidcProviderConfig.builder()
                                                            .putTenant("default", tenant).buildPrototype());
        try {
            HttpRouting.Builder routing = HttpRouting.builder();
            OidcFeature.create(provider).setup(routing);
            OidcEndpointPolicyConfig cookiePolicy = OidcEndpointPolicyConfig.builder()
                    .acceptedCredentials(List.of(OidcEndpointCredential.AUTHENTICATION_COOKIE)).buildPrototype();
            routing.get("/resource", SecurityFeature.authenticate().customObject(cookiePolicy),
                        (_, response) -> response.send("authenticated"));
            routing.get(postLogout.getPath(), (_, response) -> response.send("logged out"));
            WebServer server = WebServer.builder().host("0.0.0.0").port(callback.getPort())
                    .tls(IdpResources.serverTls())
                    .addFeature(SecurityFeature.builder()
                                        .security(Security.builder().addProvider(provider, "oidc-next").build())
                                        .build())
                    .addRouting(routing).build().start();
            try (TestBrowser browser = new TestBrowser(webClient)) {
                BrowserResult login = browse(browser, callback, true);
                assertThat("OIDC login for " + module, login.statusCode(), is(Status.OK_200_CODE));
                assertThat("OIDC cookie for " + module, login.authenticated(), is(true));
                // These two RP-Initiated Logout variants are skipped unless the RP sends state. The local logout
                // endpoint accepts it as a query parameter, including when the same-origin request uses POST.
                URI logoutUri = RP_INIT_MODULES.contains(module)
                        ? callback.resolve("/oidc/logout?state=local-conformance-logout-state")
                        : callback.resolve("/oidc/logout");
                try (HttpClientResponse endSession = browser.post(logoutUri, Parameters.empty("logout"))) {
                    assertThat("RP-Initiated Logout redirect for " + module,
                               endSession.status().code(), is(Status.SEE_OTHER_303_CODE));
                    URI opLogout = URI.create(endSession.headers().first(HeaderNames.LOCATION).orElseThrow());
                    try (HttpClientResponse opResponse = browser.get(opLogout)) {
                        int code = opResponse.status().code();
                        assertThat("OP End Session response " + module,
                                   code == Status.FOUND_302_CODE || code == Status.SEE_OTHER_303_CODE,
                                   is(true));
                        URI redirected = URI.create(opResponse.headers().first(HeaderNames.LOCATION).orElseThrow());
                        try (HttpClientResponse callbackResponse = browser.get(redirected)) {
                            assertThat(callbackResponse.status().code(), is(Status.OK_200_CODE));
                        }
                    }
                }
                assertOfficialPassed(module, suite, started.id(), webClient);
            } finally {
                server.stop();
            }
        } finally {
            provider.close();
        }
    }

    private static void runRefreshModule(String module, URI suite, String planId, JsonObject plan,
                                         WebClientConfig webClient) throws Exception {
        StartedModule started = startModule(module, suite, planId, webClient);
        JsonObject client = plan.objectValue("client").orElseThrow();
        URI callback = URI.create(client.stringValue("redirect_uri").orElseThrow());
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .issuer(started.issuer())
                .clientId(client.stringValue("client_id").orElseThrow())
                .clientSecret(client.stringValue("client_secret").orElseThrow())
                .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .webClient(webClient)
                .authorizationCode(code -> code.scopes(List.of("openid", "profile", "email"))
                        .pkceS256SupportAssured(true))
                .userInfo(info -> info.attributeClaimPaths(List.of("email", "preferred_username")))
                .cookies(cookies -> cookies.password("local-only-conformance-cookie-protection-password"))
                .buildPrototype();
        OidcProvider provider = OidcProvider.create(OidcProviderConfig.builder()
                                                            .putTenant("default", tenant).buildPrototype());
        try {
            HttpRouting.Builder routing = HttpRouting.builder();
            OidcFeature.create(provider).setup(routing);
            OidcEndpointPolicyConfig cookiePolicy = OidcEndpointPolicyConfig.builder()
                    .acceptedCredentials(List.of(OidcEndpointCredential.AUTHENTICATION_COOKIE)).buildPrototype();
            routing.get("/resource", SecurityFeature.authenticate().customObject(cookiePolicy),
                        (_, response) -> response.send("authenticated"));
            // This is a test-only, same-origin POST action. The library exposes no refresh HTTP endpoint.
            routing.post("/refresh", SecurityFeature.authenticate().customObject(cookiePolicy), (request, response) -> {
                String origin = callback.getScheme() + "://" + callback.getAuthority();
                if (!origin.equals(request.headers().first(HeaderNames.ORIGIN).orElse(""))) {
                    response.status(Status.FORBIDDEN_403).send();
                    return;
                }
                SecurityContext security = Contexts.context().flatMap(context -> context.get(SecurityContext.class))
                        .orElseThrow();
                AuthenticationResponse refreshed = provider.refresh(security);
                refreshed.responseHeaders().getOrDefault(HeaderNames.SET_COOKIE.defaultCase(), List.of())
                        .stream().map(SetCookie::parse).forEach(response.headers()::addCookie);
                if (refreshed.status() == SecurityResponse.SecurityStatus.SUCCESS) {
                    response.send("refreshed");
                } else {
                    response.status(refreshed.statusCode().orElse(Status.SERVICE_UNAVAILABLE_503_CODE))
                            .send("refresh failed");
                }
            });
            WebServer server = WebServer.builder().host("127.0.0.1").port(callback.getPort())
                    .tls(IdpResources.serverTls())
                    .addFeature(SecurityFeature.builder()
                                        .security(Security.builder().addProvider(provider, "oidc-next").build())
                                        .build())
                    .addRouting(routing).build().start();
            try (TestBrowser browser = new TestBrowser(webClient)) {
                BrowserResult login = browse(browser, callback, true);
                assertThat("OIDC login for " + module, login.statusCode(), is(Status.OK_200_CODE));
                assertThat("OIDC cookie for " + module, login.authenticated(), is(true));
                boolean valid = module.equals("oidcc-client-test-refresh-token");
                try (HttpClientResponse refreshed = browser.post(callback.resolve("/refresh"), Parameters.empty("refresh"))) {
                    assertThat("Refresh response for " + module,
                               refreshed.status().code(),
                               is(valid ? Status.OK_200_CODE : Status.SERVICE_UNAVAILABLE_503_CODE));
                }
                assertThat("OIDC cookie after refresh for " + module,
                           browser.cookieValue(OidcCookieConfig.create().localAuthenticationCookieName()).isPresent(),
                           is(true));
                assertOfficialPassed(module, suite, started.id(), webClient);
            } finally {
                server.stop();
            }
        } finally {
            provider.close();
        }
    }

    private static void runModule(String module, URI suite, String planId, JsonObject plan, WebClientConfig webClient)
            throws Exception {
        StartedModule started = startModule(module, suite, planId, webClient);
        BrowserResult browserResult = authenticate(started.issuer(), plan, webClient);
        boolean rejected = REJECTION_MODULES.contains(module);
        assertThat("Local response for " + module + " at " + browserResult.path() + ": " + browserResult.body(),
                   browserResult.statusCode(), is(rejected ? Status.BAD_GATEWAY_502_CODE : Status.OK_200_CODE));
        assertThat("Local authentication cookie for " + module, browserResult.authenticated(), is(!rejected));
        if (!rejected) {
            assertThat("Protected resource response for " + module, browserResult.body(), is("authenticated"));
        }
        String expectedResult = module.equals("oidcc-client-test-idtoken-sig-none") ? "SKIPPED" : "PASSED";
        assertThat("Official RP result for " + module + " (" + started.id() + ")",
                   officialResult(suite, started.id(), webClient), is(expectedResult));
    }

    private static void runConfigModule(String module,
                                        URI suite,
                                        String planId,
                                        JsonObject plan,
                                        WebClientConfig webClient) throws Exception {
        switch (module) {
        case "oidcc-client-test-idtoken-sig-none", "oidcc-client-test-signing-key-rotation-just-before-signing" ->
            runModule(module, suite, planId, plan, webClient);
        case "oidcc-client-test-discovery-openid-config" -> {
            StartedModule started = startModule(module, suite, planId, webClient);
            // This module finishes on discovery; do not send the browser to an authorization endpoint after it closes.
            BrowserResult response = authenticateRepeated(started.issuer(), plan, webClient, 1, false, true).getFirst();
            assertThat(response.statusCode(), is(Status.SEE_OTHER_303_CODE));
            assertThat(response.authenticated(), is(false));
            assertOfficialPassed(module, suite, started.id(), webClient);
        }
        case "oidcc-client-test-discovery-jwks-uri-keys" -> {
            StartedModule started = startModule(module, suite, planId, webClient);
            // The suite finishes as soon as it sees a JWKS request. Optional UserInfo after that would be too late.
            BrowserResult response = authenticateRepeated(started.issuer(), plan, webClient, 1, true, false).getFirst();
            assertThat("Login using discovered JWKS: " + response.body(), response.statusCode(),
                       is(Status.OK_200_CODE));
            assertThat(response.authenticated(), is(true));
            assertOfficialPassed(module, suite, started.id(), webClient);
        }
        case "oidcc-client-test-discovery-issuer-mismatch" -> {
            StartedModule started = startModule(module, suite, planId, webClient);
            BrowserResult response = authenticateRepeated(started.issuer(), plan, webClient, 1, false, true).getFirst();
            assertThat("Mismatched discovery issuer must fail closed", response.statusCode(),
                       is(Status.SERVICE_UNAVAILABLE_503_CODE));
            assertThat(response.authenticated(), is(false));
            assertOfficialPassed(module, suite, started.id(), webClient);
        }
        case "oidcc-client-test-signing-key-rotation" -> {
            StartedModule started = startModule(module, suite, planId, webClient);
            List<BrowserResult> logins = authenticateRepeated(started.issuer(), plan, webClient, 2, true, true);
            for (BrowserResult login : logins) {
                assertThat("Login after signing key rotation: " + login.body(), login.statusCode(),
                           is(Status.OK_200_CODE));
                assertThat(login.authenticated(), is(true));
            }
            assertOfficialPassed(module, suite, started.id(), webClient);
        }
        default -> throw new IllegalArgumentException("Unknown Configuration RP module: " + module);
        }
    }

    private static void assertOfficialPassed(String module, URI suite, String testId, WebClientConfig webClient)
            throws Exception {
        assertThat("Official RP result for " + module + " (" + testId + ")",
                   officialResult(suite, testId, webClient), is("PASSED"));
    }

    private static StartedModule startModule(String module, URI suite, String planId, WebClientConfig webClient)
            throws Exception {
        WebClient suiteClient = WebClient.builder().from(webClient).build();
        try {
            URI startUri = suite.resolve("/api/runner?test=" + module + "&plan=" + planId);
            String testId;
            try (HttpClientResponse response = suiteClient.post().uri(startUri)
                    .header(HeaderValues.CONTENT_TYPE_JSON).request()) {
                assertThat("Starting " + module, response.status().code(), is(Status.CREATED_201_CODE));
                testId = response.as(JsonObject.class).stringValue("id").orElseThrow();
            }
            return new StartedModule(testId, awaitIssuer(suiteClient, suite, testId));
        } finally {
            suiteClient.closeResource();
        }
    }

    private static String officialResult(URI suite, String testId, WebClientConfig webClient) throws Exception {
        WebClient suiteClient = WebClient.builder().from(webClient).build();
        try {
            return awaitResult(suiteClient, suite, testId);
        } finally {
            suiteClient.closeResource();
        }
    }

    private static BrowserResult authenticate(String issuer, JsonObject plan, WebClientConfig webClient)
            throws Exception {
        return authenticateRepeated(issuer, plan, webClient, 1, true, true).getFirst();
    }

    private static List<BrowserResult> authenticateRepeated(String issuer,
                                                             JsonObject plan,
                                                             WebClientConfig webClient,
                                                             int visits,
                                                             boolean followRedirects,
                                                             boolean retrieveUserInfo) throws Exception {
        JsonObject client = plan.objectValue("client").orElseThrow();
        URI callback = URI.create(client.stringValue("redirect_uri").orElseThrow());

        OidcTenantConfig.Builder tenant = OidcTenantConfig.builder()
                .issuer(issuer)
                .clientId(client.stringValue("client_id").orElseThrow())
                .clientSecret(client.stringValue("client_secret").orElseThrow())
                .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .webClient(webClient)
                // This suite verifies code_verifier when a code_challenge was supplied, but does not advertise
                // code_challenge_methods_supported. The explicit assurance is limited to this test issuer.
                .authorizationCode(code -> code.scopes(List.of("openid", "profile", "email"))
                        .pkceS256SupportAssured(true))
                .cookies(cookies -> cookies.password("local-only-conformance-cookie-protection-password"));
        if (retrieveUserInfo) {
            tenant.userInfo(info -> info.attributeClaimPaths(List.of("email", "preferred_username")));
        }
        OidcProvider provider = OidcProvider.create(
                OidcProviderConfig.builder().putTenant("default", tenant.buildPrototype()).buildPrototype());
        try {
            HttpRouting.Builder routing = HttpRouting.builder();
            OidcFeature.create(provider).setup(routing);
            OidcEndpointPolicyConfig cookiePolicy = OidcEndpointPolicyConfig.builder()
                    .acceptedCredentials(List.of(OidcEndpointCredential.AUTHENTICATION_COOKIE)).buildPrototype();
            routing.get("/resource", SecurityFeature.authenticate().customObject(cookiePolicy),
                        (_, response) -> response.send("authenticated"));
            WebServer server = WebServer.builder().host("127.0.0.1").port(callback.getPort())
                    .tls(IdpResources.serverTls())
                    .addFeature(SecurityFeature.builder()
                                        .security(Security.builder().addProvider(provider, "oidc-next").build())
                                        .build())
                    .addRouting(routing).build().start();
            try {
                List<BrowserResult> results = new ArrayList<>(visits);
                for (int i = 0; i < visits; i++) {
                    // A fresh browser starts the next login while the RP and its JWKS manager remain running.
                    try (TestBrowser browser = new TestBrowser(webClient)) {
                        results.add(browse(browser, callback, followRedirects));
                    }
                }
                return List.copyOf(results);
            } finally {
                server.stop();
            }
        } finally {
            provider.close();
        }
    }

    private static BrowserResult browse(TestBrowser browser, URI callback, boolean followRedirects) throws Exception {
        URI uri = callback.resolve("/resource");
        for (int redirects = 0; redirects < 12; redirects++) {
            try (HttpClientResponse response = browser.get(uri)) {
                if (!followRedirects || response.status().code() < 300 || response.status().code() >= 400) {
                    String cookieName = OidcCookieConfig.create().localAuthenticationCookieName();
                    return new BrowserResult(response.status().code(), uri.getPath(),
                                             browser.cookieValue(cookieName).isPresent(),
                                             response.entity().asOptional(String.class).orElse(""));
                }
                uri = uri.resolve(response.headers().first(HeaderNames.LOCATION).orElseThrow());
            }
        }
        throw new IllegalStateException("Conformance login exceeded the redirect limit");
    }

    private static String awaitIssuer(WebClient client, URI suite, String testId) throws Exception {
        for (int attempt = 0; attempt < 50; attempt++) {
            String status = getJson(client, suite.resolve("/api/info/" + testId))
                    .stringValue("status").orElse("");
            if (status.equals("WAITING")) {
                JsonObject runner = getJson(client, suite.resolve("/api/runner/" + testId));
                var issuer = runner.objectValue("exposed").flatMap(values -> values.stringValue("issuer"));
                if (issuer.isPresent()) {
                    return issuer.orElseThrow();
                }
            } else if (status.equals("FINISHED") || status.equals("INTERRUPTED")) {
                throw new IllegalStateException("Official suite stopped during setup for " + testId);
            }
            Thread.sleep(100);
        }
        throw new IllegalStateException("Official suite did not reach WAITING with an issuer for " + testId);
    }

    private static String awaitResult(WebClient client, URI suite, String testId) throws Exception {
        for (int attempt = 0; attempt < 100; attempt++) {
            JsonObject info = getJson(client, suite.resolve("/api/info/" + testId));
            String status = info.stringValue("status").orElse("");
            if (status.equals("FINISHED") || status.equals("INTERRUPTED")) {
                return info.stringValue("result").orElse(status);
            }
            Thread.sleep(200);
        }
        throw new IllegalStateException("Official suite did not finish test " + testId);
    }

    private static JsonObject getJson(WebClient client, URI uri) {
        try (HttpClientResponse response = client.get().uri(uri).request()) {
            assertThat("Official suite API at " + uri.getPath(), response.status().code(), is(Status.OK_200_CODE));
            return response.as(JsonObject.class);
        }
    }

    private record StartedModule(String id, String issuer) {
    }

    private record BrowserResult(int statusCode, String path, boolean authenticated, String body) {
    }
}
