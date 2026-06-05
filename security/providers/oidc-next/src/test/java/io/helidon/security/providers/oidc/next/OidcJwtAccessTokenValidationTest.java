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
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.ArrayDeque;
import java.util.List;
import java.util.Optional;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.stream.IntStream;

import io.helidon.common.configurable.Resource;
import io.helidon.http.HeaderName;
import io.helidon.http.HeaderNames;
import io.helidon.http.HeaderValues;
import io.helidon.json.JsonObject;
import io.helidon.security.AuthenticationResponse;
import io.helidon.security.Grant;
import io.helidon.security.Role;
import io.helidon.security.SecurityEnvironment;
import io.helidon.security.SecurityResponse;
import io.helidon.security.Subject;
import io.helidon.security.jwt.Jwt;
import io.helidon.security.jwt.SignedJwt;
import io.helidon.security.jwt.jwk.Jwk;
import io.helidon.security.jwt.jwk.JwkKeys;
import io.helidon.security.jwt.jwk.JwkOctet;
import io.helidon.security.jwt.jwk.JwkRSA;
import io.helidon.security.providers.common.TokenCredential;
import io.helidon.webclient.api.WebClientConfig;
import io.helidon.webserver.http.HttpRouting;
import io.helidon.webserver.testing.junit5.ServerTest;
import io.helidon.webserver.testing.junit5.SetUpRoute;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ServerTest
class OidcJwtAccessTokenValidationTest {
    private static final URI ISSUER = URI.create("https://issuer.example");
    private static final String AUDIENCE = "api://default";
    private static final String SUBJECT = "user1-id";
    private static final String USERNAME = "user1";
    private static final String TENANT_WEBCLIENT_HEADER = "X-Tenant-WebClient";
    private static final String TENANT_WEBCLIENT_HEADER_VALUE = "configured";
    private static final HeaderName TENANT_WEBCLIENT_HEADER_NAME = HeaderNames.create(TENANT_WEBCLIENT_HEADER);
    private static final URI MISSING_JWKS_URI = URI.create("file:///tmp/oidc-next-missing-jwks.json");
    private static final Instant TEST_INSTANT = Instant.parse("2026-05-21T00:00:00Z");
    private static final AtomicInteger wellKnownRequests = new AtomicInteger();
    private static final AtomicInteger remoteJwkSetRequests = new AtomicInteger();
    private static final AtomicReference<Queue<String>> remoteJwkSetResponses =
            new AtomicReference<>(new ArrayDeque<>());
    private static final AtomicReference<String> providerMetadata = new AtomicReference<>();
    private static final AtomicReference<String> wellKnownWebClientHeader = new AtomicReference<>();
    private static final AtomicReference<String> remoteJwkSetWebClientHeader = new AtomicReference<>();
    private static final AtomicReference<CountDownLatch> remoteJwkSetRequestLatch = new AtomicReference<>();
    private static final AtomicReference<CountDownLatch> remoteJwkSetResponseLatch = new AtomicReference<>();

    private static JwkKeys signKeys;
    private static URI jwksUri;
    private static String verifyJwkSet;

    private URI remoteJwksUri;
    private URI wellKnownUri;
    @TempDir
    private Path tempDir;

    @BeforeAll
    static void initClass() throws Exception {
        signKeys = JwkKeys.builder()
                .resource(Resource.create("oidc-next-sign-jwk.json"))
                .build();
        verifyJwkSet = Resource.create("oidc-next-verify-jwk.json").string();
        jwksUri = OidcJwtAccessTokenValidationTest.class.getClassLoader()
                .getResource("oidc-next-verify-jwk.json")
                .toURI();
    }

    @SetUpRoute
    static void routing(HttpRouting.Builder routing) {
        routing.get("/.well-known/openid-configuration", (request, response) -> {
            wellKnownRequests.incrementAndGet();
            wellKnownWebClientHeader.set(request.headers().first(TENANT_WEBCLIENT_HEADER_NAME).orElse(""));
            response.header(HeaderValues.CONTENT_TYPE_JSON)
                    .send(providerMetadata.get());
        });
        routing.get("/jwks", (request, response) -> {
            remoteJwkSetRequests.incrementAndGet();
            remoteJwkSetWebClientHeader.set(request.headers().first(TENANT_WEBCLIENT_HEADER_NAME).orElse(""));
            CountDownLatch requestLatch = remoteJwkSetRequestLatch.get();
            if (requestLatch != null) {
                requestLatch.countDown();
            }
            CountDownLatch responseLatch = remoteJwkSetResponseLatch.get();
            if (responseLatch != null) {
                try {
                    if (!responseLatch.await(5, TimeUnit.SECONDS)) {
                        throw new IllegalStateException("Timed out waiting to release JWK Set response");
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException("Interrupted while waiting to release JWK Set response", e);
                }
            }
            String jwkSet = remoteJwkSetResponses.get().poll();
            response.header(HeaderValues.CONTENT_TYPE_JSON)
                    .send(jwkSet == null ? emptyJwkSet() : jwkSet);
        });
    }

    @BeforeEach
    void setUp(URI serverUri) {
        remoteJwksUri = serverUri.resolve("jwks");
        wellKnownUri = serverUri.resolve(".well-known/openid-configuration");
        wellKnownRequests.set(0);
        remoteJwkSetRequests.set(0);
        wellKnownWebClientHeader.set("");
        remoteJwkSetWebClientHeader.set("");
        remoteJwkSetResponses.set(new ArrayDeque<>(List.of(verifyJwkSet)));
        providerMetadata.set(JsonObject.builder()
                .set("issuer", ISSUER.toString())
                .set("jwks_uri", remoteJwksUri.toString())
                .build()
                .toString());
        remoteJwkSetRequestLatch.set(null);
        remoteJwkSetResponseLatch.set(null);
    }

    @Test
    void validJwtAccessTokenAuthenticatesSubject() {
        String token = signedToken(it -> it.email("user1@example.org")
                .addUserGroup("admin")
                .addUserGroup("auditor")
                .addScope("resource.read")
                .addScope("resource.write"));

        AuthenticationResponse response = authenticate(provider(), token);

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        Subject subject = response.user().orElseThrow();
        assertThat(subject.principal().id(), is(SUBJECT));
        assertThat(subject.principal().getName(), is(USERNAME));
        assertThat(subject.principal().abacAttributeRaw("email"), is("user1@example.org"));
        assertThat(subject.grants(Role.class).stream().map(Role::getName).toList(), is(List.of("admin", "auditor")));
        assertThat(subject.grantsByType("scope").stream().map(Grant::getName).toList(),
                   is(List.of("resource.read", "resource.write")));

        TokenCredential credential = subject.publicCredential(TokenCredential.class).orElseThrow();
        assertThat(credential.token(), is(token));
        assertThat(credential.getIssuer().orElse(""), is(ISSUER.toString()));
        assertThat(credential.getIssueTime().isPresent(), is(true));
        assertThat(credential.getExpTime().isPresent(), is(true));
        assertThat(credential.getTokenInstance(Jwt.class).isPresent(), is(true));
        assertThat(credential.getTokenInstance(SignedJwt.class).isPresent(), is(true));
    }

    @Test
    void customSubjectMappingAppliesToJwtAccessToken() {
        String token = signedToken(it -> it
                .addPayloadClaim("tenant_user", "tenant-user-id")
                .addPayloadClaim("display_name", "Tenant User")
                .addPayloadClaim("realm_access", JsonObject.builder()
                        .setStrings("roles", List.of("realm-admin", "realm-auditor"))
                        .build())
                .addPayloadClaim("scp", List.of("message:read", "message:write")));

        AuthenticationResponse response = authenticate(provider(true, true, jwksUri, tenant -> tenant
                .subjectMapping(mapping -> mapping
                        .principalIdClaimPaths(List.of("tenant_user"))
                        .principalNameClaimPaths(List.of("display_name"))
                        .roleClaimPaths(List.of("realm_access.roles"))
                        .scopeClaimPaths(List.of("scp")))), token);

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        Subject subject = response.user().orElseThrow();
        assertThat(subject.principal().id(), is("tenant-user-id"));
        assertThat(subject.principal().getName(), is("Tenant User"));
        assertThat(subject.grants(Role.class).stream().map(Role::getName).toList(),
                   is(List.of("realm-admin", "realm-auditor")));
        assertThat(subject.grantsByType("scope").stream().map(Grant::getName).toList(),
                   is(List.of("message:read", "message:write")));
    }

    @Test
    void standardScopeClaimMustBeStringForJwtAccessToken() {
        String token = signedToken(it -> it.addPayloadClaim("scope", List.of("resource.read")));

        AuthenticationResponse response = authenticate(provider(), token);

        assertInvalidToken(response, "Bearer Token JWT claims are invalid");
    }

    @Test
    void standardScopeClaimRejectsNonSpaceDelimiterForJwtAccessToken() {
        String token = signedToken(it -> it.addPayloadClaim("scope", "resource.read\tresource.write"));

        AuthenticationResponse response = authenticate(provider(), token);

        assertInvalidToken(response, "Bearer Token JWT claims are invalid");
    }

    @Test
    void customScopeArrayValuesMustBeScopeTokensForJwtAccessToken() {
        String token = signedToken(it -> it.addPayloadClaim("scp", List.of("resource.read resource.write")));

        AuthenticationResponse response = authenticate(provider(true, true, jwksUri, tenant -> tenant
                .subjectMapping(mapping -> mapping.scopeClaimPaths(List.of("scp")))), token);

        assertInvalidToken(response, "Bearer Token JWT claims are invalid");
    }

    @Test
    void idcsIamStyleSubjectMappingSupportsCustomClaimAbac() {
        String token = signedToken(it -> it
                .preferredUsername("mcp-user")
                .addScope("mcp.tools.write")
                .addPayloadClaim("department", "finance")
                .addPayloadClaim("groups", List.of("mcp_user"))
                .addPayloadClaim("idcs_groups", "mcp_admin")
                .addPayloadClaim("iam", JsonObject.builder()
                        .setStrings("groups", List.of("mcp_tools"))
                        .build())
                .addPayloadClaim("scp", List.of("mcp.tools.read")));

        AuthenticationResponse response = authenticate(provider(true, true, jwksUri, tenant -> tenant
                .subjectMapping(mapping -> mapping
                        .principalIdClaimPaths(List.of("sub"))
                        .principalNameClaimPaths(List.of("preferred_username", "email"))
                        .roleClaimPaths(List.of("groups", "idcs_groups", "iam.groups"))
                        .scopeClaimPaths(List.of("scope", "scp"))
                        .scopeGrantsEnabled(true))), token);

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        Subject subject = response.user().orElseThrow();
        assertThat(subject.principal().id(), is(SUBJECT));
        assertThat(subject.principal().getName(), is("mcp-user"));
        assertThat(subject.principal().abacAttributeRaw("department"), is("finance"));
        assertThat(subject.grants(Role.class).stream().map(Role::getName).toList(),
                   is(List.of("mcp_user", "mcp_admin", "mcp_tools")));
        assertThat(subject.grantsByType("scope").stream().map(Grant::getName).toList(),
                   is(List.of("mcp.tools.write", "mcp.tools.read")));
    }

    @Test
    void customPrincipalIdClaimIsRequiredForJwtAccessToken() {
        String token = signedToken(it -> { });

        AuthenticationResponse response = authenticate(provider(true, true, jwksUri, tenant -> tenant
                .subjectMapping(mapping -> mapping.principalIdClaimPaths(List.of("tenant_user")))), token);

        assertInvalidToken(response, "Bearer Token JWT has no principal claim");
    }

    @Test
    void principalIdClaimMustBeScalarForJwtAccessToken() {
        String token = signedToken(it -> it.addPayloadClaim("tenant_user", List.of("first-user", "second-user")));

        AuthenticationResponse response = authenticate(provider(true, true, jwksUri, tenant -> tenant
                .subjectMapping(mapping -> mapping.principalIdClaimPaths(List.of("tenant_user")))), token);

        assertInvalidToken(response, "Bearer Token JWT has no principal claim");
    }

    @Test
    void scopeGrantsCanBeDisabledForJwtAccessToken() {
        String token = signedToken(it -> it
                .addScope("resource.read")
                .addPayloadClaim("scp", List.of("resource.write")));

        AuthenticationResponse response = authenticate(provider(true, true, jwksUri, tenant -> tenant
                .subjectMapping(mapping -> mapping
                        .scopeClaimPaths(List.of("scope", "scp"))
                        .scopeGrantsEnabled(false))), token);

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.user().orElseThrow().grantsByType("scope").isEmpty(), is(true));
    }

    @Test
    void remoteJwksEndpointAuthenticatesSubject() {
        String token = signedToken(it -> { });

        AuthenticationResponse response = authenticate(provider(true, true, remoteJwksUri), token);

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(remoteJwkSetRequests.get(), is(1));
    }

    @Test
    void wellKnownMetadataJwksEndpointAuthenticatesSubject() {
        String token = signedToken(it -> { });

        AuthenticationResponse response = authenticate(
                wellKnownProvider(tenant -> tenant.webClient(tenantWebClient())),
                token);

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(wellKnownRequests.get(), is(1));
        assertThat(remoteJwkSetRequests.get(), is(1));
        assertThat(wellKnownWebClientHeader.get(), is(TENANT_WEBCLIENT_HEADER_VALUE));
        assertThat(remoteJwkSetWebClientHeader.get(), is(TENANT_WEBCLIENT_HEADER_VALUE));
    }

    @Test
    void unknownKeyIdRefreshesJwkSetAfterInterval() throws Exception {
        MutableClock clock = MutableClock.create(TEST_INSTANT);
        Path jwkSet = tempDir.resolve("jwks.json");
        Files.writeString(jwkSet, emptyJwkSet());
        OidcJwkSetManager manager = jwkSetManager(jwkSet.toUri(), clock);

        assertThat(manager.jwkKeys(Optional.of("verify-rsa")).forKeyId("verify-rsa").isPresent(), is(false));
        Files.writeString(jwkSet, verifyJwkSet);
        clock.advance(OidcJwkSetConfig.create().unknownKeyIdRefreshInterval());

        assertThat(manager.jwkKeys(Optional.of("verify-rsa")).forKeyId("verify-rsa").isPresent(), is(true));
    }

    @Test
    void unknownKeyIdRefreshUsesConfiguredInterval() throws Exception {
        MutableClock clock = MutableClock.create(TEST_INSTANT);
        Path jwkSet = tempDir.resolve("jwks.json");
        Files.writeString(jwkSet, emptyJwkSet());
        OidcJwkSetConfig config = OidcJwkSetConfig.builder()
                .unknownKeyIdRefreshInterval(Duration.ofSeconds(30))
                .buildPrototype();
        OidcJwkSetManager manager = jwkSetManager(jwkSet.toUri(), clock, config);

        assertThat(manager.jwkKeys(Optional.of("verify-rsa")).forKeyId("verify-rsa").isPresent(), is(false));
        Files.writeString(jwkSet, verifyJwkSet);
        clock.advance(Duration.ofSeconds(29));
        assertThat(manager.jwkKeys(Optional.of("verify-rsa")).forKeyId("verify-rsa").isPresent(), is(false));
        clock.advance(Duration.ofSeconds(1));
        assertThat(manager.jwkKeys(Optional.of("verify-rsa")).forKeyId("verify-rsa").isPresent(), is(true));
    }

    @Test
    void unknownKeyIdRefreshCanBeDisabled() throws Exception {
        MutableClock clock = MutableClock.create(TEST_INSTANT);
        Path jwkSet = tempDir.resolve("jwks.json");
        Files.writeString(jwkSet, emptyJwkSet());
        OidcJwkSetConfig config = OidcJwkSetConfig.builder()
                .unknownKeyIdRefreshEnabled(false)
                .buildPrototype();
        OidcJwkSetManager manager = jwkSetManager(jwkSet.toUri(), clock, config);

        assertThat(manager.jwkKeys(Optional.of("verify-rsa")).forKeyId("verify-rsa").isPresent(), is(false));
        Files.writeString(jwkSet, verifyJwkSet);
        clock.advance(OidcJwkSetConfig.create().unknownKeyIdRefreshInterval());

        assertThat(manager.jwkKeys(Optional.of("verify-rsa")).forKeyId("verify-rsa").isPresent(), is(false));
    }

    @Test
    void unknownKeyIdRefreshIsRateLimited() throws Exception {
        MutableClock clock = MutableClock.create(TEST_INSTANT);
        Path jwkSet = tempDir.resolve("jwks.json");
        Files.writeString(jwkSet, emptyJwkSet());
        OidcJwkSetManager manager = jwkSetManager(jwkSet.toUri(), clock);

        manager.jwkKeys();
        clock.advance(OidcJwkSetConfig.create().unknownKeyIdRefreshInterval());
        assertThat(manager.jwkKeys(Optional.of("verify-rsa")).forKeyId("verify-rsa").isPresent(), is(false));
        Files.writeString(jwkSet, verifyJwkSet);

        assertThat(manager.jwkKeys(Optional.of("verify-rsa")).forKeyId("verify-rsa").isPresent(), is(false));
        clock.advance(OidcJwkSetConfig.create().unknownKeyIdRefreshInterval());
        assertThat(manager.jwkKeys(Optional.of("verify-rsa")).forKeyId("verify-rsa").isPresent(), is(true));
    }

    @Test
    void staleUnknownKeyIdRefreshDoesNotRateLimitDifferentKeyId() throws Exception {
        MutableClock clock = MutableClock.create(TEST_INSTANT);
        Path jwkSet = tempDir.resolve("jwks.json");
        Files.writeString(jwkSet, emptyJwkSet());
        OidcJwkSetManager manager = jwkSetManager(jwkSet.toUri(), clock);

        manager.jwkKeys();
        clock.advance(OidcJwkSetConfig.create().unknownKeyIdRefreshInterval());
        assertThat(manager.jwkKeys(Optional.of("bogus")).forKeyId("bogus").isPresent(), is(false));
        Files.writeString(jwkSet, verifyJwkSet);

        assertThat(manager.jwkKeys(Optional.of("verify-rsa")).forKeyId("verify-rsa").isPresent(), is(true));
    }

    @Test
    void refreshIntervalReloadsCachedJwkSet() throws Exception {
        MutableClock clock = MutableClock.create(TEST_INSTANT);
        Path jwkSet = tempDir.resolve("jwks.json");
        Files.writeString(jwkSet, emptyJwkSet());
        OidcJwkSetConfig config = OidcJwkSetConfig.builder()
                .refreshInterval(Duration.ofSeconds(30))
                .buildPrototype();
        OidcJwkSetManager manager = jwkSetManager(jwkSet.toUri(), clock, config);

        assertThat(manager.jwkKeys().forKeyId("verify-rsa").isPresent(), is(false));
        Files.writeString(jwkSet, verifyJwkSet);
        clock.advance(Duration.ofSeconds(29));
        assertThat(manager.jwkKeys().forKeyId("verify-rsa").isPresent(), is(false));
        clock.advance(Duration.ofSeconds(1));
        assertThat(manager.jwkKeys().forKeyId("verify-rsa").isPresent(), is(true));
    }

    @Test
    void failedRefreshUsesStaleJwkSetWhenConfigured() throws Exception {
        MutableClock clock = MutableClock.create(TEST_INSTANT);
        Path jwkSet = tempDir.resolve("jwks.json");
        Files.writeString(jwkSet, verifyJwkSet);
        OidcJwkSetConfig config = OidcJwkSetConfig.builder()
                .refreshInterval(Duration.ofSeconds(30))
                .buildPrototype();
        OidcJwkSetManager manager = jwkSetManager(jwkSet.toUri(), clock, config);

        assertThat(manager.jwkKeys().forKeyId("verify-rsa").isPresent(), is(true));
        Files.delete(jwkSet);
        clock.advance(Duration.ofSeconds(30));

        assertThat(manager.jwkKeys().forKeyId("verify-rsa").isPresent(), is(true));
    }

    @Test
    void failedRefreshFailsWhenStaleJwkSetIsDisabled() throws Exception {
        MutableClock clock = MutableClock.create(TEST_INSTANT);
        Path jwkSet = tempDir.resolve("jwks.json");
        Files.writeString(jwkSet, verifyJwkSet);
        OidcJwkSetConfig config = OidcJwkSetConfig.builder()
                .refreshInterval(Duration.ofSeconds(30))
                .staleOnError(false)
                .buildPrototype();
        OidcJwkSetManager manager = jwkSetManager(jwkSet.toUri(), clock, config);

        assertThat(manager.jwkKeys().forKeyId("verify-rsa").isPresent(), is(true));
        Files.delete(jwkSet);
        clock.advance(Duration.ofSeconds(30));

        assertThrows(IllegalStateException.class, manager::jwkKeys);
        assertThrows(IllegalStateException.class, manager::jwkKeys);
        Files.writeString(jwkSet, verifyJwkSet);
        clock.advance(Duration.ofSeconds(30));
        assertThat(manager.jwkKeys().forKeyId("verify-rsa").isPresent(), is(true));
    }

    @Test
    void concurrentColdJwkSetLoadIsSingleFlight() throws Exception {
        int threads = 32;
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch requestStarted = new CountDownLatch(1);
        CountDownLatch releaseResponse = new CountDownLatch(1);
        remoteJwkSetRequestLatch.set(requestStarted);
        remoteJwkSetResponseLatch.set(releaseResponse);
        remoteJwkSetResponses.set(new ConcurrentLinkedQueue<>(List.of(verifyJwkSet)));
        OidcJwkSetManager manager = jwkSetManager(remoteJwksUri, Clock.systemUTC());

        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<JwkKeys>> futures = IntStream.range(0, threads)
                    .mapToObj(ignored -> executor.submit(() -> {
                        assertTrue(start.await(5, TimeUnit.SECONDS));
                        return manager.jwkKeys();
                    }))
                    .toList();

            start.countDown();
            assertTrue(requestStarted.await(5, TimeUnit.SECONDS));
            releaseResponse.countDown();
            for (Future<JwkKeys> future : futures) {
                assertThat(future.get().forKeyId("verify-rsa").isPresent(), is(true));
            }
        }

        assertThat(remoteJwkSetRequests.get(), is(1));
    }

    @Test
    void concurrentRefreshIntervalReloadIsSingleFlight() throws Exception {
        int threads = 32;
        MutableClock clock = MutableClock.create(TEST_INSTANT);
        OidcJwkSetConfig config = OidcJwkSetConfig.builder()
                .refreshInterval(Duration.ofSeconds(1))
                .buildPrototype();
        remoteJwkSetResponses.set(new ConcurrentLinkedQueue<>(List.of(emptyJwkSet(), verifyJwkSet)));
        OidcJwkSetManager manager = jwkSetManager(remoteJwksUri, clock, config);
        assertThat(manager.jwkKeys().forKeyId("verify-rsa").isPresent(), is(false));
        assertThat(remoteJwkSetRequests.get(), is(1));

        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch requestStarted = new CountDownLatch(1);
        CountDownLatch releaseResponse = new CountDownLatch(1);
        remoteJwkSetRequestLatch.set(requestStarted);
        remoteJwkSetResponseLatch.set(releaseResponse);
        clock.advance(Duration.ofSeconds(1));

        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<JwkKeys>> futures = IntStream.range(0, threads)
                    .mapToObj(ignored -> executor.submit(() -> {
                        assertTrue(start.await(5, TimeUnit.SECONDS));
                        return manager.jwkKeys();
                    }))
                    .toList();

            start.countDown();
            assertTrue(requestStarted.await(5, TimeUnit.SECONDS));
            releaseResponse.countDown();
            for (Future<JwkKeys> future : futures) {
                future.get();
            }
        }

        assertThat(manager.jwkKeys().forKeyId("verify-rsa").isPresent(), is(true));
        assertThat(remoteJwkSetRequests.get(), is(2));
    }

    @Test
    void concurrentUnknownKeyIdRefreshIsSingleFlight() throws Exception {
        int threads = 32;
        MutableClock clock = MutableClock.create(TEST_INSTANT);
        remoteJwkSetResponses.set(new ConcurrentLinkedQueue<>(List.of(emptyJwkSet(), verifyJwkSet)));
        OidcJwkSetManager manager = jwkSetManager(remoteJwksUri, clock);
        assertThat(manager.jwkKeys().forKeyId("verify-rsa").isPresent(), is(false));
        assertThat(remoteJwkSetRequests.get(), is(1));

        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch requestStarted = new CountDownLatch(1);
        CountDownLatch releaseResponse = new CountDownLatch(1);
        remoteJwkSetRequestLatch.set(requestStarted);
        remoteJwkSetResponseLatch.set(releaseResponse);
        clock.advance(OidcJwkSetConfig.create().unknownKeyIdRefreshInterval());

        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<JwkKeys>> futures = IntStream.range(0, threads)
                    .mapToObj(ignored -> executor.submit(() -> {
                        assertTrue(start.await(5, TimeUnit.SECONDS));
                        return manager.jwkKeys(Optional.of("verify-rsa"));
                    }))
                    .toList();

            start.countDown();
            assertTrue(requestStarted.await(5, TimeUnit.SECONDS));
            releaseResponse.countDown();
            for (Future<JwkKeys> future : futures) {
                assertThat(future.get().forKeyId("verify-rsa").isPresent(), is(true));
            }
        }

        assertThat(remoteJwkSetRequests.get(), is(2));
    }

    @Test
    void coldUnknownKeyIdDoesNotFetchRemoteJwkSetTwice() {
        remoteJwkSetResponses.set(new ArrayDeque<>(List.of(emptyJwkSet(), verifyJwkSet)));
        String token = signedToken(it -> { });

        AuthenticationResponse response = authenticate(provider(true, true, remoteJwksUri), token);

        assertInvalidToken(response, "Bearer Token signature is invalid");
        assertThat(remoteJwkSetRequests.get(), is(1));
    }

    @Test
    void principalNameFallsBackToSubject() {
        String token = signedToken(it -> it.preferredUsername(null));

        AuthenticationResponse response = authenticate(provider(), token);

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.user().orElseThrow().principal().getName(), is(SUBJECT));
    }

    @Test
    void malformedJwtAccessTokenIsRejected() {
        AuthenticationResponse response = authenticate(provider(), "not-a-jwt");

        assertInvalidToken(response, "Bearer Token is not a valid signed JWT");
    }

    @Test
    void wrongIssuerIsRejected() {
        String token = signedToken(it -> it.issuer("https://other.example"));

        AuthenticationResponse response = authenticate(provider(), token);

        assertInvalidToken(response, "Bearer Token JWT claims are invalid");
    }

    @Test
    void wrongAudienceIsRejected() {
        String token = signedToken(it -> it.audience(List.of("api://other")));

        AuthenticationResponse response = authenticate(provider(), token);

        assertInvalidToken(response, "Bearer Token JWT claims are invalid");
    }

    @Test
    void audienceValidationCanBeDisabled() {
        String token = signedToken(it -> it.audience(List.of("api://other")));

        AuthenticationResponse response = authenticate(provider(false), token);

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
    }

    @Test
    void audienceValidationCanBeDisabledWithoutConfiguredAudience() {
        String token = signedToken(it -> it.audience(List.of("api://other")));

        AuthenticationResponse response = authenticate(provider(false, false, jwksUri), token);

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
    }

    @Test
    void expiredTokenIsRejected() {
        Instant now = Instant.now();
        String token = signedToken(it -> it.issueTime(now.minus(2, ChronoUnit.HOURS))
                .expirationTime(now.minus(5, ChronoUnit.MINUTES)));

        AuthenticationResponse response = authenticate(provider(), token);

        assertInvalidToken(response, "Bearer Token JWT claims are invalid");
    }

    @Test
    void expirationWithinClockSkewIsAccepted() {
        Instant now = Instant.now();
        String token = signedToken(it -> it.issueTime(now.minus(1, ChronoUnit.HOURS))
                .expirationTime(now.minus(30, ChronoUnit.SECONDS)));

        AuthenticationResponse response = authenticate(provider(), token);

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
    }

    @Test
    void missingExpirationIsRejected() {
        String token = signedToken(it -> it.expirationTime(null));

        AuthenticationResponse response = authenticate(provider(), token);

        assertInvalidToken(response, "Bearer Token JWT claims are invalid");
    }

    @Test
    void missingIssueTimeIsRejected() {
        String token = signedToken(it -> it.issueTime(null));

        AuthenticationResponse response = authenticate(provider(), token);

        assertInvalidToken(response, "Bearer Token JWT claims are invalid");
    }

    @Test
    void missingJwtIdIsRejected() {
        String token = signedToken(it -> it.jwtId(null));

        AuthenticationResponse response = authenticate(provider(), token);

        assertInvalidToken(response, "Bearer Token JWT claims are invalid");
    }

    @Test
    void missingClientIdIsRejected() {
        String token = signedToken(it -> it.removePayloadClaim("client_id"));

        AuthenticationResponse response = authenticate(provider(), token);

        assertInvalidToken(response, "Bearer Token JWT claims are invalid");
    }

    @Test
    void blankClientIdIsRejected() {
        String token = signedToken(it -> it.addPayloadClaim("client_id", " "));

        AuthenticationResponse response = authenticate(provider(), token);

        assertInvalidToken(response, "Bearer Token JWT claims are invalid");
    }

    @Test
    void unsupportedAlgorithmIsRejectedBeforeSignatureVerification() {
        String token = signedToken(JwkOctet.ALG_HS256, "verify-oct", "sign-oct", it -> { });

        AuthenticationResponse response = authenticate(provider(true, true, MISSING_JWKS_URI), token);

        assertInvalidToken(response, "Bearer Token JWS header is invalid");
    }

    @Test
    void noneAlgorithmIsRejectedBeforeSignatureVerification() {
        String token = unsignedToken(it -> { });

        AuthenticationResponse response = authenticate(provider(true, true, MISSING_JWKS_URI), token);

        assertInvalidToken(response, "Bearer Token JWS header is invalid");
    }

    @Test
    void missingAccessTokenTypeIsRejected() {
        String token = signedToken(false, JwkRSA.ALG_RS256, "verify-rsa", "sign-rsa", it -> { });

        AuthenticationResponse response = authenticate(provider(), token);

        assertInvalidToken(response, "Bearer Token JWS header is invalid");
    }

    @Test
    void wrongJwtTypeIsRejected() {
        String token = signedToken(it -> it.type("JWT"));

        AuthenticationResponse response = authenticate(provider(), token);

        assertInvalidToken(response, "Bearer Token JWS header is invalid");
    }

    @Test
    void invalidSignatureIsRejected() {
        String token = signedToken(it -> { });
        int signatureStart = token.lastIndexOf('.') + 1;
        char replacement = token.charAt(signatureStart) == 'A' ? 'B' : 'A';
        String tampered = token.substring(0, signatureStart) + replacement + token.substring(signatureStart + 1);

        AuthenticationResponse response = authenticate(provider(), tampered);

        assertInvalidToken(response, "Bearer Token signature is invalid");
    }

    @Test
    void knownKeyIdWithInvalidSignatureDoesNotRefreshRemoteJwkSet() {
        String token = signedToken(it -> { });
        int signatureStart = token.lastIndexOf('.') + 1;
        char replacement = token.charAt(signatureStart) == 'A' ? 'B' : 'A';
        String tampered = token.substring(0, signatureStart) + replacement + token.substring(signatureStart + 1);

        AuthenticationResponse response = authenticate(provider(true, true, remoteJwksUri), tampered);

        assertInvalidToken(response, "Bearer Token signature is invalid");
        assertThat(remoteJwkSetRequests.get(), is(1));
    }

    @Test
    void missingSubjectIsRejected() {
        String token = signedToken(it -> it.subject(null));

        AuthenticationResponse response = authenticate(provider(), token);

        assertInvalidToken(response, "Bearer Token JWT claims are invalid");
    }

    @Test
    void blankSubjectIsRejected() {
        String token = signedToken(it -> it.subject(" "));

        AuthenticationResponse response = authenticate(provider(), token);

        assertInvalidToken(response, "Bearer Token JWT claims are invalid");
    }

    @Test
    void unavailableJwkSetIsRejectedAsInvalidToken() {
        String token = signedToken(it -> { });

        AuthenticationResponse response = authenticate(provider(true, true, MISSING_JWKS_URI), token);

        assertInvalidToken(response, "Bearer Token signature keys are unavailable");
    }

    private static AuthenticationResponse authenticate(OidcProvider provider, String token) {
        return provider.authenticate(OidcProviderTest.request(null,
                                                              SecurityEnvironment.builder()
                                                                      .targetUri(URI.create("https://rp.example/resource"))
                                                                      .header("Authorization", "Bearer " + token)
                                                                      .build()));
    }

    private static OidcProvider provider() {
        return provider(true);
    }

    private static OidcProvider provider(boolean audienceValidationEnabled) {
        return provider(audienceValidationEnabled, true, jwksUri);
    }

    private OidcProvider wellKnownProvider(Consumer<OidcTenantConfig.Builder> tenantCustomizer) {
        OidcTenantConfig.Builder tenantBuilder = OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .endpoints(it -> it.wellKnownUri(wellKnownUri)
                        .tlsRequired(false))
                .protectedResource(it -> it.tokenValidation(validation -> validation
                        .method(OidcTokenValidationMethod.JWT)
                        .audience(AUDIENCE)));
        tenantCustomizer.accept(tenantBuilder);
        return OidcProvider.create(OidcProviderConfig.builder()
                                           .putTenant("default", tenantBuilder.buildPrototype())
                                           .buildPrototype());
    }

    private static WebClientConfig tenantWebClient() {
        return WebClientConfig.builder()
                .addHeader(TENANT_WEBCLIENT_HEADER, TENANT_WEBCLIENT_HEADER_VALUE)
                .buildPrototype();
    }

    private static OidcProvider provider(boolean audienceValidationEnabled, boolean audienceConfigured, URI jwksUri) {
        return provider(audienceValidationEnabled, audienceConfigured, jwksUri, tenant -> { });
    }

    private static OidcProvider provider(boolean audienceValidationEnabled,
                                         boolean audienceConfigured,
                                         URI jwksUri,
                                         Consumer<OidcTenantConfig.Builder> tenantCustomizer) {
        OidcTenantConfig.Builder tenantBuilder = OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .endpoints(it -> it.jwksUri(jwksUri)
                        .tlsRequired(false))
                .protectedResource(it -> it.tokenValidation(validation -> {
                            validation.method(OidcTokenValidationMethod.JWT)
                                    .audienceValidationEnabled(audienceValidationEnabled);
                            if (audienceConfigured) {
                                validation.audience(AUDIENCE);
                            }
                        }));
        tenantCustomizer.accept(tenantBuilder);
        return OidcProvider.create(OidcProviderConfig.builder()
                                           .putTenant("default", tenantBuilder.buildPrototype())
                                           .buildPrototype());
    }

    private static OidcJwkSetManager jwkSetManager(URI jwksUri, Clock clock) {
        return jwkSetManager(jwksUri, clock, OidcJwkSetConfig.create());
    }

    private static OidcJwkSetManager jwkSetManager(URI jwksUri, Clock clock, OidcJwkSetConfig config) {
        OidcProviderMetadata metadata = OidcProviderMetadata.create(Optional.of(ISSUER.toString()),
                                                                    Optional.empty(),
                                                                    Optional.empty(),
                                                                    Optional.empty(),
                                                                    Optional.of(jwksUri),
                                                                    Optional.empty(),
                                                                    Optional.empty(),
                                                                    Optional.empty());
        return OidcJwkSetManager.create("default", metadata, clock, config);
    }

    private static String signedToken(Consumer<Jwt.Builder> customizer) {
        return signedToken(JwkRSA.ALG_RS256, "verify-rsa", "sign-rsa", customizer);
    }

    private static String emptyJwkSet() {
        return "{\"keys\":[]}";
    }

    private static String signedToken(String algorithm,
                                      String keyId,
                                      String signingKeyId,
                                      Consumer<Jwt.Builder> customizer) {
        return signedToken(true, algorithm, keyId, signingKeyId, customizer);
    }

    private static String signedToken(boolean accessTokenType,
                                      String algorithm,
                                      String keyId,
                                      String signingKeyId,
                                      Consumer<Jwt.Builder> customizer) {
        Instant now = Instant.now();
        Jwt.Builder builder = Jwt.builder()
                .subject(SUBJECT)
                .preferredUsername(USERNAME)
                .issuer(ISSUER.toString())
                .algorithm(algorithm)
                .keyId(keyId)
                .issueTime(now)
                .expirationTime(now.plus(1, ChronoUnit.HOURS))
                .jwtId("jwt-id")
                .addPayloadClaim("client_id", "calling-client")
                .addAudience(AUDIENCE);
        if (accessTokenType) {
            builder.type("at+jwt");
        }
        customizer.accept(builder);
        return SignedJwt.sign(builder.build(), signKeys.forKeyId(signingKeyId).orElseThrow())
                .tokenContent();
    }

    private static String unsignedToken(Consumer<Jwt.Builder> customizer) {
        Instant now = Instant.now();
        Jwt.Builder builder = Jwt.builder()
                .type("at+jwt")
                .subject(SUBJECT)
                .preferredUsername(USERNAME)
                .issuer(ISSUER.toString())
                .algorithm(Jwk.ALG_NONE)
                .issueTime(now)
                .expirationTime(now.plus(1, ChronoUnit.HOURS))
                .jwtId("jwt-id")
                .addPayloadClaim("client_id", "calling-client")
                .addAudience(AUDIENCE);
        customizer.accept(builder);
        return SignedJwt.sign(builder.build(), Jwk.NONE_JWK)
                .tokenContent();
    }

    private static void assertInvalidToken(AuthenticationResponse response, String description) {
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.FAILURE));
        assertThat(response.statusCode().orElse(-1), is(401));
        assertThat(response.description().orElse(""), is(description));
        assertThat(response.responseHeaders().get("WWW-Authenticate").get(0),
                   is("Bearer error=\"invalid_token\", error_description=\"" + description + "\""));
    }

    private static final class MutableClock extends Clock {
        private Instant instant;
        private final ZoneId zone;

        private MutableClock(Instant instant, ZoneId zone) {
            this.instant = instant;
            this.zone = zone;
        }

        static MutableClock create(Instant instant) {
            return new MutableClock(instant, ZoneId.of("UTC"));
        }

        void advance(Duration duration) {
            instant = instant.plus(duration);
        }

        @Override
        public ZoneId getZone() {
            return zone;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return new MutableClock(instant, zone);
        }

        @Override
        public Instant instant() {
            return instant;
        }
    }
}
