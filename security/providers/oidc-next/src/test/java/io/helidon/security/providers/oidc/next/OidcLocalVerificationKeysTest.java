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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import io.helidon.common.configurable.Resource;
import io.helidon.common.configurable.ResourceConfig;
import io.helidon.config.Config;
import io.helidon.config.ConfigSources;
import io.helidon.http.HeaderValues;
import io.helidon.json.JsonObject;
import io.helidon.json.JsonParser;
import io.helidon.security.SecurityEnvironment;
import io.helidon.security.jwt.Jwt;
import io.helidon.security.jwt.SignedJwt;
import io.helidon.security.jwt.jwk.JwkKeys;
import io.helidon.webserver.WebServer;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class OidcLocalVerificationKeysTest {
    private static final String AUDIENCE = "api://orders";
    private static final String CLIENT_ID = "client-id";
    private static final Instant NOW = Instant.parse("2026-09-17T12:00:00Z");
    private static final String LOCAL_KEYS = Resource.create("oidc-next-verify-jwk.json").string();
    private static final String PUBLIC_KEYS = Resource.create("oidc-next-verify-public-jwk.json").string();
    private static final ResourceConfig LOCAL_RESOURCE = ResourceConfig.builder().contentPlain(LOCAL_KEYS).buildPrototype();
    private static final JwkKeys SIGNING_KEYS = JwkKeys.builder().resource(Resource.create("oidc-next-sign-jwk.json")).build();

    private final AtomicInteger metadataRequests = new AtomicInteger();
    private final AtomicInteger jwksRequests = new AtomicInteger();
    private final AtomicReference<JsonObject> metadata = new AtomicReference<>();
    private final AtomicReference<String> providerKeys = new AtomicReference<>(PUBLIC_KEYS);

    private WebServer server;
    private URI issuer;
    private URI metadataUri;
    private URI jwksUri;

    @BeforeEach
    void init() {
        server = WebServer.builder().routing(routing -> routing
                .get("/.well-known/openid-configuration", (_, response) -> {
                    metadataRequests.incrementAndGet();
                    response.header(HeaderValues.CONTENT_TYPE_JSON).send(metadata.get().toString());
                })
                .get("/jwks", (_, response) -> {
                    jwksRequests.incrementAndGet();
                    response.header(HeaderValues.CONTENT_TYPE_JSON).send(providerKeys.get());
                })).build().start();
        issuer = URI.create("http://localhost:" + server.port());
        metadataUri = issuer.resolve("/.well-known/openid-configuration");
        jwksUri = issuer.resolve("/jwks");
        metadata.set(JsonObject.builder()
                .set("issuer", issuer.toString())
                .set("jwks_uri", jwksUri.toString())
                .set("authorization_endpoint", issuer.resolve("/authorize").toString())
                .set("token_endpoint", issuer.resolve("/token").toString())
                .setStrings("response_types_supported", List.of("code"))
                .setStrings("subject_types_supported", List.of("public"))
                .setStrings("id_token_signing_alg_values_supported", List.of("RS256"))
                .setStrings("code_challenge_methods_supported", List.of("S256"))
                .build());
    }

    @AfterEach
    void close() {
        if (server != null) {
            server.stop();
        }
    }

    @Test
    void localKeysWorkWithoutProviderJwksOrDiscovery() {
        withTenant(localTenant(_ -> { }).buildPrototype(), context -> {
            assertReady(context);
            assertThat(validateAccessToken(context, signedToken(false)).succeeded(), is(true));
            assertThat(validateAccessToken(context, signedToken(false)).succeeded(), is(true));
        });
        assertThat(metadataRequests.get(), is(0));
        assertThat(jwksRequests.get(), is(0));
    }

    @Test
    void localKeysHaveRootAndNamedConfigurationParity() {
        for (String prefix : List.of("", "tenants.tenant.")) {
            OidcProviderConfig config = OidcProviderConfig.create(config(prefix, Map.of()));
            withProvider(config, context -> {
                assertReady(context);
                assertThat(context.tokenValidation().verificationJwk().orElseThrow().contentPlain().orElseThrow(),
                           is(LOCAL_KEYS));
                assertThat(validateAccessToken(context, signedToken(false)).succeeded(), is(true));
            });
        }
        assertThat(metadataRequests.get(), is(0));
        assertThat(jwksRequests.get(), is(0));
    }

    @Test
    void localKeyMaterialIsConfidential() {
        OidcTenantConfig tenant = localTenant(_ -> { }).buildPrototype();
        String secret = JsonParser.create(LOCAL_KEYS).readJsonObject().arrayValue("keys").orElseThrow()
                .values().get(1).asObject().stringValue("k").orElseThrow();

        assertThat(tenant.toString(), not(containsString(secret)));
        assertThat(tenant.protectedResource().orElseThrow().tokenValidation().toString(), not(containsString(secret)));
        assertThat(OidcProviderConfig.create(config("", Map.of())).toString(), not(containsString(secret)));
    }

    @Test
    void uriResourcesAreRejectedBeforeOpening() {
        ResourceConfig remote = ResourceConfig.builder().uri(jwksUri).buildPrototype();
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> localTenant(validation -> validation.verificationJwk(remote)).buildPrototype());
        assertThat(exception.getMessage(), containsString("verification-jwk must be local"));
        assertThrows(IllegalArgumentException.class, () -> OidcJwkSetLoader.loadLocal(remote));

        for (String prefix : List.of("", "tenants.tenant.")) {
            assertThrows(IllegalArgumentException.class,
                         () -> OidcProviderConfig.create(config(prefix, Map.of(
                                 "protected-resource.token-validation.verification-jwk.uri", jwksUri.toString()))));
        }
        assertThat(metadataRequests.get(), is(0));
        assertThat(jwksRequests.get(), is(0));
    }

    @Test
    void localKeysRequireJwtValidationMethod() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> localTenant(validation -> validation.method(OidcTokenValidationMethod.INTROSPECTION)).buildPrototype());
        assertThat(exception.getMessage(), containsString("verification-jwk requires token-validation.method JWT"));
        for (String prefix : List.of("", "tenants.tenant.")) {
            assertThrows(IllegalArgumentException.class,
                         () -> OidcProviderConfig.create(config(prefix, Map.of(
                                 "protected-resource.token-validation.method", "INTROSPECTION"))));
        }
    }

    @Test
    void hmacRequiresAnExplicitLocalSource() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(issuer.toString()).endpoints(endpoints -> endpoints.jwksUri(jwksUri).tlsRequired(false))
                .protectedResource(resource -> resource.tokenValidation(validation -> validation
                        .method(OidcTokenValidationMethod.JWT).audience(AUDIENCE).allowedAlgorithms(List.of("HS256"))))
                .buildPrototype());
        assertThat(exception.getMessage(), containsString("verification-jwk must be configured for HMAC"));
    }

    @Test
    void localKeysStillRequireATrustedIssuer() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .protectedResource(resource -> resource.tokenValidation(validation -> validation
                        .method(OidcTokenValidationMethod.JWT).audience(AUDIENCE)
                        .allowedAlgorithms(List.of("HS256")).verificationJwk(LOCAL_RESOURCE)))
                .buildPrototype());
        assertThat(exception.getMessage(), containsString("issuer or well-known-uri"));
    }

    @Test
    void discoveryCanProvideIssuerWithoutFetchingProviderKeys() {
        withTenant(discoveryTenant(), context -> {
            assertReady(context);
            assertThat(validateAccessToken(context, signedToken(false)).succeeded(), is(true));
        });
        assertThat(metadataRequests.get(), is(1));
        assertThat(jwksRequests.get(), is(0));
    }

    @Test
    void localKeysDoNotRelaxRequiredDiscoveryMetadata() {
        metadata.set(JsonObject.builder().from(metadata.get()).unset("jwks_uri").build());
        withTenant(discoveryTenant(), context -> {
            assertThat(context.state(), is(OidcTenantState.FAILED));
            assertThat(context.failureCause().orElseThrow().getMessage(), containsString("jwks_uri must be present"));
        });
        assertThat(metadataRequests.get(), is(1));
        assertThat(jwksRequests.get(), is(0));
    }

    @Test
    void missingLocalKeyDoesNotFallBackToProviderKeys() {
        JsonObject symmetric = JsonParser.create(LOCAL_KEYS).readJsonObject().arrayValue("keys").orElseThrow()
                .values().get(1).asObject();
        ResourceConfig onlySymmetric = ResourceConfig.builder().contentPlain("{\"keys\":[" + symmetric + "]}").buildPrototype();
        OidcTenantConfig tenant = localTenant(validation -> validation.allowedAlgorithms(List.of("RS256"))
                .verificationJwk(onlySymmetric))
                .endpoints(endpoints -> endpoints.jwksUri(jwksUri).tlsRequired(false)).buildPrototype();
        withTenant(tenant, context -> {
            assertReady(context);
            Jwt jwt = accessToken().algorithm("RS256").keyId("verify-rsa").build();
            String token = SignedJwt.sign(jwt, SIGNING_KEYS.forKeyId("sign-rsa").orElseThrow()).tokenContent();
            assertThat(validateAccessToken(context, token).succeeded(), is(false));
        });
        assertThat(metadataRequests.get(), is(0));
        assertThat(jwksRequests.get(), is(0));
    }

    @Test
    void browserAndAccessTokenKeysRemainIndependent() {
        withTenant(browserTenant(), context -> {
            assertReady(context);
            OidcValidationResult<OidcValidatedIdToken> result = new OidcIdTokenValidator()
                    .validate(signedToken(true), context, requestState(), NOW);
            assertThat(result.succeeded(), is(true));
            assertThat(validateAccessToken(context, signedToken(false)).succeeded(), is(true));
        });
        assertThat(metadataRequests.get(), is(0));
        assertThat(jwksRequests.get(), is(1));
    }

    @Test
    void localAccessTokenKeysDoNotReplaceIdTokenDiscoveryKeys() {
        OidcTenantConfig tenant = localTenant(_ -> { }).clientId(CLIENT_ID).clientSecret("test-client-secret")
                .endpoints(endpoints -> endpoints.authorizationEndpointUri(issuer.resolve("/authorize"))
                        .tokenEndpointUri(issuer.resolve("/token")).tlsRequired(false))
                .authorizationCode(code -> code.redirectionEndpointUri(requestState().redirectionEndpointUri()))
                .cookies(cookies -> cookies.protection(protection -> protection.password("test-cookie-password")))
                .buildPrototype();
        withTenant(tenant, context -> {
            assertReady(context);
            assertThat(new OidcIdTokenValidator().validate(signedToken(true), context, requestState(), NOW).succeeded(), is(true));
            assertThat(validateAccessToken(context, signedToken(false)).succeeded(), is(true));
        });
        assertThat(metadataRequests.get(), is(1));
        assertThat(jwksRequests.get(), is(1));
    }

    @Test
    void localAccessTokenKeysCannotReplaceInvalidProviderKeys() {
        JsonObject privateKey = JsonParser.create(Resource.create("oidc-next-sign-jwk.json").string()).readJsonObject()
                .arrayValue("keys").orElseThrow().values().getFirst().asObject();
        providerKeys.set("{\"keys\":[" + JsonObject.builder().from(privateKey).set("kid", "verify-rsa").build() + "]}");
        withTenant(browserTenant(), context -> {
            assertReady(context);
            assertThat(new OidcIdTokenValidator().validate(signedToken(true), context, requestState(), NOW).succeeded(), is(false));
            assertThat(validateAccessToken(context, signedToken(false)).succeeded(), is(true));
        });
        assertThat(jwksRequests.get(), is(1));
    }

    private static void assertReady(OidcTenantContext context) {
        assertThat(context.failureCause().map(Throwable::getMessage).orElse("tenant state"),
                   context.state(), is(OidcTenantState.READY));
    }

    private static OidcValidationResult<OidcValidatedAccessToken> validateAccessToken(OidcTenantContext context, String token) {
        return new OidcJwtAccessTokenValidator().validate(new OidcAccessTokenValidationRequest(token, context,
                OidcAccessTokenValidationRequest.Use.PROTECTED_RESOURCE, Optional.empty(), NOW));
    }

    private static void withTenant(OidcTenantConfig tenant, Consumer<OidcTenantContext> assertions) {
        withProvider(OidcProviderConfig.builder().putTenant("tenant", tenant).buildPrototype(), assertions);
    }

    private static void withProvider(OidcProviderConfig provider, Consumer<OidcTenantContext> assertions) {
        OidcTenantContext context = OidcTenantRuntimeRegistry.create(provider)
                .tenantContext(OidcProviderTest.request(null, SecurityEnvironment.create())).orElseThrow();
        try {
            assertions.accept(context);
        } finally {
            if (context.ready()) {
                context.webClient().closeResource();
            }
        }
    }

    private OidcTenantConfig.Builder localTenant(Consumer<OidcTokenValidationConfig.Builder> customizer) {
        OidcTokenValidationConfig.Builder validation = OidcTokenValidationConfig.builder()
                .method(OidcTokenValidationMethod.JWT).audience(AUDIENCE)
                .allowedAlgorithms(List.of("HS256")).verificationJwk(LOCAL_RESOURCE);
        customizer.accept(validation);
        return OidcTenantConfig.builder().issuer(issuer.toString()).endpoints(endpoints -> endpoints.tlsRequired(false))
                .protectedResource(resource -> resource.tokenValidation(validation.buildPrototype()));
    }

    private OidcTenantConfig discoveryTenant() {
        return OidcTenantConfig.builder().endpoints(endpoints -> endpoints.wellKnownUri(metadataUri).tlsRequired(false))
                .protectedResource(resource -> resource.tokenValidation(validation -> validation
                        .method(OidcTokenValidationMethod.JWT).audience(AUDIENCE)
                        .allowedAlgorithms(List.of("HS256")).verificationJwk(LOCAL_RESOURCE)))
                .buildPrototype();
    }

    private OidcTenantConfig browserTenant() {
        return localTenant(_ -> { }).clientId(CLIENT_ID)
                .endpoints(endpoints -> endpoints.authorizationEndpointUri(issuer.resolve("/authorize"))
                        .tokenEndpointUri(issuer.resolve("/token")).jwksUri(jwksUri).tlsRequired(false))
                .authorizationCode(code -> code.redirectionEndpointUri(requestState().redirectionEndpointUri()))
                .cookies(cookies -> cookies.protection(protection -> protection.password("test-cookie-password")))
                .buildPrototype();
    }

    private Config config(String prefix, Map<String, String> overrides) {
        Map<String, String> values = new HashMap<>(Map.of(
                "issuer", issuer.toString(),
                "endpoints.tls-required", "false",
                "protected-resource.token-validation.method", "JWT",
                "protected-resource.token-validation.audience", AUDIENCE,
                "protected-resource.token-validation.allowed-algorithms.0", "HS256",
                "protected-resource.token-validation.verification-jwk.content-plain", LOCAL_KEYS));
        values.putAll(overrides);
        Map<String, String> properties = new HashMap<>();
        values.forEach((key, value) -> properties.put(prefix + key, value));
        return Config.builder().disableEnvironmentVariablesSource().disableSystemPropertiesSource()
                .sources(ConfigSources.create(properties)).build();
    }

    private Jwt.Builder accessToken() {
        return Jwt.builder().type("at+jwt").algorithm("HS256").keyId("verify-oct")
                .issuer(issuer.toString()).subject("alice").addAudience(AUDIENCE)
                .issueTime(NOW).expirationTime(NOW.plusSeconds(3600)).jwtId("test-token")
                .addPayloadClaim("client_id", "calling-client");
    }

    private String signedToken(boolean idToken) {
        Jwt jwt = idToken
                ? Jwt.builder().algorithm("RS256").keyId("verify-rsa").issuer(issuer.toString())
                        .subject("alice").addAudience(CLIENT_ID).nonce("nonce")
                        .issueTime(NOW).expirationTime(NOW.plusSeconds(3600)).build()
                : accessToken().build();
        return SignedJwt.sign(jwt, SIGNING_KEYS.forKeyId(idToken ? "sign-rsa" : "sign-oct").orElseThrow()).tokenContent();
    }

    private OidcAuthenticationRequestState requestState() {
        return new OidcAuthenticationRequestState("tenant", "state", "nonce", "pkce", null, issuer.toString(),
                URI.create("https://rp.example/resource"), URI.create("https://rp.example/callback"),
                NOW.minusSeconds(1), NOW.plusSeconds(300));
    }
}
