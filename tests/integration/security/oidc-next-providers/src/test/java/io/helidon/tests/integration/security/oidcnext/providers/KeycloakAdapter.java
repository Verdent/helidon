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
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

import io.helidon.common.parameters.Parameters;
import io.helidon.common.uri.UriQuery;
import io.helidon.http.HeaderNames;
import io.helidon.http.Status;
import io.helidon.json.JsonArray;
import io.helidon.json.JsonObject;
import io.helidon.security.providers.oidc.next.OidcJwtAccessTokenConfig;
import io.helidon.security.providers.oidc.next.OidcJwtAccessTokenProfile;
import io.helidon.webclient.api.HttpClientResponse;
import io.helidon.webclient.api.WebClient;
import io.helidon.webclient.api.WebClientConfig;

import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.MountableFile;

final class KeycloakAdapter implements IdpAdapter {
    private static final Pattern LOGIN_ACTION = Pattern.compile("<form[^>]+action=\"([^\"]+/login-actions/authenticate[^\"]*)\"");
    private final String issuerHost;
    private GenericContainer<?> container;
    private URI issuer;
    private WebClientConfig client;

    KeycloakAdapter() {
        this(null);
    }

    KeycloakAdapter(String issuerHost) {
        this.issuerHost = issuerHost;
    }

    @Override
    public void start() throws Exception {
        Path realm = Files.createTempFile("helidon-keycloak-contract-", ".json");
        Files.writeString(realm, realm().toString());
        try {
            container = new GenericContainer<>(System.getProperty("helidon.tests.keycloak.image",
                                                                 "quay.io/keycloak/keycloak:26.8.0"))
                    .withExposedPorts(8443)
                    // The OP must reach the test RP from its container and verify the RP's SAN-bearing TLS cert.
                    .withExtraHost("auth.authelia.test", "host-gateway")
                    .withEnv("KC_BOOTSTRAP_ADMIN_USERNAME", "admin")
                    .withEnv("KC_BOOTSTRAP_ADMIN_PASSWORD", "admin")
                    .withCopyFileToContainer(MountableFile.forHostPath(realm), "/opt/keycloak/data/import/contract-realm.json")
                    .withCopyFileToContainer(MountableFile.forClasspathResource("tls-cert.pem"), "/opt/keycloak/conf/test.crt")
                    .withCopyFileToContainer(MountableFile.forClasspathResource("tls-key.pem"), "/opt/keycloak/conf/test.key")
                    .withCommand("start-dev", "--import-realm", "--features=par",
                                 "--https-certificate-file=/opt/keycloak/conf/test.crt",
                                 "--https-certificate-key-file=/opt/keycloak/conf/test.key",
                                 "--truststore-paths=/opt/keycloak/conf/test.crt")
                    .waitingFor(Wait.forHttp("/realms/contract/.well-known/openid-configuration").forPort(8443)
                            .usingTls().allowInsecure().withStartupTimeout(Duration.ofMinutes(4)));
            container.start();
            issuer = URI.create("https://" + (issuerHost == null ? container.getHost() : issuerHost) + ":"
                                        + container.getMappedPort(8443) + "/realms/contract");
            client = IdpResources.webClient(container.getHost());
        } finally {
            Files.deleteIfExists(realm);
        }
    }

    @Override
    public URI issuer() {
        return issuer;
    }

    @Override
    public WebClientConfig webClient() {
        return client;
    }

    @Override
    public Set<Capability> capabilities() {
        return EnumSet.allOf(Capability.class);
    }

    @Override
    public String unavailableReason(Capability capability) {
        throw new IllegalArgumentException("Keycloak fixture supports " + capability);
    }

    @Override
    public String diagnostics() {
        return container.getLogs();
    }

    @Override
    public void registerCallback(ClientMode mode, URI callback) {
        WebClient admin = WebClient.builder().from(client).build();
        try {
            String token = adminToken(admin);
            String id = clientInternalId(admin, token, mode);
            try (HttpClientResponse response = admin.put().uri(issuer.resolve("/admin/realms/contract/clients/" + id))
                    .header(HeaderNames.AUTHORIZATION, "Bearer " + token)
                    .submit(JsonObject.builder().setStrings("redirectUris", List.of(callback.toString(), COLLECTOR)).build())) {
                if (response.status().code() != 204) {
                    throw new IllegalStateException("Keycloak callback registration failed: " + response.status());
                }
            }
        } finally {
            admin.closeResource();
        }
    }

    AutoCloseable registerBackChannelLogout(ClientMode mode, URI logoutUri, boolean sessionRequired) {
        WebClient admin = WebClient.builder().from(client).build();
        try {
            String token = adminToken(admin);
            URI clientUri = issuer.resolve("/admin/realms/contract/clients/" + clientInternalId(admin, token, mode));
            JsonObject attributes;
            boolean frontchannelLogout;
            try (HttpClientResponse response = admin.get().uri(clientUri)
                    .header(HeaderNames.AUTHORIZATION, "Bearer " + token).request()) {
                JsonObject registration = response.as(JsonObject.class);
                attributes = registration.objectValue("attributes").orElseThrow();
                frontchannelLogout = registration.booleanValue("frontchannelLogout", false);
            }
            JsonObject updated = JsonObject.builder().from(attributes)
                    .set("backchannel.logout.url", logoutUri.toString())
                    .set("backchannel.logout.session.required", Boolean.toString(sessionRequired)).build();
            try (HttpClientResponse response = admin.put().uri(clientUri)
                    .header(HeaderNames.AUTHORIZATION, "Bearer " + token)
                    .submit(JsonObject.builder().set("frontchannelLogout", false).set("attributes", updated).build())) {
                if (response.status().code() != Status.NO_CONTENT_204_CODE) {
                    throw new IllegalStateException("Keycloak back-channel registration failed: " + response.status());
                }
            }
            return () -> {
                WebClient restore = WebClient.builder().from(client).build();
                try (HttpClientResponse response = restore.put().uri(clientUri)
                        .header(HeaderNames.AUTHORIZATION, "Bearer " + adminToken(restore))
                        .submit(JsonObject.builder().set("frontchannelLogout", frontchannelLogout)
                                        .set("attributes", attributes).build())) {
                    if (response.status().code() != Status.NO_CONTENT_204_CODE) {
                        throw new IllegalStateException("Keycloak logout registration restoration failed: "
                                                                + response.status());
                    }
                } finally {
                    restore.closeResource();
                }
            };
        } finally {
            admin.closeResource();
        }
    }

    void logoutUser(String username) {
        WebClient admin = WebClient.builder().from(client).build();
        try {
            String token = adminToken(admin);
            String userId;
            try (HttpClientResponse response = admin.get().uri(issuer.resolve("/admin/realms/contract/users"))
                    .queryParam("username", username).queryParam("exact", "true")
                    .header(HeaderNames.AUTHORIZATION, "Bearer " + token).request()) {
                userId = response.as(JsonArray.class).values().getFirst().asObject().stringValue("id").orElseThrow();
            }
            try (HttpClientResponse response = admin.post()
                    .uri(issuer.resolve("/admin/realms/contract/users/" + userId + "/logout"))
                    .header(HeaderNames.AUTHORIZATION, "Bearer " + token).request()) {
                if (response.status().code() != Status.NO_CONTENT_204_CODE) {
                    throw new IllegalStateException("Keycloak administrator logout failed: " + response.status());
                }
            }
        } finally {
            admin.closeResource();
        }
    }

    @Override
    public AutoCloseable rotateSigningKey() {
        WebClient admin = WebClient.builder().from(client).build();
        URI component;
        try {
            String token = adminToken(admin);
            String realmId;
            try (HttpClientResponse response = admin.get().uri(issuer.resolve("/admin/realms/contract"))
                    .header(HeaderNames.AUTHORIZATION, "Bearer " + token).request()) {
                realmId = response.as(JsonObject.class).stringValue("id").orElseThrow();
            }
            JsonObject configuration = JsonObject.builder().setStrings("priority", List.of("1000000"))
                    .setStrings("algorithm", List.of("RS256")).setStrings("keySize", List.of("2048"))
                    .setStrings("active", List.of("true")).setStrings("enabled", List.of("true")).build();
            try (HttpClientResponse response = admin.post().uri(issuer.resolve("/admin/realms/contract/components"))
                    .header(HeaderNames.AUTHORIZATION, "Bearer " + token)
                    .submit(JsonObject.builder().set("name", "rotated-signing-key").set("parentId", realmId)
                                    .set("providerId", "rsa-generated").set("providerType", "org.keycloak.keys.KeyProvider")
                                    .set("config", configuration).build())) {
                if (response.status().code() != 201) {
                    throw new IllegalStateException("Keycloak key rotation failed: " + response.status());
                }
                component = issuer.resolve(response.headers().first(HeaderNames.LOCATION).orElseThrow());
            }
        } finally {
            admin.closeResource();
        }
        return () -> {
            WebClient restore = WebClient.builder().from(client).build();
            try (HttpClientResponse response = restore.delete().uri(component)
                    .header(HeaderNames.AUTHORIZATION, "Bearer " + adminToken(restore)).request()) {
                if (response.status().code() != 204) {
                    throw new IllegalStateException("Keycloak signing key restoration failed: " + response.status());
                }
            } finally {
                restore.closeResource();
            }
        };
    }

    @Override
    public URI login(TestBrowser browser, URI authorization, URI callback) throws Exception {
        URI page = authorization;
        for (int redirects = 0; redirects < 5; redirects++) {
            try (HttpClientResponse response = browser.get(page)) {
                if (response.status().code() == 302 || response.status().code() == 303) {
                    page = page.resolve(response.headers().first(HeaderNames.LOCATION).orElseThrow());
                    if (page.getHost().equals(callback.getHost()) && page.getPath().equals(callback.getPath())) {
                        return page;
                    }
                    continue;
                }
                String html = response.as(String.class);
                var matcher = LOGIN_ACTION.matcher(html);
                if (!matcher.find()) {
                    throw new IllegalStateException("Keycloak login form missing: " + response.status() + " " + html);
                }
                URI action = URI.create(matcher.group(1).replace("&amp;", "&"));
                try (HttpClientResponse login = browser.post(action, Parameters.builder("login")
                        .add("username", "alice").add("password", "secret").build())) {
                    if (login.status().code() != 302) {
                        throw new IllegalStateException("Keycloak login failed: " + login.status()
                                                                + " " + login.as(String.class));
                    }
                    URI result = action.resolve(login.headers().first(HeaderNames.LOCATION).orElseThrow());
                    if (UriQuery.create(result).contains("error")) {
                        throw new IllegalStateException("Keycloak authorization error: " + result);
                    }
                    return result;
                }
            }
        }
        throw new IllegalStateException("Keycloak exceeded login redirect limit");
    }

    @Override
    public OidcJwtAccessTokenConfig jwtLayout() {
        return OidcJwtAccessTokenConfig.builder().profile(OidcJwtAccessTokenProfile.CUSTOM)
                .allowedTypes(List.of("JWT", "at+jwt")).requiredClaims(List.of("sub", "iat", "jti", "azp"))
                .putRequiredStringClaim("typ", "Bearer").buildPrototype();
    }

    @Override
    public void close() {
        if (container != null) {
            container.close();
            container = null;
        }
    }

    private static JsonObject realm() {
        // Separate Keycloak servers deliberately issue the same sub, so tenant isolation cannot rely on sub alone.
        JsonObject user = JsonObject.builder().set("id", "00000000-0000-4000-8000-000000000001")
                .set("username", "alice").set("enabled", true)
                .set("email", "alice@example.org").set("emailVerified", true)
                .set("firstName", "Alice").set("lastName", "Example")
                .setStrings("realmRoles", List.of("offline_access"))
                .set("credentials", JsonArray.create(List.of(JsonObject.builder()
                        .set("type", "password").set("value", "secret").set("temporary", false).build())))
                .setStrings("groups", List.of("/reader")).build();
        return JsonObject.builder().set("realm", "contract").set("enabled", true).set("sslRequired", "none")
                .set("roles", JsonObject.builder().set("realm", JsonArray.create(List.of(JsonObject.builder()
                        .set("name", "offline_access").build()))).build())
                .set("users", JsonArray.create(List.of(user)))
                .set("groups", JsonArray.create(List.of(JsonObject.builder().set("name", "reader").build())))
                .set("clientScopes", JsonArray.create(List.of(scope("basic"), scope("profile"), scope("email"),
                                                             scope("offline_access"), scope("groups"), scope("resource.read"))))
                .set("clients", JsonArray.create(Arrays.stream(ClientMode.values()).map(KeycloakAdapter::client).toList()))
                .build();
    }

    private static JsonObject scope(String name) {
        return JsonObject.builder().set("name", name).set("protocol", "openid-connect")
                .set("attributes", JsonObject.builder().set("include.in.token.scope", "true").build()).build();
    }

    private static JsonObject client(ClientMode mode) {
        boolean service = mode == ClientMode.SERVICE || mode == ClientMode.API || mode == ClientMode.JWT_SERVICE;
        JsonObject.Builder attributes = JsonObject.builder().set("pkce.code.challenge.method", "S256")
                .set("post.logout.redirect.uris", "+").set("standard.token.exchange.enabled", "true")
                .set("use.jwks.string", "true").set("jwks.string", IdpResources.publicClientKeys().toString());
        if (mode == ClientMode.SHORT_LIVED) {
            attributes.set("access.token.lifespan", "45");
        }
        if (mode == ClientMode.SIGNED_USERINFO) {
            attributes.set("user.info.response.signature.alg", "RS256");
        }
        if (mode == ClientMode.ENCRYPTED_ID_TOKEN) {
            attributes.set("id.token.encrypted.response.alg", "RSA-OAEP-256")
                    .set("id.token.encrypted.response.enc", "A256GCM");
        }
        if (mode == ClientMode.JAR || mode == ClientMode.PAR_JAR) {
            attributes.set("request.object.required", "request or request_uri").set("request.object.signature.alg", "RS256");
        }
        if (mode == ClientMode.PAR || mode == ClientMode.PAR_JAR) {
            attributes.set("require.pushed.authorization.requests", "true");
        }
        JsonObject audience = mapper("api-audience", "oidc-audience-mapper", JsonObject.builder()
                .set("included.custom.audience", AUDIENCE).set("access.token.claim", "true")
                .set("id.token.claim", "false").build());
        JsonObject groups = mapper("groups", "oidc-group-membership-mapper", JsonObject.builder()
                .set("claim.name", "groups").set("full.path", "false").set("access.token.claim", "true")
                .set("id.token.claim", "true").set("userinfo.token.claim", "true").build());
        JsonObject serviceAudience = mapper("service-audience", "oidc-audience-mapper", JsonObject.builder()
                .set("included.custom.audience", ClientMode.SERVICE.id()).set("access.token.claim", "true")
                .set("id.token.claim", "false").build());
        JsonObject username = mapper("username", "oidc-usermodel-property-mapper", JsonObject.builder()
                .set("user.attribute", "username").set("claim.name", "preferred_username").set("jsonType.label", "String")
                .set("access.token.claim", "true").set("id.token.claim", "true").set("userinfo.token.claim", "true").build());
        JsonObject email = mapper("email", "oidc-usermodel-property-mapper", JsonObject.builder()
                .set("user.attribute", "email").set("claim.name", "email").set("jsonType.label", "String")
                .set("access.token.claim", "true").set("id.token.claim", "true").set("userinfo.token.claim", "true").build());
        JsonObject subject = mapper("subject", "oidc-sub-mapper", JsonObject.builder()
                .set("access.token.claim", "true").set("id.token.claim", "true").set("userinfo.token.claim", "true").build());
        return JsonObject.builder().set("clientId", mode.id()).set("enabled", true).set("protocol", "openid-connect")
                .set("publicClient", mode == ClientMode.PUBLIC).set("secret", SECRET)
                .set("clientAuthenticatorType", mode == ClientMode.PRIVATE_JWT ? "client-jwt"
                        : mode == ClientMode.SECRET_JWT ? "client-secret-jwt" : "client-secret")
                .set("standardFlowEnabled", !service).set("serviceAccountsEnabled", service)
                .setStrings("redirectUris", List.of(COLLECTOR))
                .setStrings("defaultClientScopes", List.of("basic", "profile", "email", "groups", "resource.read"))
                .setStrings("optionalClientScopes", List.of("offline_access"))
                .set("attributes", attributes.build())
                .set("protocolMappers", JsonArray.create(List.of(audience, serviceAudience, groups, username, email, subject)))
                .build();
    }

    private static JsonObject mapper(String name, String type, JsonObject configuration) {
        return JsonObject.builder().set("name", name).set("protocol", "openid-connect")
                .set("protocolMapper", type).set("config", configuration).build();
    }

    private String adminToken(WebClient admin) {
        try (HttpClientResponse response = admin.post().uri(issuer.resolve("/realms/master/protocol/openid-connect/token"))
                .submit(Parameters.builder("admin").add("client_id", "admin-cli").add("grant_type", "password")
                                .add("username", "admin").add("password", "admin").build())) {
            if (response.status().code() != 200) {
                throw new IllegalStateException("Keycloak admin authentication failed: " + response.status());
            }
            return response.as(JsonObject.class).stringValue("access_token").orElseThrow();
        }
    }

    private String clientInternalId(WebClient admin, String token, ClientMode mode) {
        try (HttpClientResponse response = admin.get().uri(issuer.resolve("/admin/realms/contract/clients"))
                .queryParam("clientId", mode.id()).header(HeaderNames.AUTHORIZATION, "Bearer " + token).request()) {
            return response.as(JsonArray.class).values().getFirst().asObject().stringValue("id").orElseThrow();
        }
    }
}
