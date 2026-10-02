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

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import io.helidon.common.configurable.Resource;
import io.helidon.common.uri.UriQuery;
import io.helidon.http.HeaderNames;
import io.helidon.json.JsonArray;
import io.helidon.json.JsonObject;
import io.helidon.security.providers.oidc.next.OidcJwtAccessTokenConfig;
import io.helidon.webclient.api.HttpClientResponse;
import io.helidon.webclient.api.WebClientConfig;

import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.MountableFile;

final class AutheliaAdapter implements IdpAdapter {
    private final Map<ClientMode, Set<String>> callbacks = new EnumMap<>(ClientMode.class);
    private GenericContainer<?> container;
    private Path directory;
    private URI issuer;
    private WebClientConfig client;
    private String passwordHash;
    private String clientSecretHash;
    private String rotatedSigningKey;

    @Override
    public void start() throws Exception {
        directory = Files.createTempDirectory("helidon-authelia-");
        container = new GenericContainer<>(System.getProperty("helidon.tests.authelia.image",
                                                             "ghcr.io/authelia/authelia:4.39.28"))
                .withExposedPorts(9091)
                .withCreateContainerCmdModifier(command -> {
                    command.withEntrypoint("/bin/sh");
                    command.getHostConfig().withInit(true);
                })
                .withCommand("-c", "sleep infinity")
                .waitingFor(Wait.forSuccessfulCommand("test -d /tmp"));
        container.start();
        container.copyFileToContainer(MountableFile.forClasspathResource("tls-cert.pem"), "/tmp/tls-cert.pem");
        container.copyFileToContainer(MountableFile.forClasspathResource("tls-key.pem"), "/tmp/tls-key.pem");
        issuer = URI.create("https://auth.authelia.test:" + container.getMappedPort(9091));
        client = IdpResources.webClient(container.getHost());
        String hashOutput = container.execInContainer("authelia", "crypto", "hash", "generate", "argon2",
                                                       "--password", "secret").getStdout();
        passwordHash = hashOutput.lines().filter(line -> line.contains("$argon2id$")).findFirst().orElseThrow();
        passwordHash = passwordHash.substring(passwordHash.indexOf("$argon2id$"));
        String secretOutput = container.execInContainer("authelia", "crypto", "hash", "generate", "pbkdf2",
                "--password", SECRET).getStdout();
        clientSecretHash = secretOutput.lines().filter(line -> line.contains("$pbkdf2-")).findFirst().orElseThrow();
        clientSecretHash = clientSecretHash.substring(clientSecretHash.indexOf("$pbkdf2-"));
        writeConfiguration();
        startProcess();
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
        return EnumSet.complementOf(EnumSet.of(Capability.RP_LOGOUT, Capability.TOKEN_EXCHANGE,
                                               Capability.SIGNED_USERINFO, Capability.PAR_WITH_JAR,
                                               Capability.REFRESH_TOKEN_REVOCATION));
    }

    @Override
    public String unavailableReason(Capability capability) {
        return switch (capability) {
        case SIGNED_USERINFO -> "Known Authelia 4.39.28 incompatibility: signed UserInfo omits mandatory iss and aud claims; "
                + "the provider-specific regression verifies rejection";
        case PAR_WITH_JAR -> "Known Authelia 4.39.28 incompatibility: PAR with JAR requires outer response_type, "
                + "which RFC 9126 section 3 prohibits; the provider-specific regression verifies rejection";
        case REFRESH_TOKEN_REVOCATION -> "Known Authelia 4.39.28 SQLite incompatibility: refresh after revocation returns "
                + "server_error instead of invalid_grant; the provider-specific regression verifies no renewal";
        case RP_LOGOUT, TOKEN_EXCHANGE -> "Authelia 4.39.28 does not implement " + capability + "; see its OIDC support chart";
        default -> throw new IllegalArgumentException("Authelia fixture supports " + capability);
        };
    }

    @Override
    public String diagnostics() {
        try {
            return container.execInContainer("tail", "-20", "/tmp/authelia.log").getStdout();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return "Interrupted while reading Authelia diagnostics";
        } catch (Exception e) {
            return "Cannot read Authelia diagnostics: " + e;
        }
    }

    @Override
    public void registerCallback(ClientMode mode, URI callback) throws Exception {
        if (callbacks.computeIfAbsent(mode, _ -> new LinkedHashSet<>()).add(callback.toString())) {
            reloadConfiguration();
        }
    }

    @Override
    public AutoCloseable rotateSigningKey() throws Exception {
        rotatedSigningKey = IdpKeyMaterial.generateSigningPem();
        try {
            reloadConfiguration();
        } catch (Exception e) {
            rotatedSigningKey = null;
            throw e;
        }
        return () -> {
            rotatedSigningKey = null;
            reloadConfiguration();
        };
    }

    @Override
    public URI login(TestBrowser browser, URI authorization, URI callback) throws Exception {
        URI consent;
        try (HttpClientResponse response = browser.get(authorization)) {
            if (response.status().code() != 303) {
                throw new IllegalStateException("Authelia authorization did not start consent: " + response.status()
                                                        + " " + response.as(String.class));
            }
            consent = authorization.resolve(response.headers().first(HeaderNames.LOCATION).orElseThrow());
        }
        var flow = UriQuery.create(consent).first("flow_id");
        if (flow.isEmpty()) {
            throw new IllegalStateException("Authelia authorization returned " + consent + "\n" + diagnostics());
        }
        String flowId = flow.orElseThrow();
        browser.postJson(issuer.resolve("/api/firstfactor"), JsonObject.builder()
                .set("username", "alice").set("password", "secret")
                .set("keepMeLoggedIn", false).set("targetURL", consent.toString()).build());
        JsonObject result;
        try {
            result = browser.postJson(issuer.resolve("/api/oidc/consent"), JsonObject.builder()
                    .set("flow_id", flowId).set("client_id", UriQuery.create(authorization).first("client_id").orElseThrow())
                    .set("consent", true).build());
        } catch (Exception e) {
            throw new IllegalStateException("Authelia consent failed: "
                                                    + diagnostics(), e);
        }
        JsonObject data = result.objectValue("data").orElseThrow();
        URI finish = URI.create(data.stringValue("redirect_uri").or(() -> data.stringValue("redirect"))
                                        .orElseThrow(() -> new IllegalStateException("Authelia consent response: " + result)));
        try (HttpClientResponse response = browser.get(finish)) {
            if (response.status().code() != 303 && response.status().code() != 302) {
                throw new IllegalStateException("Authelia consent did not return an authorization code: "
                                                        + response.status() + " " + response.as(String.class));
            }
            return finish.resolve(response.headers().first(HeaderNames.LOCATION).orElseThrow());
        }
    }

    @Override
    public OidcJwtAccessTokenConfig jwtLayout() {
        return OidcJwtAccessTokenConfig.create();
    }

    @Override
    public void close() {
        try {
            if (container != null) {
                container.close();
                container = null;
            }
        } finally {
            if (directory != null && Files.exists(directory)) {
                try (var files = Files.walk(directory)) {
                    for (Path file : files.sorted(Comparator.reverseOrder()).toList()) {
                        Files.deleteIfExists(file);
                    }
                } catch (IOException e) {
                    throw new IllegalStateException("Cannot remove Authelia fixture files", e);
                } finally {
                    directory = null;
                }
            }
        }
    }

    private void startProcess() throws Exception {
        container.execInContainer("sh", "-c",
                                  "authelia --config /tmp/authelia.yml >/tmp/authelia.log 2>&1 & echo $! >/tmp/authelia.pid");
        try {
            Wait.forSuccessfulCommand("grep -q 'Listening for TLS connections' /tmp/authelia.log")
                    .withStartupTimeout(Duration.ofSeconds(40)).waitUntilReady(container);
        } catch (RuntimeException e) {
            throw new IllegalStateException("Authelia startup failed: "
                                                    + container.execInContainer("cat", "/tmp/authelia.log").getStdout(), e);
        }
    }

    private void reloadConfiguration() throws Exception {
        container.execInContainer("sh", "-c", "kill \"$(cat /tmp/authelia.pid)\"");
        Wait.forSuccessfulCommand("test ! -d /proc/$(cat /tmp/authelia.pid)")
                .withStartupTimeout(Duration.ofSeconds(20)).waitUntilReady(container);
        writeConfiguration();
        startProcess();
    }

    private void writeConfiguration() throws Exception {
        JsonObject user = JsonObject.builder().set("password", passwordHash)
                .set("displayname", "Alice Example").set("email", "alice@example.org")
                .setStrings("groups", List.of("reader")).build();
        Path users = directory.resolve("users.yml");
        Files.writeString(users, JsonObject.builder().set("users", JsonObject.builder().set("alice", user).build())
                .build().toString());
        container.copyFileToContainer(MountableFile.forHostPath(users), "/tmp/users.yml");
        List<JsonObject> clients = Arrays.stream(ClientMode.values()).map(this::clientConfiguration).toList();
        JsonObject originalKey = JsonObject.builder().set("key_id", "provider-rsa")
                .set("algorithm", "RS256").set("use", "sig").set("key", Resource.create("tls-key.pem").string()).build();
        List<JsonObject> issuerKeys = rotatedSigningKey != null
                ? List.of(JsonObject.builder().set("key_id", "provider-rsa-rotated").set("algorithm", "RS256")
                                  .set("use", "sig").set("key", rotatedSigningKey).build(), originalKey)
                : List.of(originalKey);
        JsonObject config = JsonObject.builder()
                .set("ntp", JsonObject.builder().set("disable_startup_check", true).build())
                .set("server", JsonObject.builder().set("address", "tcp://0.0.0.0:9091/")
                        .set("tls", JsonObject.builder().set("certificate", "/tmp/tls-cert.pem")
                                .set("key", "/tmp/tls-key.pem").build()).build())
                .set("authentication_backend", JsonObject.builder().set("file", JsonObject.builder()
                        .set("path", "/tmp/users.yml").build())
                        .set("password_reset", JsonObject.builder().set("disable", true).build()).build())
                .set("access_control", JsonObject.builder().set("default_policy", "one_factor").build())
                .set("session", JsonObject.builder()
                        .set("secret", "test-session-secret-which-is-at-least-sixty-four-characters-long-12345")
                        .set("cookies", JsonArray.create(List.of(JsonObject.builder()
                                .set("domain", "auth.authelia.test").set("authelia_url", issuer.toString()).build()))).build())
                .set("storage", JsonObject.builder()
                        .set("encryption_key", "test-storage-encryption-key-at-least-thirty-two-characters")
                        .set("local", JsonObject.builder().set("path", "/tmp/authelia.sqlite").build()).build())
                .set("notifier", JsonObject.builder().set("filesystem", JsonObject.builder()
                        .set("filename", "/tmp/notifications.txt").build()).build())
                .set("identity_providers", JsonObject.builder().set("oidc", JsonObject.builder()
                        .set("enable_client_debug_messages", true)
                        .set("hmac_secret", "test-oidc-hmac-secret-at-least-sixty-four-characters-long-1234567890")
                        .set("jwks", JsonArray.create(issuerKeys))
                        .set("scopes", JsonObject.builder().set("resource.read", JsonObject.builder()
                                .setStrings("claims", List.of()).build()).build())
                        .set("claims_policies", JsonObject.builder().set("integration", JsonObject.builder()
                                .setStrings("id_token", List.of("preferred_username", "email", "groups"))
                                .setStrings("access_token", List.of("preferred_username", "email", "groups"))
                                .build()).build())
                        .set("clients", JsonArray.create(clients)).build()).build()).build();
        Path file = directory.resolve("authelia.yml");
        Files.writeString(file, config.toString());
        container.copyFileToContainer(MountableFile.forHostPath(file), "/tmp/authelia.yml");
    }

    private JsonObject clientConfiguration(ClientMode mode) {
        boolean service = mode == ClientMode.SERVICE || mode == ClientMode.API || mode == ClientMode.JWT_SERVICE;
        JsonObject.Builder client = JsonObject.builder().set("client_id", mode.id())
                .set("authorization_policy", "one_factor").set("consent_mode", "explicit")
                .set("requested_audience_mode", "implicit").setStrings("audience", List.of(AUDIENCE))
                .setStrings("redirect_uris", Stream.concat(Stream.of(COLLECTOR),
                        callbacks.getOrDefault(mode, Set.of()).stream()).toList())
                .setStrings("grant_types", service
                        ? List.of("client_credentials") : List.of("authorization_code", "refresh_token"))
                .setStrings("response_types", service ? List.of() : List.of("code"))
                .setStrings("scopes", service ? List.of("resource.read")
                        : List.of("openid", "profile", "email", "groups", "offline_access", "resource.read"));
        if (mode == ClientMode.PUBLIC) {
            client.set("public", true).set("token_endpoint_auth_method", "none");
        } else if (mode == ClientMode.PRIVATE_JWT) {
            client.set("token_endpoint_auth_method", "private_key_jwt")
                    .set("token_endpoint_auth_signing_alg", "RS256")
                    .set("introspection_endpoint_auth_method", "private_key_jwt")
                    .set("introspection_endpoint_auth_signing_alg", "RS256")
                    .set("revocation_endpoint_auth_method", "private_key_jwt")
                    .set("revocation_endpoint_auth_signing_alg", "RS256")
                    .set("pushed_authorization_request_endpoint_auth_method", "private_key_jwt")
                    .set("pushed_authorization_request_endpoint_auth_signing_alg", "RS256")
                    .set("jwks", JsonArray.create(List.of(JsonObject.builder()
                            .set("key_id", "sign-rsa").set("algorithm", "RS256").set("use", "sig")
                            .set("key", IdpKeyMaterial.publicSigningPem()).build())));
        } else {
            client.set("client_secret", mode == ClientMode.SECRET_JWT ? "$plaintext$" + SECRET : clientSecretHash)
                    .set("token_endpoint_auth_method", mode == ClientMode.POST ? "client_secret_post"
                            : mode == ClientMode.SECRET_JWT ? "client_secret_jwt" : "client_secret_basic");
            if (mode == ClientMode.SECRET_JWT) {
                client.set("token_endpoint_auth_signing_alg", "HS256");
            }
        }
        if (mode == ClientMode.PAR || mode == ClientMode.PAR_JAR) {
            client.set("require_pushed_authorization_requests", true);
        }
        if (mode == ClientMode.JAR || mode == ClientMode.PAR_JAR) {
            client.set("request_object_signing_alg", "RS256").set("jwks", JsonArray.create(List.of(JsonObject.builder()
                    .set("key_id", "sign-rsa").set("algorithm", "RS256").set("use", "sig")
                    .set("key", IdpKeyMaterial.publicSigningPem()).build())));
        }
        if (mode == ClientMode.SIGNED_USERINFO) {
            client.set("userinfo_signed_response_alg", "RS256");
        }
        if (mode == ClientMode.JWT_ACCESS || mode == ClientMode.JWT_SERVICE) {
            client.set("access_token_signed_response_alg", "RS256").set("claims_policy", "integration");
        }
        if (mode == ClientMode.ENCRYPTED_ID_TOKEN) {
            client.set("id_token_encrypted_response_alg", "RSA-OAEP-256")
                    .set("id_token_encrypted_response_enc", "A256GCM")
                    .set("jwks", JsonArray.create(List.of(JsonObject.builder()
                            .set("key_id", "encrypt-rsa").set("use", "enc")
                            .set("key", IdpKeyMaterial.publicEncryptionPem()).build())));
        }
        return client.build();
    }
}
