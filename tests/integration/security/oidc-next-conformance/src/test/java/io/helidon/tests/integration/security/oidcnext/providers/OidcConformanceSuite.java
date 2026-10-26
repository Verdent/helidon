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
import java.io.InputStream;
import java.net.InetAddress;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Base64;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import io.helidon.http.Status;
import io.helidon.json.JsonObject;
import io.helidon.webclient.api.HttpClientResponse;
import io.helidon.webclient.api.WebClient;
import io.helidon.webclient.api.WebClientConfig;

/**
 * Ephemeral, locally hosted official OIDF test suite. Only the opt-in Maven module starts these containers.
 * A fresh development-mode MongoDB and fresh plans are used for each execution; no OIDF account is needed.
 */
final class OidcConformanceSuite implements AutoCloseable {
    private static final URI SUITE = URI.create("https://localhost.emobix.co.uk:8443");
    private static final String BASIC_PLAN = "oidcc-client-basic-certification-test-plan";
    private static final String REFRESH_PLAN = "oidcc-client-refreshtoken-test-plan";
    private static final int RP_PORT = 39443;
    private static final int READY_ATTEMPTS = 180;

    private final Path workDirectory;
    private final Path composeFile;
    private final String projectName;
    private final Map<String, String> planIds = new HashMap<>();

    private WebClientConfig webClient;
    private boolean started;
    private boolean closed;

    private OidcConformanceSuite(Path workDirectory) {
        this.workDirectory = workDirectory;
        this.composeFile = workDirectory.resolve("oidf-compose.yml");
        this.projectName = "oidc-next-oidf-" + UUID.randomUUID().toString().substring(0, 12);
    }

    static OidcConformanceSuite start() throws Exception {
        OidcConformanceSuite suite = new OidcConformanceSuite(Files.createTempDirectory("oidc-next-oidf-"));
        try {
            suite.prepare();
            suite.started = true;
            suite.run(Duration.ofMinutes(8), "docker", "compose", "--project-name", suite.projectName,
                      "-f", suite.composeFile.toString(), "up", "-d");
            suite.awaitReady();
            return suite;
        } catch (Exception | Error failure) {
            try {
                suite.close();
            } catch (Exception cleanupFailure) {
                failure.addSuppressed(cleanupFailure);
            }
            throw failure;
        }
    }

    URI url() {
        return SUITE;
    }

    WebClientConfig webClient() {
        return webClient;
    }

    String planId(String name) {
        return Objects.requireNonNull(planIds.get(name), "OIDF test plan was not created: " + name);
    }

    void createPlan(String planName) {
        JsonObject.Builder variant = JsonObject.builder()
                .set("request_type", "plain_http_request")
                .set("client_registration", "static_client");
        if (!BASIC_PLAN.equals(planName)) {
            variant.set("client_auth_type", "client_secret_basic");
        }
        if (REFRESH_PLAN.equals(planName)) {
            variant.set("response_type", "code").set("response_mode", "default");
        }
        String variantQuery = URLEncoder.encode(variant.build().toString(), StandardCharsets.UTF_8);
        URI create = SUITE.resolve("/api/plan?planName=" + planName + "&variant=" + variantQuery);
        JsonObject client = JsonObject.builder()
                .set("client_id", "helidon-oidc-next-local-rp")
                .set("client_secret", randomSecret())
                .set("redirect_uri", "https://localhost:" + RP_PORT + "/oidc/callback")
                .set("request_type", "plain_http_request")
                .set("post_logout_redirect_uri", "https://localhost:" + RP_PORT + "/logout-complete")
                .set("backchannel_logout_uri", "https://host.docker.internal:" + RP_PORT + "/oidc/backchannel")
                .build();
        JsonObject config = JsonObject.builder()
                .set("description", "Helidon OIDC Next test-only conformance run")
                .set("alias", "helidon_" + planName.replace('-', '_'))
                .set("client", client)
                .build();
        WebClient http = WebClient.builder().from(webClient).build();
        try {
            try (HttpClientResponse response = http.post().uri(create).submit(config)) {
                if (response.status().code() != Status.CREATED_201_CODE) {
                    throw new IllegalStateException("Cannot create OIDF plan " + planName + ": " + response.status());
                }
                String id = response.as(JsonObject.class).stringValue("id").orElseThrow();
                planIds.put(planName, id);
            }
        } finally {
            http.closeResource();
        }
    }

    private void prepare() throws Exception {
        try (InputStream input = OidcConformanceSuite.class.getResourceAsStream("/oidf-compose.yml")) {
            Files.copy(Objects.requireNonNull(input, "Missing OIDF Compose test resource"), composeFile);
        }
        Path certificate = workDirectory.resolve("oidf-local.crt");
        Path key = workDirectory.resolve("oidf-local.key");
        run(Duration.ofSeconds(30), "openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes",
            "-days", "1", "-subj", "/CN=localhost.emobix.co.uk",
            "-addext", "subjectAltName=DNS:localhost.emobix.co.uk", "-keyout", key.toString(),
            "-out", certificate.toString());
        X509Certificate suiteCertificate;
        X509Certificate rpCertificate;
        try (InputStream suite = Files.newInputStream(certificate);
                InputStream rp = OidcConformanceSuite.class.getResourceAsStream("/tls-cert.pem")) {
            CertificateFactory certificates = CertificateFactory.getInstance("X.509");
            suiteCertificate = (X509Certificate) certificates.generateCertificate(suite);
            rpCertificate = (X509Certificate) certificates.generateCertificate(
                    Objects.requireNonNull(rp, "Missing RP test TLS certificate"));
        }
        InetAddress loopback = InetAddress.getByName("127.0.0.1");
        webClient = WebClientConfig.builder()
                .tls(tls -> tls.trust(List.of(suiteCertificate, rpCertificate)))
                .dnsResolver((host, _) -> {
                    if (host.equals("localhost.emobix.co.uk") || host.equals("localhost")
                            || host.equals("127.0.0.1")) {
                        return loopback;
                    }
                    throw new IllegalStateException("OIDF fixture only connects to local hosts");
                }).buildPrototype();
    }

    private void awaitReady() throws IOException, InterruptedException {
        RuntimeException lastFailure = null;
        for (int attempt = 0; attempt < READY_ATTEMPTS; attempt++) {
            WebClient http = WebClient.builder().from(webClient).build();
            try {
                try (HttpClientResponse response = http.get()
                        .uri(SUITE.resolve("/api/plan/info/" + BASIC_PLAN)).request()) {
                    if (response.status().code() == Status.OK_200_CODE) {
                        return;
                    }
                    lastFailure = new IllegalStateException("OIDF suite returned " + response.status());
                }
            } catch (RuntimeException e) {
                lastFailure = e;
            } finally {
                http.closeResource();
            }
            // If a container cannot start (for example, a missing dev-mode setting), report its logs promptly.
            if (attempt % 10 == 9 && !run(Duration.ofSeconds(10), "docker", "compose", "--project-name",
                                          projectName, "-f", composeFile.toString(), "ps", "--status", "exited",
                                          "--quiet", "server", "mongodb", "nginx").isBlank()) {
                break;
            }
            Thread.sleep(1000);
        }
        String logs = run(Duration.ofSeconds(20), "docker", "compose", "--project-name", projectName,
                          "-f", composeFile.toString(), "logs", "--tail", "50", "server", "mongodb", "nginx");
        throw new IllegalStateException("OIDF suite did not become ready; container logs:\n" + logs, lastFailure);
    }

    private static String randomSecret() {
        byte[] random = new byte[32];
        new SecureRandom().nextBytes(random);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(random);
    }

    private String run(Duration timeout, String... command) throws IOException, InterruptedException {
        Path output = workDirectory.resolve("command-output.log");
        ProcessBuilder processBuilder = new ProcessBuilder(command).directory(workDirectory.toFile())
                .redirectErrorStream(true).redirectOutput(output.toFile());
        processBuilder.environment().put("OIDF_CERT", workDirectory.resolve("oidf-local.crt").toString());
        processBuilder.environment().put("OIDF_KEY", workDirectory.resolve("oidf-local.key").toString());
        Process process = processBuilder.start();
        try {
            if (!process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS)) {
                process.destroyForcibly();
                throw new IllegalStateException("Timed out waiting for " + command[0] + " " + command[1]);
            }
            if (process.exitValue() != 0) {
                throw new IllegalStateException("Command failed (" + process.exitValue() + "): "
                                                        + String.join(" ", command) + "\n" + Files.readString(output));
            }
            return Files.readString(output);
        } finally {
            if (process.isAlive()) {
                process.destroyForcibly();
            }
        }
    }

    @Override
    public void close() throws Exception {
        if (closed) {
            return;
        }
        closed = true;
        Exception failure = null;
        try {
            if (started) {
                run(Duration.ofSeconds(90), "docker", "compose", "--project-name", projectName,
                    "-f", composeFile.toString(), "down", "--timeout", "30");
            }
        } catch (Exception e) {
            failure = e;
        }
        try (Stream<Path> files = Files.walk(workDirectory)) {
            for (Path file : files.sorted(Comparator.reverseOrder()).toList()) {
                Files.delete(file);
            }
        } catch (IOException e) {
            if (failure == null) {
                failure = e;
            } else {
                failure.addSuppressed(e);
            }
        }
        if (failure != null) {
            throw failure;
        }
    }
}
