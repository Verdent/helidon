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

import java.net.URI;
import java.time.Duration;

import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.containers.wait.strategy.WaitStrategy;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

final class KeycloakOidcContainer {
    static final String REALM = "helidon";
    static final int HTTP_PORT = 8080;
    static final int HTTPS_PORT = 8443;
    static final GenericContainer<?> CONTAINER;

    private static final DockerImageName IMAGE = DockerImageName.parse(
            System.getProperty("helidon.tests.keycloak.image", "quay.io/keycloak/keycloak:26.8.0"));
    private static final String TLS_CERTIFICATE = "/opt/keycloak/conf/oidc-next-test.crt";
    private static final String TLS_PRIVATE_KEY = "/opt/keycloak/conf/oidc-next-test.key";

    static {
        CONTAINER = container()
                .withExposedPorts(HTTP_PORT)
                .withCommand("start-dev", "--import-realm", "--features=par")
                .waitingFor(metadataReady());
    }

    private KeycloakOidcContainer() {
    }

    static GenericContainer<?> httpsContainer(String certificate, String privateKey) {
        return container()
                .withExposedPorts(HTTP_PORT, HTTPS_PORT)
                .withCopyFileToContainer(MountableFile.forClasspathResource(certificate), TLS_CERTIFICATE)
                .withCopyFileToContainer(MountableFile.forClasspathResource(privateKey), TLS_PRIVATE_KEY)
                .withCommand("start-dev", "--import-realm", "--features=par",
                             "--https-certificate-file=" + TLS_CERTIFICATE,
                             "--https-certificate-key-file=" + TLS_PRIVATE_KEY)
                .waitingFor(metadataReady());
    }

    static URI baseUri() {
        return URI.create("http://" + CONTAINER.getHost() + ":" + CONTAINER.getMappedPort(HTTP_PORT));
    }

    static URI issuer() {
        return baseUri().resolve("/realms/" + REALM);
    }

    static URI metadataUri() {
        return issuer().resolve("/realms/" + REALM + "/.well-known/openid-configuration");
    }

    static URI tokenEndpointUri() {
        return issuer().resolve("/realms/" + REALM + "/protocol/openid-connect/token");
    }

    static URI introspectionEndpointUri() {
        return issuer().resolve("/realms/" + REALM + "/protocol/openid-connect/token/introspect");
    }

    private static GenericContainer<?> container() {
        return new GenericContainer<>(IMAGE)
                .withEnv("KC_BOOTSTRAP_ADMIN_USERNAME", "admin")
                .withEnv("KC_BOOTSTRAP_ADMIN_PASSWORD", "admin")
                .withCopyFileToContainer(MountableFile.forClasspathResource("keycloak/helidon-realm.json"),
                                         "/opt/keycloak/data/import/helidon-realm.json")
                .withStartupAttempts(3);
    }

    private static WaitStrategy metadataReady() {
        return Wait.forHttp("/realms/" + REALM + "/.well-known/openid-configuration")
                .forPort(HTTP_PORT)
                .forStatusCode(200)
                .withStartupTimeout(Duration.ofMinutes(4));
    }
}
