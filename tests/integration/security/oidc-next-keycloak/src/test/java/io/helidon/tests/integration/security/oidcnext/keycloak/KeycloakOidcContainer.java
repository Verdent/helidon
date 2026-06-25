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
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

final class KeycloakOidcContainer {
    static final String REALM = "helidon";
    static final int HTTP_PORT = 8080;

    private static final DockerImageName IMAGE = DockerImageName.parse(
            System.getProperty("helidon.tests.keycloak.image", "quay.io/keycloak/keycloak:26.6.3"));

    static final GenericContainer<?> CONTAINER = new GenericContainer<>(IMAGE)
            .withEnv("KC_BOOTSTRAP_ADMIN_USERNAME", "admin")
            .withEnv("KC_BOOTSTRAP_ADMIN_PASSWORD", "admin")
            .withExposedPorts(HTTP_PORT)
            .withCopyFileToContainer(MountableFile.forClasspathResource("keycloak/helidon-realm.json"),
                                     "/opt/keycloak/data/import/helidon-realm.json")
            .withCommand("start-dev", "--import-realm", "--features=par")
            .withStartupAttempts(3)
            .waitingFor(Wait.forHttp("/realms/" + REALM + "/.well-known/openid-configuration")
                                .forPort(HTTP_PORT)
                                .forStatusCode(200)
                                .withStartupTimeout(Duration.ofMinutes(4)));

    private KeycloakOidcContainer() {
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
}
