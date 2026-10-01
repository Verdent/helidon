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
import java.io.InputStream;
import java.net.InetAddress;
import java.net.URI;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;

import io.helidon.common.uri.UriQuery;
import io.helidon.http.HeaderNames;
import io.helidon.http.Status;
import io.helidon.security.providers.oidc.next.OidcProviderConfig;
import io.helidon.security.providers.oidc.next.OidcPushedAuthorizationRequestMode;
import io.helidon.security.providers.oidc.next.OidcRequestObjectMode;
import io.helidon.security.providers.oidc.next.OidcTenantConfig;
import io.helidon.tests.integration.security.oidcnext.keycloak.KeycloakOidcIntegrationSupport.BrowserSession;
import io.helidon.webclient.api.HttpClientResponse;
import io.helidon.webclient.api.WebClient;
import io.helidon.webclient.api.WebClientConfig;
import io.helidon.webserver.WebServer;

import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

@Testcontainers(disabledWithoutDocker = true)
class KeycloakTlsCertificateIdentityIT {
    private static final String RESOURCE_ROOT = "keycloak/tls/";
    private static final String JAR_CLIENT_ID = "helidon-jar-web";
    private static final String JAR_CLIENT_SECRET = "jar-web-secret";

    @Test
    void dnsSanCertificateAllowsSignedJarPushedAuthorizationRequest() throws Exception {
        assertThat(pushedAuthorizationRequestStatus("dns-san", true, false), is(Status.SEE_OTHER_303_CODE));
    }

    @Test
    void mismatchedDnsSanCertificateRejectsSignedJarPushedAuthorizationRequest() throws Exception {
        assertThat(pushedAuthorizationRequestStatus("wrong-san", true, false), is(Status.SERVICE_UNAVAILABLE_503_CODE));
    }

    @Test
    void cnOnlyCertificateRejectsSignedJarPushedAuthorizationRequest() throws Exception {
        assertThat(pushedAuthorizationRequestStatus("cn-only", true, false), is(Status.SERVICE_UNAVAILABLE_503_CODE));
    }

    @Test
    void cnOnlyCertificateRejectsSignedJarAfterPooledConnectionWasEstablished() throws Exception {
        assertThat(pushedAuthorizationRequestStatus("cn-only", true, true), is(Status.SERVICE_UNAVAILABLE_503_CODE));
    }

    @Test
    void cnOnlyCertificateRemainsUsableWithoutSignedJar() throws Exception {
        assertThat(pushedAuthorizationRequestStatus("cn-only", false, false), is(Status.SEE_OTHER_303_CODE));
    }

    private static int pushedAuthorizationRequestStatus(String certificateName,
                                                        boolean signedJar,
                                                        boolean prewarmConnection) throws Exception {
        String prefix = RESOURCE_ROOT + certificateName;
        try (GenericContainer<?> keycloak = KeycloakOidcContainer.httpsContainer(prefix + ".crt", prefix + ".key")) {
            keycloak.start();
            assumeTrue(InetAddress.getByName(keycloak.getHost()).isLoopbackAddress(),
                       "TLS certificate fixture requires a loopback Testcontainers host");

            URI issuer = URI.create("https://localhost:" + keycloak.getMappedPort(KeycloakOidcContainer.HTTPS_PORT)
                                            + "/realms/" + KeycloakOidcContainer.REALM);
            X509Certificate trustedCertificate = certificate(prefix + ".crt");
            WebClientConfig clientConfig = WebClientConfig.builder()
                    .tls(tls -> tls.trust(List.of(trustedCertificate)))
                    .buildPrototype();
            OidcTenantConfig tenant = OidcTenantConfig.builder()
                    .issuer(issuer.toString())
                    .clientId(signedJar ? JAR_CLIENT_ID : "helidon-web")
                    .clientSecret(signedJar ? JAR_CLIENT_SECRET : "web-secret")
                    .webClient(clientConfig)
                    .endpoints(endpoints -> endpoints
                            .authorizationEndpointUri(endpoint(issuer, "auth"))
                            .tokenEndpointUri(endpoint(issuer, "token"))
                            .jwksUri(endpoint(issuer, "certs"))
                            .pushedAuthorizationRequestEndpointUri(endpoint(issuer, "ext/par/request"))
                            // The RP callback is local HTTP; every Keycloak endpoint still uses HTTPS.
                            .tlsRequired(false))
                    .authorizationCode(authorizationCode -> {
                        authorizationCode.pushedAuthorizationRequests(OidcPushedAuthorizationRequestMode.REQUIRED);
                        if (signedJar) {
                            authorizationCode.requestObject(requestObject -> requestObject
                                    .mode(OidcRequestObjectMode.REQUIRED)
                                    .signingJwk(jwk -> jwk.resourcePath("keycloak/oidc-jar-sign-jwk.json"))
                                    .signingKeyId("sign-rsa")
                                    .signingAlgorithm("RS256"));
                        }
                    })
                    .cookies(cookies -> cookies.protection(protection -> protection.password("keycloak-tls-test-password")))
                    .buildPrototype();
            OidcProviderConfig providerConfig = OidcProviderConfig.builder()
                    .putTenant("default", tenant)
                    .buildPrototype();
            if (prewarmConnection) {
                WebClient lenientClient = WebClient.create(clientConfig);
                try (HttpClientResponse response = lenientClient.get()
                             .uri(issuer.resolve(issuer.getPath() + "/.well-known/openid-configuration"))
                             .request()) {
                    assertThat(response.status(), is(Status.OK_200));
                } finally {
                    lenientClient.closeResource();
                }
            }
            WebServer rpServer = KeycloakOidcIntegrationSupport.rpServer(
                    providerConfig,
                    routing -> KeycloakOidcIntegrationSupport.protectedRoute(routing, "/resource"));
            try (BrowserSession browser = new BrowserSession()) {
                URI resourceUri = KeycloakOidcIntegrationSupport.rpBaseUri(rpServer).resolve("/resource");
                try (HttpClientResponse response = browser.get(resourceUri)) {
                    if (response.status().code() == Status.SEE_OTHER_303_CODE) {
                        URI authorizationUri = URI.create(response.headers().first(HeaderNames.LOCATION).orElseThrow());
                        assertThat(UriQuery.create(authorizationUri).contains("request_uri"), is(true));
                    }
                    return response.status().code();
                }
            } finally {
                rpServer.stop();
            }
        }
    }

    private static URI endpoint(URI issuer, String path) {
        return issuer.resolve(issuer.getPath() + "/protocol/openid-connect/" + path);
    }

    private static X509Certificate certificate(String resourceName) throws IOException, CertificateException {
        try (InputStream input = KeycloakTlsCertificateIdentityIT.class.getResourceAsStream("/" + resourceName)) {
            if (input == null) {
                throw new IllegalArgumentException("Missing test certificate: " + resourceName);
            }
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(input);
        }
    }
}
