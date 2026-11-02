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

import java.net.InetAddress;
import java.net.URI;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import javax.net.ssl.SSLSession;

import io.helidon.common.configurable.Resource;
import io.helidon.common.parameters.Parameters;
import io.helidon.common.pki.Keys;
import io.helidon.common.tls.Tls;
import io.helidon.http.HeaderNames;
import io.helidon.http.HeaderValues;
import io.helidon.http.Status;
import io.helidon.json.JsonObject;
import io.helidon.security.AuthenticationResponse;
import io.helidon.security.SecurityEnvironment;
import io.helidon.security.jwt.SignedJwt;
import io.helidon.security.jwt.jwk.JwkKeys;
import io.helidon.webclient.api.ConnectedSocketChannelInfo;
import io.helidon.webclient.api.ConnectedSocketInfo;
import io.helidon.webclient.api.ConnectionListener;
import io.helidon.webclient.api.WebClientConfig;
import io.helidon.webserver.WebServer;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThan;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;

/*
 * RFC 9101 §8, https://www.rfc-editor.org/rfc/rfc9101.html#section-8:
 * "Clients MUST NOT use CN-ID identifiers" applies to the Request Object URI method.
 * These tests instead send a signed Request Object by value in a PAR POST. Helidon's extra
 * DNS-ID requirement for that combination is a local security policy, not an RFC 9101 §8 MUST.
 */
class OidcWebClientFactoryTlsIdentityTest {
    private static final String CLIENT_ID = "signed-par-client";
    private static final String CLIENT_SECRET = "test-secret";
    private static final String REQUEST_URI = "urn:ietf:params:oauth:request_uri:par-1";

    @TestFactory
    Stream<DynamicTest> signedJarParRejectsUntrustedServerIdentityBeforeHttp() {
        return Stream.of(
                dynamicTest("CN without SAN", () -> assertPar("cn-only", "localhost", true, false)),
                dynamicTest("CN matches but DNS SAN does not", () -> assertPar("wildcard", "localhost", true, false)),
                dynamicTest("IP host with matching IP SAN", () -> assertPar("server", "127.0.0.1", true, false)),
                dynamicTest("wildcard cannot match more than one label",
                            () -> assertPar("wildcard", "deep.login.oidc.test", true, false)),
                dynamicTest("partial leftmost wildcard is invalid",
                            () -> assertPar("wildcard", "api1.bad.oidc.test", true, false)),
                dynamicTest("multiple wildcard labels are invalid",
                            () -> assertPar("wildcard", "one.two.invalid.oidc.test", true, false)));
    }

    @TestFactory
    Stream<DynamicTest> signedJarParAcceptsMatchingDnsIdentity() {
        return Stream.of(
                dynamicTest("matching DNS SAN", () -> assertPar("server", "localhost", true, true)),
                dynamicTest("one-label wildcard DNS SAN",
                            () -> assertPar("wildcard", "login.oidc.test", true, true)));
    }

    @Test
    void parWithoutSignedJarDoesNotAcquireStrictDnsIdPolicy() throws Exception {
        // RFC 9525 §6.6, https://www.rfc-editor.org/rfc/rfc9525.html#section-6.6,
        // allows prior configuration to accept a particular certificate for a peer.
        // This test explicitly trusts the leaf before connecting and disables the test client's
        // default hostname check. It does not assert that a default TLS client accepts CN-only identities.
        assertPar("cn-only", "localhost", false, true);
    }

    private static void assertPar(String certificate, String hostname, boolean signedJar, boolean accepted)
            throws Exception {
        Keys serverKeys = serverKeys(certificate);
        AtomicInteger parRequests = new AtomicInteger();
        AtomicReference<String> authorization = new AtomicReference<>();
        AtomicReference<List<String>> requestObjects = new AtomicReference<>(List.of());
        WebServer server = WebServer.builder().host("127.0.0.1").port(0)
                .tls(Tls.builder().privateKey(serverKeys).privateKeyCertChain(serverKeys).build())
                .routing(routing -> routing.post("/par", (request, response) -> {
                    parRequests.incrementAndGet();
                    authorization.set(request.headers().first(HeaderNames.AUTHORIZATION).orElse(""));
                    Parameters form = request.content().as(Parameters.class);
                    requestObjects.set(form.names().contains("request") ? form.all("request") : List.of());
                    response.status(Status.CREATED_201)
                            .header(HeaderValues.CONTENT_TYPE_JSON)
                            .header(HeaderNames.CACHE_CONTROL, "no-store")
                            .send(JsonObject.builder().set("request_uri", REQUEST_URI).set("expires_in", 90)
                                          .build().toString());
                }))
                .build().start();
        try {
            AtomicInteger connected = new AtomicInteger();
            AtomicInteger successfulHandshakes = new AtomicInteger();
            InetAddress loopback = InetAddress.getByAddress(new byte[] {127, 0, 0, 1});
            // Disable only the test client's built-in hostname check to exercise the OIDC DNS-ID gate itself;
            // the TLS certificate chain is still verified against the selected trusted test certificate.
            WebClientConfig webClient = WebClientConfig.builder()
                    .dnsResolver((_, _) -> loopback)
                    .tls(tls -> tls.endpointIdentificationAlgorithm(Tls.ENDPOINT_IDENTIFICATION_NONE)
                            .trust(serverKeys.certChain()))
                    .connectionListener(new ConnectionListener() {
                        @Override
                        public void socketConnected(ConnectedSocketInfo socketInfo) {
                            connected.incrementAndGet();
                        }

                        @Override
                        public void socketChannelConnected(ConnectedSocketChannelInfo socketInfo) {
                            connected.incrementAndGet();
                        }

                        @Override
                        public void tlsHandshakeCompleted(SSLSession session) {
                            successfulHandshakes.incrementAndGet();
                        }
                    })
                    .buildPrototype();
            URI issuer = URI.create("https://" + hostname + ":" + server.port());
            OidcTenantConfig tenant = OidcTenantConfig.builder()
                    .issuer(issuer.toString())
                    .clientId(CLIENT_ID)
                    .clientSecret(CLIENT_SECRET)
                    .webClient(webClient)
                    .endpoints(endpoints -> endpoints
                            .authorizationEndpointUri(issuer.resolve("/authorize"))
                            .tokenEndpointUri(issuer.resolve("/token"))
                            .jwksUri(issuer.resolve("/jwks"))
                            .pushedAuthorizationRequestEndpointUri(issuer.resolve("/par"))
                            .tlsRequired(false)) // Only the RP callback is local HTTP; OP endpoints are HTTPS.
                    .authorizationCode(code -> {
                        code.redirectionEndpointUri(URI.create("http://127.0.0.1/oidc/callback"))
                                .pushedAuthorizationRequests(OidcPushedAuthorizationRequestMode.REQUIRED);
                        if (signedJar) {
                            code.requestObject(requestObject -> requestObject
                                    .mode(OidcRequestObjectMode.REQUIRED)
                                    .signingJwk(jwk -> jwk.resourcePath("oidc-next-sign-jwk.json"))
                                    .signingKeyId("sign-rsa")
                                    .signingAlgorithm("RS256"));
                        }
                    })
                    .cookies(cookies -> cookies.password("test-tls-identity-cookie-password"))
                    .buildPrototype();
            try (OidcProvider provider = OidcProvider.create(OidcProviderConfig.builder()
                    .putTenant("default", tenant).buildPrototype())) {
                AuthenticationResponse result = provider.authenticate(OidcProviderTest.request(null,
                        SecurityEnvironment.builder().targetUri(URI.create("http://127.0.0.1/resource"))
                                .path("/resource").transport("http").build()));
                assertThat("PAR response for " + certificate + " at " + hostname
                                   + ": " + result.description().orElse("<none>")
                                   + ", sockets=" + connected.get()
                                   + ", accepted TLS=" + successfulHandshakes.get()
                                   + ", PAR requests=" + parRequests.get(),
                           result.statusCode().orElseThrow(),
                           is(accepted ? Status.SEE_OTHER_303_CODE : Status.SERVICE_UNAVAILABLE_503_CODE));
            }
            assertThat("TLS socket established", connected.get(), greaterThan(0));
            assertThat("configured listener follows successful identity verification", successfulHandshakes.get(),
                       is(accepted ? 1 : 0));
            assertThat("rejected TLS identity must not transmit a PAR request", parRequests.get(),
                       is(accepted ? 1 : 0));
            if (accepted) {
                assertThat(authorization.get(),
                           is(OidcClientAuthenticationSupport.basicAuthorization(CLIENT_ID, CLIENT_SECRET)));
                if (signedJar) {
                    List<String> requestObjectValues = requestObjects.get();
                    assertThat(requestObjectValues.size(), is(1));
                    JwkKeys keys = JwkKeys.builder().resource(Resource.create("oidc-next-sign-jwk.json")).build();
                    SignedJwt.parseToken(requestObjectValues.getFirst()).verifySignature(keys).checkValid();
                } else {
                    assertThat(requestObjects.get().isEmpty(), is(true));
                }
            } else {
                assertThat(authorization.get(), nullValue());
                assertThat(requestObjects.get(), is(List.of()));
            }
        } finally {
            server.stop();
        }
    }

    private static Keys serverKeys(String certificate) {
        if ("server".equals(certificate)) {
            return Keys.builder().keystore(store -> store.passphrase("password")
                    .keystore(Resource.create("server.p12"))).build();
        }
        return Keys.builder().pem(pem -> pem
                .key(Resource.create("oidc-next-tls-" + certificate + ".key"))
                .certChain(Resource.create("oidc-next-tls-" + certificate + ".crt"))).build();
    }
}
