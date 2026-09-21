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

import java.io.InputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;

import io.helidon.common.configurable.Resource;
import io.helidon.common.configurable.ResourceConfig;
import io.helidon.common.configurable.ResourceException;
import io.helidon.common.parameters.Parameters;
import io.helidon.security.jwt.Jwt;
import io.helidon.security.jwt.SignedJwt;
import io.helidon.security.jwt.jwk.JwkKeys;
import io.helidon.security.jwt.jwk.JwkRSA;
import io.helidon.webclient.api.WebClient;

import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class OidcClientAssertionReuseTest {
    private static final String KEY_RESOURCE = "oidc-next-sign-jwk.json";
    private static final URI TOKEN_ENDPOINT = URI.create("https://issuer.example/token");
    private static final URI INTROSPECTION_ENDPOINT = URI.create("https://issuer.example/introspect");
    private static final String TOKEN_CLIENT = "oauth-client";
    private static final String INTROSPECTION_CLIENT = "resource-server";

    private static JwkKeys verificationKeys;

    @BeforeAll
    static void setupKeys() {
        verificationKeys = JwkKeys.builder().resource(Resource.create(KEY_RESOURCE)).build();
    }

    @Test
    void classpathKeyDescriptionSupportsTokenAndInheritedIntrospection() throws Exception {
        OidcTenantConfig tenant = tenant(ResourceConfig.builder().resourcePath(KEY_RESOURCE).buildPrototype());

        OidcClientAuthenticationSupport token = OidcClientAuthenticationSupport.tokenEndpoint(tenant);
        OidcClientAuthenticationSupport introspection = OidcClientAuthenticationSupport.introspectionEndpoint(tenant);
        WebClient client = WebClient.create();
        try {
            Jwt tokenAssertion = tokenAssertion(token, client);
            Jwt introspectionAssertion = introspectionAssertion(introspection, client);

            assertClaims(tokenAssertion, TOKEN_CLIENT, TOKEN_ENDPOINT);
            assertClaims(introspectionAssertion, INTROSPECTION_CLIENT, INTROSPECTION_ENDPOINT);
            assertThat(introspectionAssertion.jwtId(), not(tokenAssertion.jwtId()));
        } finally {
            client.closeResource();
        }
    }

    @Test
    void repeatedConstructionSupportsTheSameResourceConfiguration() throws Exception {
        OidcTenantConfig tenant = tenant(ResourceConfig.builder().resourcePath(KEY_RESOURCE).buildPrototype());
        OidcClientAuthenticationSupport first = OidcClientAuthenticationSupport.tokenEndpoint(tenant);
        OidcClientAuthenticationSupport second = OidcClientAuthenticationSupport.tokenEndpoint(tenant);
        WebClient client = WebClient.create();
        try {
            Jwt firstAssertion = tokenAssertion(first, client);
            Jwt secondAssertion = tokenAssertion(second, client);

            assertClaims(firstAssertion, TOKEN_CLIENT, TOKEN_ENDPOINT);
            assertClaims(secondAssertion, TOKEN_CLIENT, TOKEN_ENDPOINT);
            assertThat(secondAssertion.jwtId(), not(firstAssertion.jwtId()));
        } finally {
            client.closeResource();
        }
    }

    @Test
    void suppliedKeyContentSupportsBothEndpoints() throws Exception {
        ResourceConfig resource = ResourceConfig.builder().contentPlain(Resource.create(KEY_RESOURCE).string()).buildPrototype();
        OidcTenantConfig tenant = tenant(resource);
        OidcClientAuthenticationSupport token = OidcClientAuthenticationSupport.tokenEndpoint(tenant);
        OidcClientAuthenticationSupport introspection = OidcClientAuthenticationSupport.introspectionEndpoint(tenant);
        WebClient client = WebClient.create();
        try {
            assertClaims(tokenAssertion(token, client), TOKEN_CLIENT, TOKEN_ENDPOINT);
            assertClaims(introspectionAssertion(introspection, client), INTROSPECTION_CLIENT, INTROSPECTION_ENDPOINT);
        } finally {
            client.closeResource();
        }
    }

    @Test
    void concurrentVirtualThreadsCreateIndependentAssertionsFromSharedConfiguration() throws Exception {
        ResourceConfig resource = ResourceConfig.builder().resourcePath(KEY_RESOURCE).buildPrototype();
        OidcTenantConfig tenant = tenant(resource);
        CountDownLatch start = new CountDownLatch(1);
        WebClient client = WebClient.create();
        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<Jwt>> assertions;
            try {
                assertions = IntStream.range(0, 128)
                        .mapToObj(index -> executor.submit(() -> {
                            start.await();
                            assertThat(Thread.currentThread().isVirtual(), is(true));
                            return index % 2 == 0
                                    ? tokenAssertion(OidcClientAuthenticationSupport.tokenEndpoint(tenant), client)
                                    : introspectionAssertion(OidcClientAuthenticationSupport.introspectionEndpoint(tenant), client);
                        }))
                        .toList();
            } finally {
                start.countDown();
            }
            Set<String> ids = new HashSet<>();
            for (int i = 0; i < assertions.size(); i++) {
                Jwt assertion = assertions.get(i).get(20, TimeUnit.SECONDS);
                assertClaims(assertion,
                             i % 2 == 0 ? TOKEN_CLIENT : INTROSPECTION_CLIENT,
                             i % 2 == 0 ? TOKEN_ENDPOINT : INTROSPECTION_ENDPOINT);
                assertThat(ids.add(assertion.jwtId().orElseThrow()), is(true));
            }
            assertThat(ids.size(), is(128));
        } finally {
            start.countDown();
            client.closeResource();
        }
    }

    @Test
    void copiedConfigurationKeepsIndependentAlgorithmAndLifetime() throws Exception {
        OidcTenantConfig tokenTenant = tenant(ResourceConfig.builder().resourcePath(KEY_RESOURCE).buildPrototype());
        OidcClientAssertionConfig override = OidcClientAssertionConfig.builder(tokenTenant.clientAssertion())
                .algorithm("RS512")
                .lifetime(Duration.ofSeconds(20))
                .buildPrototype();
        OidcTenantConfig introspectionTenant = OidcTenantConfig.builder(tokenTenant)
                .protectedResource(resource -> resource.tokenValidation(validation -> validation
                        .method(OidcTokenValidationMethod.INTROSPECTION)
                        .audience("api://resource")
                        .introspection(introspection -> introspection
                                .clientId(INTROSPECTION_CLIENT)
                                .authenticationMethod(OidcClientAuthenticationMethod.PRIVATE_KEY_JWT)
                                .clientAssertion(override))))
                .buildPrototype();
        WebClient client = WebClient.create();
        try {
            Jwt firstToken = tokenAssertion(OidcClientAuthenticationSupport.tokenEndpoint(tokenTenant), client);
            Jwt introspection = introspectionAssertion(
                    OidcClientAuthenticationSupport.introspectionEndpoint(introspectionTenant), client);
            Jwt nextToken = tokenAssertion(OidcClientAuthenticationSupport.tokenEndpoint(tokenTenant), client);

            assertClaims(firstToken, TOKEN_CLIENT, TOKEN_ENDPOINT);
            assertClaims(introspection, INTROSPECTION_CLIENT, INTROSPECTION_ENDPOINT, "RS512", Duration.ofSeconds(20));
            assertClaims(nextToken, TOKEN_CLIENT, TOKEN_ENDPOINT);
            assertThat(nextToken.jwtId(), not(firstToken.jwtId()));
        } finally {
            client.closeResource();
        }
    }

    @Test
    void invalidKeySelectionDoesNotPreventOtherResourceConsumers() throws Exception {
        OidcTenantConfig valid = tenant(ResourceConfig.builder().resourcePath(KEY_RESOURCE).buildPrototype());
        OidcTenantConfig invalid = OidcTenantConfig.builder(valid)
                .clientAssertion(OidcClientAssertionConfig.builder(valid.clientAssertion())
                                         .keyId("sign-oct")
                                         .buildPrototype())
                .buildPrototype();

        assertThrows(IllegalArgumentException.class, () -> OidcClientAuthenticationSupport.tokenEndpoint(invalid));
        WebClient client = WebClient.create();
        try {
            assertClaims(tokenAssertion(OidcClientAuthenticationSupport.tokenEndpoint(valid), client), TOKEN_CLIENT, TOKEN_ENDPOINT);
        } finally {
            client.closeResource();
        }
    }

    @Test
    void sharedKeyMaterialDoesNotShareClientIdentity() throws Exception {
        OidcTenantConfig original = tenant(ResourceConfig.builder().resourcePath(KEY_RESOURCE).buildPrototype());
        OidcTenantConfig other = OidcTenantConfig.builder(original).clientId("other-client").buildPrototype();
        WebClient client = WebClient.create();
        try {
            Jwt originalAssertion = tokenAssertion(OidcClientAuthenticationSupport.tokenEndpoint(original), client);
            Jwt otherAssertion = tokenAssertion(OidcClientAuthenticationSupport.tokenEndpoint(other), client);

            assertClaims(originalAssertion, TOKEN_CLIENT, TOKEN_ENDPOINT);
            assertClaims(otherAssertion, "other-client", TOKEN_ENDPOINT);
            assertThat(otherAssertion.jwtId(), not(originalAssertion.jwtId()));
        } finally {
            client.closeResource();
        }
    }

    @Test
    void parAssertionUsesIssuerAudienceAndRemainsFresh() throws Exception {
        OidcClientAuthenticationSupport support = OidcClientAuthenticationSupport.tokenEndpoint(
                tenant(ResourceConfig.builder().resourcePath(KEY_RESOURCE).buildPrototype()));
        URI parEndpoint = URI.create("https://issuer.example/par");
        URI issuer = URI.create("https://issuer.example");
        WebClient client = WebClient.create();
        try {
            Jwt token = tokenAssertion(support, client);
            Parameters.Builder first = Parameters.builder("first-par");
            Parameters.Builder second = Parameters.builder("second-par");
            support.applyPushedAuthorizationRequestAuthentication(parEndpoint, Optional.of(issuer.toString()), first,
                                                                  client.post().uri(parEndpoint), false);
            support.applyPushedAuthorizationRequestAuthentication(parEndpoint, Optional.of(issuer.toString()), second,
                                                                  client.post().uri(parEndpoint), false);
            Jwt firstAssertion = verifiedAssertion(first.build());
            Jwt secondAssertion = verifiedAssertion(second.build());

            assertClaims(firstAssertion, TOKEN_CLIENT, issuer);
            assertClaims(secondAssertion, TOKEN_CLIENT, issuer);
            assertThat(firstAssertion.jwtId(), not(token.jwtId()));
            assertThat(secondAssertion.jwtId(), not(firstAssertion.jwtId()));
        } finally {
            client.closeResource();
        }
    }

    @Test
    void failedLocalLoadDoesNotPoisonTheResourceDescription(@TempDir Path directory) throws Exception {
        Path path = directory.resolve("signing.jwk");
        OidcTenantConfig tenant = tenant(ResourceConfig.builder().path(path).buildPrototype());
        assertThrows(ResourceException.class, () -> OidcClientAuthenticationSupport.tokenEndpoint(tenant));
        Files.write(path, Resource.create(KEY_RESOURCE).bytes());

        WebClient client = WebClient.create();
        try {
            assertClaims(tokenAssertion(OidcClientAuthenticationSupport.tokenEndpoint(tenant), client), TOKEN_CLIENT, TOKEN_ENDPOINT);
        } finally {
            client.closeResource();
        }
    }

    @Test
    void consumedResourceDoesNotAffectAnotherConsumerOfTheDescription() throws Exception {
        ResourceConfig resource = ResourceConfig.builder().resourcePath(KEY_RESOURCE).buildPrototype();
        try (InputStream input = resource.build().stream()) {
            input.readAllBytes();
        }
        WebClient client = WebClient.create();
        try {
            assertClaims(tokenAssertion(OidcClientAuthenticationSupport.tokenEndpoint(tenant(resource)), client),
                         TOKEN_CLIENT, TOKEN_ENDPOINT);
        } finally {
            client.closeResource();
        }
    }

    private static OidcTenantConfig tenant(ResourceConfig resource) {
        return OidcTenantConfig.builder()
                .issuer("https://issuer.example")
                .clientId(TOKEN_CLIENT)
                .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.PRIVATE_KEY_JWT)
                .clientAssertion(assertion -> assertion.jwk(resource).keyId("sign-rsa").algorithm("RS256"))
                .endpoints(endpoints -> endpoints.tokenEndpointUri(TOKEN_ENDPOINT)
                        .introspectionEndpointUri(INTROSPECTION_ENDPOINT))
                .protectedResource(protectedResource -> protectedResource.tokenValidation(validation -> validation
                        .method(OidcTokenValidationMethod.INTROSPECTION)
                        .audience("api://resource")
                        .introspection(introspection -> introspection
                                .clientId(INTROSPECTION_CLIENT)
                                .authenticationMethod(OidcClientAuthenticationMethod.PRIVATE_KEY_JWT))))
                .buildPrototype();
    }

    private static Jwt tokenAssertion(OidcClientAuthenticationSupport support, WebClient client) throws Exception {
        Parameters.Builder form = Parameters.builder("token");
        support.applyTokenEndpointAuthentication(TOKEN_ENDPOINT, form, client.post().uri(TOKEN_ENDPOINT));
        return verifiedAssertion(form.build());
    }

    private static Jwt introspectionAssertion(OidcClientAuthenticationSupport support, WebClient client) throws Exception {
        Parameters.Builder form = Parameters.builder("introspection");
        support.applyIntrospectionEndpointAuthentication(INTROSPECTION_ENDPOINT,
                                                         form,
                                                         client.post().uri(INTROSPECTION_ENDPOINT));
        return verifiedAssertion(form.build());
    }

    private static Jwt verifiedAssertion(Parameters form) throws Exception {
        assertThat(form.first("client_assertion_type").orElseThrow(),
                   is("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"));
        String assertion = form.first("client_assertion").orElseThrow();
        SignedJwt signed = SignedJwt.parseToken(assertion);
        JwkRSA rsa = (JwkRSA) verificationKeys.forKeyId("sign-rsa").orElseThrow();
        // Verify with an independent JWT implementation, including algorithm-specific RSA signatures.
        assertThat(SignedJWT.parse(assertion).verify(new RSASSAVerifier((RSAPublicKey) rsa.publicKey())), is(true));
        return signed.getJwt();
    }

    private static void assertClaims(Jwt assertion, String clientId, URI audience) {
        assertClaims(assertion, clientId, audience, "RS256", Duration.ofMinutes(1));
    }

    private static void assertClaims(Jwt assertion, String clientId, URI audience, String algorithm, Duration lifetime) {
        assertThat(assertion.algorithm().orElseThrow(), is(algorithm));
        assertThat(assertion.keyId().orElseThrow(), is("sign-rsa"));
        assertThat(assertion.issuer().orElseThrow(), is(clientId));
        assertThat(assertion.subject().orElseThrow(), is(clientId));
        assertThat(assertion.audience().orElseThrow(), is(List.of(audience.toString())));
        assertThat(assertion.jwtId().orElseThrow().isBlank(), is(false));
        assertThat(Duration.between(assertion.issueTime().orElseThrow(), assertion.expirationTime().orElseThrow()),
                   is(lifetime));
        assertThat(assertion.payloadClaimsJson().keySet(), is(Set.of("iss", "sub", "aud", "jti", "iat", "exp")));
    }
}
