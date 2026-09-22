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
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import io.helidon.common.configurable.Resource;
import io.helidon.common.parameters.Parameters;
import io.helidon.common.pki.Keys;
import io.helidon.common.tls.Tls;
import io.helidon.common.tls.TlsClientAuth;
import io.helidon.config.Config;
import io.helidon.config.ConfigSources;
import io.helidon.http.HeaderNames;
import io.helidon.http.HeaderValues;
import io.helidon.http.Status;
import io.helidon.json.JsonObject;
import io.helidon.security.AuthenticationResponse;
import io.helidon.security.EndpointConfig;
import io.helidon.security.Principal;
import io.helidon.security.ProviderRequest;
import io.helidon.security.SecurityContext;
import io.helidon.security.SecurityEnvironment;
import io.helidon.security.SecurityResponse;
import io.helidon.security.Subject;
import io.helidon.security.jwt.Jwt;
import io.helidon.security.jwt.SignedJwt;
import io.helidon.security.jwt.jwk.JwkKeys;
import io.helidon.security.providers.common.OutboundTarget;
import io.helidon.security.providers.common.TokenCredential;
import io.helidon.webclient.api.HttpClientResponse;
import io.helidon.webclient.api.WebClient;
import io.helidon.webclient.api.WebClientConfig;
import io.helidon.webserver.WebServer;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;

class OidcTokenPropagationTest {
    private static final String ACCESS_TOKEN = "access-token";
    private static final String EXISTING_HEADER_NAME = "X-Existing";
    private static final String EXISTING_HEADER_VALUE = "existing-value";

    @TestFactory
    Stream<DynamicTest> propagatedTokensRetainTheirCertificateBindingOnTheDownstreamConnection() {
        return Stream.of(OidcTokenValidationMethod.JWT, OidcTokenValidationMethod.INTROSPECTION)
                .flatMap(method -> Stream.of(true, false).flatMap(bound -> Stream.of("static", "omitted", "false", "true")
                        .map(metadataSupport -> dynamicTest(method + " bound=" + bound + " metadata=" + metadataSupport,
                                () -> verifyDownstreamCertificateBinding(method, bound, metadataSupport)))));
    }

    @Test
    void tokenPropagationOnlyAppliesToMatchingOutboundTarget() {
        OidcProvider provider = provider(OidcTenantConfig.create(), ordersTarget());
        ProviderRequest request = providerRequest(subject("api://orders"));
        SecurityEnvironment outboundEnv = outboundEnvironment("https://api.example.com/orders/42", "/orders/42");

        var response = provider.outboundSecurity(request, outboundEnv, EndpointConfig.create());

        assertThat(provider.isOutboundSupported(request, outboundEnv, EndpointConfig.create()), is(true));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer " + ACCESS_TOKEN)));
        assertThat(response.requestHeaders().get(EXISTING_HEADER_NAME), is(List.of(EXISTING_HEADER_VALUE)));
    }

    @Test
    void rootSingleTenantOutboundTargetSupportsTokenPropagationWithoutNamedTenant() {
        OidcProvider provider = OidcProvider.create(OidcProviderConfig.builder()
                .outboundTargets(List.of(ordersTarget()))
                .buildPrototype());
        ProviderRequest request = providerRequest(subject("api://orders"));
        SecurityEnvironment outboundEnv = outboundEnvironment("https://api.example.com/orders/42", "/orders/42");

        var response = provider.outboundSecurity(request, outboundEnv, EndpointConfig.create());

        assertThat(provider.isOutboundSupported(request, outboundEnv, EndpointConfig.create()), is(true));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer " + ACCESS_TOKEN)));
    }

    @Test
    void tokenPropagationReplacesExistingAuthorizationHeaderCaseInsensitively() {
        OidcProvider provider = provider(OidcTenantConfig.create(), ordersTarget());
        ProviderRequest request = providerRequest(subject("api://orders"));
        SecurityEnvironment outboundEnv = SecurityEnvironment.builder()
                .targetUri(URI.create("https://api.example.com/orders/42"))
                .transport("https")
                .path("/orders/42")
                .method("GET")
                .header("authorization", "Bearer stale-token")
                .build();

        var response = provider.outboundSecurity(request, outboundEnv, EndpointConfig.create());

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer " + ACCESS_TOKEN)));
        assertThat(response.requestHeaders().containsKey("authorization"), is(false));
    }

    @Test
    void tokenPropagationCanUseRawTokenCredentialWhenAudienceValidationIsDisabled() {
        OidcProvider provider = provider(OidcTenantConfig.create(), ordersTargetWithoutAudienceValidation());
        ProviderRequest request = providerRequest(subjectWithRawToken());
        SecurityEnvironment outboundEnv = outboundEnvironment("https://api.example.com/orders/42", "/orders/42");

        var response = provider.outboundSecurity(request, outboundEnv, EndpointConfig.create());

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer " + ACCESS_TOKEN)));
    }

    @Test
    void tokenPropagationMatchesHttpsUriWhenEnvironmentTransportIsStale() {
        OidcProvider provider = provider(OidcTenantConfig.create(), ordersTarget());
        ProviderRequest request = providerRequest(subject("api://orders"));
        SecurityEnvironment outboundEnv = SecurityEnvironment.builder()
                .targetUri(URI.create("https://api.example.com/orders/42"))
                .transport("http")
                .path("/orders/42")
                .method("GET")
                .build();

        var response = provider.outboundSecurity(request, outboundEnv, EndpointConfig.create());

        assertThat(provider.isOutboundSupported(request, outboundEnv, EndpointConfig.create()), is(true));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer " + ACCESS_TOKEN)));
    }

    @Test
    void tokenPropagationMatchesUppercaseHttpsUriScheme() {
        OidcProvider provider = provider(OidcTenantConfig.create(), ordersTarget());
        ProviderRequest request = providerRequest(subject("api://orders"));
        SecurityEnvironment outboundEnv = outboundEnvironment("HTTPS://api.example.com/orders/42", "/orders/42");

        var response = provider.outboundSecurity(request, outboundEnv, EndpointConfig.create());

        assertThat(provider.isOutboundSupported(request, outboundEnv, EndpointConfig.create()), is(true));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer " + ACCESS_TOKEN)));
    }

    @Test
    void tokenPropagationDoesNotApplyToArbitraryHost() {
        OidcProvider provider = provider(OidcTenantConfig.create(), ordersTarget());
        ProviderRequest request = providerRequest(subject("api://orders"));
        SecurityEnvironment outboundEnv = outboundEnvironment("https://other.example.com/orders/42", "/orders/42");

        var response = provider.outboundSecurity(request, outboundEnv, EndpointConfig.create());

        assertThat(provider.isOutboundSupported(request, outboundEnv, EndpointConfig.create()), is(false));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.ABSTAIN));
    }

    @Test
    void tokenPropagationDoesNotApplyWhenTransportDiffersFromUriScheme() {
        OidcProvider provider = provider(OidcTenantConfig.create(), ordersTarget());
        ProviderRequest request = providerRequest(subject("api://orders"));
        SecurityEnvironment outboundEnv = SecurityEnvironment.builder()
                .targetUri(URI.create("http://api.example.com/orders/42"))
                .transport("https")
                .path("/orders/42")
                .method("GET")
                .build();

        var response = provider.outboundSecurity(request, outboundEnv, EndpointConfig.create());

        assertThat(provider.isOutboundSupported(request, outboundEnv, EndpointConfig.create()), is(false));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.ABSTAIN));
    }

    @Test
    void tokenPropagationDoesNotApplyToHttpTargetWhenTlsIsRequired() {
        OidcProvider provider = provider(OidcTenantConfig.create(), ordersTargetForAllTransports());
        ProviderRequest request = providerRequest(subject("api://orders"));
        SecurityEnvironment outboundEnv = outboundEnvironment("http://api.example.com/orders/42", "/orders/42");

        var response = provider.outboundSecurity(request, outboundEnv, EndpointConfig.create());

        assertThat(provider.isOutboundSupported(request, outboundEnv, EndpointConfig.create()), is(false));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.ABSTAIN));
    }

    @Test
    void endpointTokenPropagationDoesNotApplyWhenTargetUriIsMissingAndTlsIsRequired() {
        OidcProvider provider = provider(OidcTenantConfig.create());
        ProviderRequest request = providerRequest(subject("api://orders"));
        SecurityEnvironment outboundEnv = SecurityEnvironment.builder()
                .transport("https")
                .path("/orders/42")
                .method("GET")
                .build();
        EndpointConfig outboundConfig = EndpointConfig.builder()
                .customObject(OidcOutboundPolicy.class, OidcOutboundPolicy.tokenPropagation("api://orders"))
                .build();

        var response = provider.outboundSecurity(request, outboundEnv, outboundConfig);

        assertThat(provider.isOutboundSupported(request, outboundEnv, outboundConfig), is(false));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.ABSTAIN));
    }

    @Test
    void endpointTokenPropagationDoesNotApplyWhenTargetUriHasNoSchemeAndTlsIsRequired() {
        OidcProvider provider = provider(OidcTenantConfig.create());
        ProviderRequest request = providerRequest(subject("api://orders"));
        SecurityEnvironment outboundEnv = SecurityEnvironment.builder()
                .targetUri(URI.create("/orders/42"))
                .transport("https")
                .path("/orders/42")
                .method("GET")
                .build();
        EndpointConfig outboundConfig = EndpointConfig.builder()
                .customObject(OidcOutboundPolicy.class, OidcOutboundPolicy.tokenPropagation("api://orders"))
                .build();

        var response = provider.outboundSecurity(request, outboundEnv, outboundConfig);

        assertThat(provider.isOutboundSupported(request, outboundEnv, outboundConfig), is(false));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.ABSTAIN));
    }

    @Test
    void tokenPropagationDoesNotApplyToOtherPath() {
        OidcProvider provider = provider(OidcTenantConfig.create(), ordersTarget());
        ProviderRequest request = providerRequest(subject("api://orders"));
        SecurityEnvironment outboundEnv = outboundEnvironment("https://api.example.com/billing/42", "/billing/42");

        var response = provider.outboundSecurity(request, outboundEnv, EndpointConfig.create());

        assertThat(provider.isOutboundSupported(request, outboundEnv, EndpointConfig.create()), is(false));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.ABSTAIN));
    }

    @Test
    void tokenPropagationDoesNotApplyToOtherMethod() {
        OidcProvider provider = provider(OidcTenantConfig.create(), ordersTarget());
        ProviderRequest request = providerRequest(subject("api://orders"));
        SecurityEnvironment outboundEnv = outboundEnvironment("https://api.example.com/orders/42", "/orders/42", "POST");

        var response = provider.outboundSecurity(request, outboundEnv, EndpointConfig.create());

        assertThat(provider.isOutboundSupported(request, outboundEnv, EndpointConfig.create()), is(false));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.ABSTAIN));
    }

    @Test
    void tokenPropagationRequiresConfiguredTarget() {
        OidcProvider provider = provider(OidcTenantConfig.create());
        ProviderRequest request = providerRequest(subject("api://orders"));
        SecurityEnvironment outboundEnv = outboundEnvironment("https://api.example.com/orders/42", "/orders/42");

        var response = provider.outboundSecurity(request, outboundEnv, EndpointConfig.create());

        assertThat(provider.isOutboundSupported(request, outboundEnv, EndpointConfig.create()), is(false));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.ABSTAIN));
    }

    @Test
    void audienceRestrictionAllowsMatchingToken() {
        OidcProvider provider = provider(OidcTenantConfig.create(), ordersTarget("api://orders"));
        ProviderRequest request = providerRequest(subject("api://orders"));
        SecurityEnvironment outboundEnv = outboundEnvironment("https://api.example.com/orders/42", "/orders/42");

        var response = provider.outboundSecurity(request, outboundEnv, EndpointConfig.create());

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer " + ACCESS_TOKEN)));
    }

    @Test
    void audienceRestrictionAllowsIntrospectionClaims() {
        OidcProvider provider = provider(OidcTenantConfig.create(), ordersTarget("api://orders"));
        ProviderRequest request = providerRequest(subjectWithJsonAudience("api://orders"));
        SecurityEnvironment outboundEnv = outboundEnvironment("https://api.example.com/orders/42", "/orders/42");

        var response = provider.outboundSecurity(request, outboundEnv, EndpointConfig.create());

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer " + ACCESS_TOKEN)));
    }

    @Test
    void audienceRestrictionRejectsMismatchedToken() {
        OidcProvider provider = provider(OidcTenantConfig.create(), ordersTarget("api://billing"));
        ProviderRequest request = providerRequest(subject("api://orders"));
        SecurityEnvironment outboundEnv = outboundEnvironment("https://api.example.com/orders/42", "/orders/42");

        var response = provider.outboundSecurity(request, outboundEnv, EndpointConfig.create());

        assertThat(provider.isOutboundSupported(request, outboundEnv, EndpointConfig.create()), is(true));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.ABSTAIN));
    }

    @Test
    void audienceRestrictionRejectsRawTokenWithoutParsedClaims() {
        OidcProvider provider = provider(OidcTenantConfig.create(), ordersTarget("api://orders"));
        ProviderRequest request = providerRequest(subjectWithRawToken());
        SecurityEnvironment outboundEnv = outboundEnvironment("https://api.example.com/orders/42", "/orders/42");

        var response = provider.outboundSecurity(request, outboundEnv, EndpointConfig.create());

        assertThat(provider.isOutboundSupported(request, outboundEnv, EndpointConfig.create()), is(true));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.ABSTAIN));
    }

    @Test
    void tokenPropagationRequiresAudienceWhenAudienceValidationIsEnabled() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                                                       () -> OidcOutboundTargetConfig.builder()
                                                               .tokenPropagationEnabled(true)
                                                               .buildPrototype());

        assertThat(thrown.getMessage(), containsString("audience must be configured"));
    }

    @Test
    void targetConfigurationCanDisablePropagationAudienceValidation() {
        Config config = Config.builder()
                .sources(ConfigSources.create(Map.ofEntries(
                        Map.entry("tenants.default.enabled", "true"),
                        Map.entry("outbound.0.name", "orders"),
                        Map.entry("outbound.0.transports.0", "https"),
                        Map.entry("outbound.0.hosts.0", "api.example.com"),
                        Map.entry("outbound.0.paths.0", "/orders/.*"),
                        Map.entry("outbound.0.methods.0", "GET"),
                        Map.entry("outbound.0.token-propagation-enabled", "true"),
                        Map.entry("outbound.0.audience-validation-enabled", "false"))))
                .build();
        OidcProvider provider = OidcProvider.create(OidcProviderConfig.create(config));
        ProviderRequest request = providerRequest(subjectWithRawToken());
        SecurityEnvironment outboundEnv = outboundEnvironment("https://api.example.com/orders/42", "/orders/42");

        var response = provider.outboundSecurity(request, outboundEnv, EndpointConfig.create());

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer " + ACCESS_TOKEN)));
    }

    @Test
    void targetConfigurationCanSelectTokenPropagationAndAudience() {
        Config config = Config.builder()
                .sources(ConfigSources.create(Map.ofEntries(
                        Map.entry("tenants.default.enabled", "true"),
                        Map.entry("outbound.0.name", "orders"),
                        Map.entry("outbound.0.transports.0", "https"),
                        Map.entry("outbound.0.hosts.0", "api.example.com"),
                        Map.entry("outbound.0.paths.0", "/orders/.*"),
                        Map.entry("outbound.0.methods.0", "GET"),
                        Map.entry("outbound.0.token-propagation-enabled", "true"),
                        Map.entry("outbound.0.audience", "api://orders"))))
                .build();
        OidcProvider provider = OidcProvider.create(OidcProviderConfig.create(config));
        ProviderRequest request = providerRequest(subject("api://orders"));
        SecurityEnvironment outboundEnv = outboundEnvironment("https://api.example.com/orders/42", "/orders/42");

        var response = provider.outboundSecurity(request, outboundEnv, EndpointConfig.create());

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer " + ACCESS_TOKEN)));
    }

    private static void verifyDownstreamCertificateBinding(OidcTokenValidationMethod method,
                                                          boolean bound,
                                                          String metadataSupport) {
        Keys callerKeys = Keys.builder()
                .keystore(store -> store.passphrase("password").keystore(Resource.create("client.p12"))).build();
        Keys serverKeys = Keys.builder()
                .keystore(store -> store.passphrase("password").keystore(Resource.create("server.p12"))).build();
        String callerThumbprint = OidcTestCertificates.thumbprint(callerKeys.publicCert().orElseThrow());
        String otherThumbprint = OidcTestCertificates.thumbprint(serverKeys.publicCert().orElseThrow());
        Tls serverTls = Tls.builder().privateKey(serverKeys).privateKeyCertChain(serverKeys)
                .trust(callerKeys.certChain()).clientAuth(TlsClientAuth.OPTIONAL).build();
        Tls callerTls = Tls.builder().privateKey(callerKeys).privateKeyCertChain(callerKeys)
                .trust(serverKeys.certChain()).build();
        Tls otherTls = Tls.builder().privateKey(serverKeys).privateKeyCertChain(serverKeys)
                .trust(serverKeys.certChain()).build();
        Tls noCertificateTls = Tls.builder().trust(serverKeys.certChain()).build();
        Jwt.Builder claims = Jwt.builder().issuer("https://issuer.example").subject("user1").addAudience("api://orders")
                .algorithm("RS256").keyId("verify-rsa").type("at+jwt").jwtId("propagation-test")
                .issueTime(Instant.now()).expirationTime(Instant.now().plusSeconds(600))
                .addPayloadClaim("client_id", "calling-client");
        if (bound) {
            claims.addPayloadClaim("cnf", JsonObject.builder().set("x5t#S256", callerThumbprint).build());
        }
        Jwt jwt = claims.build();
        String token = method == OidcTokenValidationMethod.JWT
                ? SignedJwt.sign(jwt, JwkKeys.builder().resource(Resource.create("oidc-next-sign-jwk.json"))
                        .build().forKeyId("sign-rsa").orElseThrow()).tokenContent()
                : "opaque-propagated-token";
        JsonObject introspection = JsonObject.builder().from(jwt.payloadJsonObject())
                .set("active", true).set("token_type", "Bearer").build();
        String jwks = Resource.create("oidc-next-verify-public-jwk.json").string();
        AtomicReference<String> providerMetadata = new AtomicReference<>();
        WebServer issuer = WebServer.builder().port(0).tls(serverTls).routing(routing -> routing
                .get("/.well-known/openid-configuration", (_, response) -> response.header(HeaderValues.CONTENT_TYPE_JSON)
                        .send(providerMetadata.get()))
                .get("/jwks", (_, response) -> response.header(HeaderValues.CONTENT_TYPE_JSON).send(jwks))
                .post("/introspect", (request, response) -> {
                    assertThat(request.content().as(Parameters.class).first("token").orElseThrow(), is(token));
                    response.header(HeaderValues.CONTENT_TYPE_JSON).send(introspection.toString());
                })).build().start();
        try {
            URI issuerUri = URI.create("https://localhost:" + issuer.port());
            JsonObject.Builder metadata = JsonObject.builder().set("issuer", "https://issuer.example")
                    .set("jwks_uri", issuerUri.resolve("/jwks").toString())
                    .set("introspection_endpoint", issuerUri.resolve("/introspect").toString())
                    .setStrings("introspection_endpoint_auth_methods_supported", List.of("client_secret_basic"));
            if ("true".equals(metadataSupport) || "false".equals(metadataSupport)) {
                metadata.set("tls_client_certificate_bound_access_tokens", Boolean.parseBoolean(metadataSupport));
            }
            providerMetadata.set(metadata.build().toString());
            OidcTenantConfig tenant = OidcTenantConfig.builder().issuer("https://issuer.example")
                    .clientId("resource-client").clientSecret("resource-secret")
                    // OP/AS TLS credentials do not configure the application's downstream connection.
                    .webClient(WebClientConfig.builder().tls(callerTls).buildPrototype())
                    .endpoints(endpoints -> {
                        if ("static".equals(metadataSupport)) {
                            endpoints.jwksUri(issuerUri.resolve("/jwks"))
                                    .introspectionEndpointUri(issuerUri.resolve("/introspect"));
                        } else {
                            endpoints.wellKnownUri(issuerUri.resolve("/.well-known/openid-configuration"));
                        }
                    })
                    .protectedResource(resource -> resource.tokenValidation(validation -> validation.method(method)
                            .audience("api://orders")
                            .certificateBoundAccessTokens(binding -> binding
                                    .mode(OidcCertificateBoundAccessTokenMode.IF_PRESENT))))
                    .buildPrototype();
            OutboundTarget target = OutboundTarget.builder("orders").addHost("localhost").addTransport("https")
                    .addPath("/orders/.*").customObject(OidcOutboundTargetConfig.class, OidcOutboundTargetConfig.builder()
                            .tokenPropagationEnabled(true).audience("api://orders").buildPrototype()).build();
            try (OidcProvider forwardingProvider = provider(tenant, target);
                 OidcProvider receivingProvider = provider(tenant)) {
                SecurityEnvironment inbound = SecurityEnvironment.builder().targetUri(URI.create("https://service.example"))
                        .header(HeaderNames.AUTHORIZATION.defaultCase(), "Bearer " + token)
                        .addAttribute("remotePeer", OidcTestCertificates.peerInfo(callerKeys.publicCert().orElseThrow())).build();
                AuthenticationResponse authenticated = forwardingProvider.authenticate(OidcProviderTest.request(null, inbound));
                assertThat(authenticated.description().orElse("No authentication description"), authenticated.status(),
                           is(SecurityResponse.SecurityStatus.SUCCESS));
                ProviderRequest request = providerRequest(authenticated.user().orElseThrow());
                AtomicReference<String> peerThumbprint = new AtomicReference<>();
                WebServer downstream = WebServer.builder().port(0).tls(serverTls).routing(routing -> routing
                        .get("/orders/42", (received, response) -> {
                            peerThumbprint.set(received.remotePeer().tlsCertificates()
                                    .map(chain -> OidcTestCertificates.thumbprint(chain[0])).orElse("absent"));
                            AuthenticationResponse result = receivingProvider.authenticate(OidcProviderTest.request(null,
                                    SecurityEnvironment.builder().targetUri(URI.create("https://downstream.example/orders/42"))
                                            .header(HeaderNames.AUTHORIZATION.defaultCase(),
                                                    received.headers().first(HeaderNames.AUTHORIZATION).orElseThrow())
                                            .addAttribute("remotePeer", received.remotePeer()).build()));
                            result.responseHeaders().getOrDefault(HeaderNames.WWW_AUTHENTICATE.defaultCase(), List.of())
                                    .forEach(value -> response.header(HeaderNames.WWW_AUTHENTICATE, value));
                            response.status(result.statusCode().orElse(200)).send(result.status().name());
                        })).build().start();
                try {
                    URI downstreamUri = URI.create("https://localhost:" + downstream.port() + "/orders/42");
                    // Like WebClientSecurity, derived metadata may still describe the incoming peer, not outgoing proof.
                    SecurityEnvironment outbound = inbound.derive().clearHeaders().targetUri(downstreamUri)
                            .transport("https").path("/orders/42").method("GET").build();
                    for (EndpointConfig policy : List.of(EndpointConfig.create(), EndpointConfig.builder()
                            .customObject(OidcOutboundPolicy.class, OidcOutboundPolicy.tokenPropagation("api://orders"))
                            .build())) {
                        var propagated = forwardingProvider.outboundSecurity(request, outbound, policy);
                        assertThat(propagated.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
                        String authorization = propagated.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase())
                                .getFirst();
                        assertThat(authorization, is("Bearer " + token));
                        for (var transport : Map.of(callerThumbprint, callerTls,
                                                    otherThumbprint, otherTls,
                                                    "absent", noCertificateTls).entrySet()) {
                            WebClient client = WebClient.builder().tls(transport.getValue()).build();
                            try {
                                try (HttpClientResponse response = client.get(downstreamUri.toString())
                                        .header(HeaderNames.AUTHORIZATION, authorization).request()) {
                                    boolean validProof = !bound || transport.getKey().equals(callerThumbprint);
                                    assertThat(response.status(), is(validProof ? Status.OK_200 : Status.UNAUTHORIZED_401));
                                    assertThat(response.as(String.class), is(validProof ? "SUCCESS" : "FAILURE"));
                                    assertThat(peerThumbprint.get(), is(transport.getKey()));
                                    if (!validProof) {
                                        assertThat(response.headers().first(HeaderNames.WWW_AUTHENTICATE).orElseThrow(),
                                                   containsString("error=\"invalid_token\""));
                                    }
                                }
                            } finally {
                                client.closeResource();
                            }
                        }
                    }
                } finally {
                    downstream.stop();
                }
            }
        } finally {
            issuer.stop();
        }
    }

    private static OidcProvider provider(OidcTenantConfig tenant, OutboundTarget... outboundTargets) {
        return OidcProvider.create(OidcProviderConfig.builder()
                                           .putTenant("default", tenant)
                                           .outboundTargets(List.of(outboundTargets))
                                           .buildPrototype());
    }

    private static OutboundTarget ordersTarget() {
        return OutboundTarget.builder("orders")
                .addTransport("https")
                .addHost("api.example.com")
                .addPath("/orders/.*")
                .addMethod("GET")
                .customObject(OidcOutboundTargetConfig.class,
                              OidcOutboundTargetConfig.builder()
                                      .tokenPropagationEnabled(true)
                                      .audience("api://orders")
                                      .buildPrototype())
                .build();
    }

    private static OutboundTarget ordersTargetForAllTransports() {
        return OutboundTarget.builder("orders")
                .addHost("api.example.com")
                .addPath("/orders/.*")
                .addMethod("GET")
                .customObject(OidcOutboundTargetConfig.class,
                              OidcOutboundTargetConfig.builder()
                                      .tokenPropagationEnabled(true)
                                      .audience("api://orders")
                                      .buildPrototype())
                .build();
    }

    private static OutboundTarget ordersTargetWithoutAudienceValidation() {
        return OutboundTarget.builder("orders")
                .addTransport("https")
                .addHost("api.example.com")
                .addPath("/orders/.*")
                .addMethod("GET")
                .customObject(OidcOutboundTargetConfig.class,
                              OidcOutboundTargetConfig.builder()
                                      .tokenPropagationEnabled(true)
                                      .audienceValidationEnabled(false)
                                      .buildPrototype())
                .build();
    }

    private static OutboundTarget ordersTarget(String audience) {
        return OutboundTarget.builder("orders")
                .addTransport("https")
                .addHost("api.example.com")
                .addPath("/orders/.*")
                .addMethod("GET")
                .customObject(OidcOutboundTargetConfig.class,
                              OidcOutboundTargetConfig.builder()
                                      .tokenPropagationEnabled(true)
                                      .audience(audience)
                                      .buildPrototype())
                .build();
    }

    private static SecurityEnvironment outboundEnvironment(String targetUri, String path) {
        return outboundEnvironment(targetUri, path, "GET");
    }

    private static SecurityEnvironment outboundEnvironment(String targetUri, String path, String method) {
        URI uri = URI.create(targetUri);
        return SecurityEnvironment.builder()
                .targetUri(uri)
                .transport(uri.getScheme())
                .path(path)
                .method(method)
                .header(EXISTING_HEADER_NAME, EXISTING_HEADER_VALUE)
                .build();
    }

    private static Subject subject(String audience) {
        Jwt jwt = Jwt.builder()
                .issuer("https://issuer.example")
                .subject("user1")
                .audience(List.of(audience))
                .issueTime(Instant.now().minusSeconds(60))
                .expirationTime(Instant.now().plusSeconds(600))
                .build();
        TokenCredential credential = TokenCredential.builder()
                .token(ACCESS_TOKEN)
                .addToken(Jwt.class, jwt)
                .build();
        return Subject.builder()
                .principal(Principal.create("user1"))
                .addPublicCredential(TokenCredential.class, credential)
                .build();
    }

    private static Subject subjectWithRawToken() {
        TokenCredential credential = TokenCredential.builder()
                .token(ACCESS_TOKEN)
                .build();
        return Subject.builder()
                .principal(Principal.create("user1"))
                .addPublicCredential(TokenCredential.class, credential)
                .build();
    }

    private static Subject subjectWithJsonAudience(String audience) {
        JsonObject claims = JsonObject.builder()
                .setStrings("aud", List.of(audience))
                .build();
        TokenCredential credential = TokenCredential.builder()
                .token(ACCESS_TOKEN)
                .addToken(JsonObject.class, claims)
                .build();
        return Subject.builder()
                .principal(Principal.create("user1"))
                .addPublicCredential(TokenCredential.class, credential)
                .build();
    }

    private static ProviderRequest providerRequest(Subject subject) {
        return new TestProviderRequest(subject);
    }

    private static final class TestProviderRequest implements ProviderRequest {
        private final Subject subject;

        private TestProviderRequest(Subject subject) {
            this.subject = subject;
        }

        @Override
        public EndpointConfig endpointConfig() {
            return EndpointConfig.create();
        }

        @Override
        public SecurityContext securityContext() {
            return null;
        }

        @Override
        public Optional<Subject> subject() {
            return Optional.of(subject);
        }

        @Override
        public Optional<Subject> service() {
            return Optional.empty();
        }

        @Override
        public SecurityEnvironment env() {
            return SecurityEnvironment.create();
        }

        @Override
        public Optional<Object> getObject() {
            return Optional.empty();
        }

        @Override
        public Object abacAttributeRaw(String key) {
            return null;
        }

        @Override
        public Collection<String> abacAttributeNames() {
            return List.of();
        }
    }
}
