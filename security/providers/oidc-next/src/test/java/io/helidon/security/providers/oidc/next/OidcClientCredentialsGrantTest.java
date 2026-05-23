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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import io.helidon.common.parameters.Parameters;
import io.helidon.config.Config;
import io.helidon.config.ConfigSources;
import io.helidon.http.HeaderNames;
import io.helidon.http.HeaderValues;
import io.helidon.json.JsonObject;
import io.helidon.security.EndpointConfig;
import io.helidon.security.OutboundSecurityResponse;
import io.helidon.security.ProviderRequest;
import io.helidon.security.SecurityEnvironment;
import io.helidon.security.SecurityResponse;
import io.helidon.security.SecurityTime;
import io.helidon.security.providers.common.OutboundTarget;
import io.helidon.webserver.http.HttpRouting;
import io.helidon.webserver.http.ServerRequest;
import io.helidon.webserver.http.ServerResponse;
import io.helidon.webserver.testing.junit5.ServerTest;
import io.helidon.webserver.testing.junit5.SetUpRoute;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;

@ServerTest
@Execution(ExecutionMode.SAME_THREAD)
class OidcClientCredentialsGrantTest {
    private static final String CLIENT_ID = "client/id";
    private static final String CLIENT_SECRET = "client+secret=value";
    private static final String EXISTING_HEADER_NAME = "X-Existing";
    private static final String EXISTING_HEADER_VALUE = "existing-value";

    private static final AtomicInteger REQUEST_COUNT = new AtomicInteger();
    private static final AtomicInteger REDIRECTED_REQUEST_COUNT = new AtomicInteger();
    private static final AtomicReference<RecordedRequest> RECORDED_REQUEST = new AtomicReference<>();

    private static volatile int responseStatus;
    private static volatile String responseBody;
    private static volatile String providerMetadata;
    private static volatile String redirectLocation;
    private static volatile boolean dynamicTokenResponse;
    private static volatile Integer dynamicExpiresIn;

    private URI issuer;
    private URI tokenEndpointUri;
    private URI redirectedTokenEndpointUri;

    @SetUpRoute
    static void routing(HttpRouting.Builder routing) {
        routing.get("/.well-known/openid-configuration", (request, response) -> response
                .header(HeaderValues.CONTENT_TYPE_JSON)
                .send(providerMetadata));
        routing.post("/token", OidcClientCredentialsGrantTest::handleTokenEndpoint);
        routing.post("/redirected-token", OidcClientCredentialsGrantTest::handleRedirectedTokenEndpoint);
    }

    @BeforeEach
    void setUp(URI serverUri) {
        issuer = URI.create(serverUri.toString().substring(0, serverUri.toString().length() - 1));
        tokenEndpointUri = serverUri.resolve("token");
        redirectedTokenEndpointUri = serverUri.resolve("redirected-token");
        responseStatus = 200;
        responseBody = tokenResponse("access-token", 600).toString();
        providerMetadata = JsonObject.builder()
                .set("issuer", issuer.toString())
                .set("token_endpoint", tokenEndpointUri.toString())
                .build()
                .toString();
        redirectLocation = null;
        dynamicTokenResponse = false;
        dynamicExpiresIn = 600;
        REQUEST_COUNT.set(0);
        REDIRECTED_REQUEST_COUNT.set(0);
        RECORDED_REQUEST.set(null);
    }

    @Test
    void clientCredentialsGrantObtainsTokenAndUsesClientSecretBasic() {
        OidcProvider provider = provider(confidentialTenant());
        SecurityEnvironment outboundEnv = outboundEnvironment();

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(), outboundEnv, EndpointConfig.create());

        assertThat(provider.isOutboundSupported(providerRequest(), outboundEnv, EndpointConfig.create()), is(true));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer access-token")));
        assertThat(response.requestHeaders().get(EXISTING_HEADER_NAME), is(List.of(EXISTING_HEADER_VALUE)));
        assertThat(REQUEST_COUNT.get(), is(1));

        RecordedRequest request = RECORDED_REQUEST.get();
        assertThat(request.method(), is("POST"));
        assertThat(request.authorization(),
                   is(OidcClientAuthenticationSupport.basicAuthorization(CLIENT_ID, CLIENT_SECRET)));
        assertThat(request.contentType(), is("application/x-www-form-urlencoded"));
        assertThat(request.formParameters(), is(Map.of("grant_type", List.of("client_credentials"))));
    }

    @Test
    void clientCredentialsGrantCanUseClientSecretPost() {
        OidcProvider provider = provider(confidentialTenant(OidcClientAuthenticationMethod.CLIENT_SECRET_POST));

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(),
                                                                      outboundEnvironment(),
                                                                      EndpointConfig.create());

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        RecordedRequest request = RECORDED_REQUEST.get();
        assertThat(request.authorization(), is(""));
        assertThat(request.formParameters(), is(Map.of("grant_type", List.of("client_credentials"),
                                                       "client_id", List.of(CLIENT_ID),
                                                       "client_secret", List.of(CLIENT_SECRET))));
    }

    @Test
    void outboundTargetCanSelectClientCredentialsGrant() {
        OidcProvider provider = provider(confidentialTenantWithoutOutbound(), clientCredentialsTarget());
        SecurityEnvironment outboundEnv = outboundEnvironment();

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(),
                                                                      outboundEnv,
                                                                      EndpointConfig.create());

        assertThat(provider.isOutboundSupported(providerRequest(), outboundEnv, EndpointConfig.create()), is(true));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer access-token")));
        assertThat(REQUEST_COUNT.get(), is(1));
    }

    @Test
    void outboundTargetClientCredentialsGrantMatchesHttpsUriWhenEnvironmentTransportIsStale() {
        OidcProvider provider = provider(confidentialTenantWithoutOutbound(), clientCredentialsTarget());
        SecurityEnvironment outboundEnv = SecurityEnvironment.builder()
                .targetUri(URI.create("https://api.example.com/resource"))
                .transport("http")
                .path("/resource")
                .method("GET")
                .build();

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(),
                                                                      outboundEnv,
                                                                      EndpointConfig.create());

        assertThat(provider.isOutboundSupported(providerRequest(), outboundEnv, EndpointConfig.create()), is(true));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer access-token")));
        assertThat(REQUEST_COUNT.get(), is(1));
    }

    @Test
    void outboundTargetClientCredentialsGrantMatchesUppercaseHttpsUriScheme() {
        OidcProvider provider = provider(confidentialTenantWithoutOutbound(), clientCredentialsTarget());
        SecurityEnvironment outboundEnv = outboundEnvironment("HTTPS://api.example.com/resource", "/resource");

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(),
                                                                      outboundEnv,
                                                                      EndpointConfig.create());

        assertThat(provider.isOutboundSupported(providerRequest(), outboundEnv, EndpointConfig.create()), is(true));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer access-token")));
        assertThat(REQUEST_COUNT.get(), is(1));
    }

    @Test
    void outboundTargetClientCredentialsGrantDoesNotApplyToOtherHost() {
        OidcProvider provider = provider(confidentialTenantWithoutOutbound(), clientCredentialsTarget());
        SecurityEnvironment outboundEnv = outboundEnvironment("https://other.example.com/resource", "/resource");

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(),
                                                                      outboundEnv,
                                                                      EndpointConfig.create());

        assertThat(provider.isOutboundSupported(providerRequest(), outboundEnv, EndpointConfig.create()), is(false));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.ABSTAIN));
        assertThat(REQUEST_COUNT.get(), is(0));
    }

    @Test
    void outboundTargetClientCredentialsGrantDoesNotApplyWhenTransportDiffersFromUriScheme() {
        OidcProvider provider = provider(confidentialTenantWithoutOutbound(), clientCredentialsTarget());
        SecurityEnvironment outboundEnv = SecurityEnvironment.builder()
                .targetUri(URI.create("http://api.example.com/resource"))
                .transport("https")
                .path("/resource")
                .method("GET")
                .build();

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(),
                                                                      outboundEnv,
                                                                      EndpointConfig.create());

        assertThat(provider.isOutboundSupported(providerRequest(), outboundEnv, EndpointConfig.create()), is(false));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.ABSTAIN));
        assertThat(REQUEST_COUNT.get(), is(0));
    }

    @Test
    void outboundTargetClientCredentialsGrantDoesNotApplyToHttpWhenTlsIsRequired() {
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .endpoints(it -> it.tokenEndpointUri(URI.create("https://issuer.example/token")))
                .buildPrototype();
        OidcProvider provider = provider(tenant, clientCredentialsTargetForAllTransports());
        SecurityEnvironment outboundEnv = outboundEnvironment("http://api.example.com/resource", "/resource");

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(),
                                                                      outboundEnv,
                                                                      EndpointConfig.create());

        assertThat(provider.isOutboundSupported(providerRequest(), outboundEnv, EndpointConfig.create()), is(false));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.ABSTAIN));
        assertThat(REQUEST_COUNT.get(), is(0));
    }

    @Test
    void tenantWideClientCredentialsGrantDoesNotApplyToHttpWhenTlsIsRequired() {
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .endpoints(it -> it.tokenEndpointUri(URI.create("https://issuer.example/token")))
                .outbound(it -> it.clientCredentialsGrantEnabled(true))
                .buildPrototype();
        OidcProvider provider = provider(tenant);
        SecurityEnvironment outboundEnv = outboundEnvironment("http://api.example.com/resource", "/resource");

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(),
                                                                      outboundEnv,
                                                                      EndpointConfig.create());

        assertThat(provider.isOutboundSupported(providerRequest(), outboundEnv, EndpointConfig.create()), is(false));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.ABSTAIN));
        assertThat(REQUEST_COUNT.get(), is(0));
    }

    @Test
    void clientCredentialsGrantCanUseHttpOutboundTargetWhenTlsRequirementIsDisabled() {
        OidcProvider provider = provider(confidentialTenantWithoutOutbound(), clientCredentialsTargetForAllTransports());
        SecurityEnvironment outboundEnv = outboundEnvironment("http://api.example.com/resource", "/resource");

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(),
                                                                      outboundEnv,
                                                                      EndpointConfig.create());

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer access-token")));
        assertThat(REQUEST_COUNT.get(), is(1));
    }

    @Test
    void outboundTargetClientCredentialsGrantDoesNotApplyToOtherPath() {
        OidcProvider provider = provider(confidentialTenantWithoutOutbound(), clientCredentialsTarget());
        SecurityEnvironment outboundEnv = outboundEnvironment("https://api.example.com/other", "/other");

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(),
                                                                      outboundEnv,
                                                                      EndpointConfig.create());

        assertThat(provider.isOutboundSupported(providerRequest(), outboundEnv, EndpointConfig.create()), is(false));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.ABSTAIN));
        assertThat(REQUEST_COUNT.get(), is(0));
    }

    @Test
    void outboundTargetClientCredentialsGrantDoesNotApplyToOtherMethod() {
        OidcProvider provider = provider(confidentialTenantWithoutOutbound(), clientCredentialsTarget());
        SecurityEnvironment outboundEnv = outboundEnvironment("https://api.example.com/resource", "/resource", "POST");

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(),
                                                                      outboundEnv,
                                                                      EndpointConfig.create());

        assertThat(provider.isOutboundSupported(providerRequest(), outboundEnv, EndpointConfig.create()), is(false));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.ABSTAIN));
        assertThat(REQUEST_COUNT.get(), is(0));
    }

    @Test
    void outboundTargetConfigCanSelectClientCredentialsGrant() {
        Config config = Config.builder()
                .sources(ConfigSources.create(Map.ofEntries(
                        Map.entry("tenants.default.client-id", CLIENT_ID),
                        Map.entry("tenants.default.client-secret", CLIENT_SECRET),
                        Map.entry("tenants.default.endpoints.token-endpoint-uri", tokenEndpointUri.toString()),
                        Map.entry("tenants.default.endpoints.tls-required", "false"),
                        Map.entry("outbound.0.name", "api"),
                        Map.entry("outbound.0.transports.0", "https"),
                        Map.entry("outbound.0.hosts.0", "api.example.com"),
                        Map.entry("outbound.0.paths.0", "/resource"),
                        Map.entry("outbound.0.methods.0", "GET"),
                        Map.entry("outbound.0.client-credentials-grant-enabled", "true"))))
                .build();
        OidcProvider provider = OidcProvider.create(OidcProviderConfig.create(config));
        SecurityEnvironment outboundEnv = outboundEnvironment();

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(),
                                                                      outboundEnv,
                                                                      EndpointConfig.create());

        assertThat(provider.isOutboundSupported(providerRequest(), outboundEnv, EndpointConfig.create()), is(true));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer access-token")));
        assertThat(REQUEST_COUNT.get(), is(1));
    }

    @Test
    void outboundTargetConfigCanUseDiscoveredTokenEndpoint() {
        Config config = Config.builder()
                .sources(ConfigSources.create(Map.ofEntries(
                        Map.entry("tenants.default.issuer", issuer.toString()),
                        Map.entry("tenants.default.client-id", CLIENT_ID),
                        Map.entry("tenants.default.client-secret", CLIENT_SECRET),
                        Map.entry("tenants.default.endpoints.tls-required", "false"),
                        Map.entry("outbound.0.name", "api"),
                        Map.entry("outbound.0.transports.0", "https"),
                        Map.entry("outbound.0.hosts.0", "api.example.com"),
                        Map.entry("outbound.0.paths.0", "/resource"),
                        Map.entry("outbound.0.methods.0", "GET"),
                        Map.entry("outbound.0.client-credentials-grant-enabled", "true"))))
                .build();
        OidcProvider provider = OidcProvider.create(OidcProviderConfig.create(config));

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(),
                                                                      outboundEnvironment(),
                                                                      EndpointConfig.create());

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer access-token")));
        assertThat(REQUEST_COUNT.get(), is(1));
    }

    @Test
    void clientCredentialsGrantCachesTokenUntilExpires() {
        dynamicTokenResponse = true;
        dynamicExpiresIn = 600;
        OidcProvider provider = provider(confidentialTenant());

        OutboundSecurityResponse first = provider.outboundSecurity(providerRequest(),
                                                                   outboundEnvironment(),
                                                                   EndpointConfig.create());
        OutboundSecurityResponse second = provider.outboundSecurity(providerRequest(),
                                                                    outboundEnvironment(),
                                                                    EndpointConfig.create());

        assertThat(first.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer access-token-1")));
        assertThat(second.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer access-token-1")));
        assertThat(REQUEST_COUNT.get(), is(1));
    }

    @Test
    void expiredClientCredentialsTokenIsReacquired() {
        dynamicTokenResponse = true;
        dynamicExpiresIn = 120;
        OidcProvider provider = provider(confidentialTenant());

        OutboundSecurityResponse first = provider.outboundSecurity(providerRequest(),
                                                                   outboundEnvironment(0),
                                                                   EndpointConfig.create());
        OutboundSecurityResponse second = provider.outboundSecurity(providerRequest(),
                                                                    outboundEnvironment(70),
                                                                    EndpointConfig.create());

        assertThat(first.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer access-token-1")));
        assertThat(second.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer access-token-2")));
        assertThat(REQUEST_COUNT.get(), is(2));
    }

    @Test
    void clientCredentialsGrantDoesNotCacheTokenWithoutExpiresIn() {
        dynamicTokenResponse = true;
        dynamicExpiresIn = null;
        OidcProvider provider = provider(confidentialTenant());

        OutboundSecurityResponse first = provider.outboundSecurity(providerRequest(),
                                                                   outboundEnvironment(),
                                                                   EndpointConfig.create());
        OutboundSecurityResponse second = provider.outboundSecurity(providerRequest(),
                                                                    outboundEnvironment(),
                                                                    EndpointConfig.create());

        assertThat(first.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer access-token-1")));
        assertThat(second.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer access-token-2")));
        assertThat(REQUEST_COUNT.get(), is(2));
    }

    @Test
    void clientCredentialsGrantDoesNotCacheTokenWithinClockSkew() {
        dynamicTokenResponse = true;
        dynamicExpiresIn = 60;
        OidcProvider provider = provider(confidentialTenant());

        OutboundSecurityResponse first = provider.outboundSecurity(providerRequest(),
                                                                   outboundEnvironment(),
                                                                   EndpointConfig.create());
        OutboundSecurityResponse second = provider.outboundSecurity(providerRequest(),
                                                                    outboundEnvironment(),
                                                                    EndpointConfig.create());

        assertThat(first.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer access-token-1")));
        assertThat(second.requestHeaders().get(HeaderNames.AUTHORIZATION.defaultCase()),
                   is(List.of("Bearer access-token-2")));
        assertThat(REQUEST_COUNT.get(), is(2));
    }

    @Test
    void tokenEndpointErrorMapsToOutboundFailure() {
        responseStatus = 400;
        responseBody = JsonObject.builder()
                .set("error", "invalid_client")
                .set("error_description", "client authentication failed")
                .build()
                .toString();
        OidcProvider provider = provider(confidentialTenant());

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(),
                                                                      outboundEnvironment(),
                                                                      EndpointConfig.create());

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.FAILURE));
        assertThat(response.description().orElse(""),
                   is("Client Credentials Grant failed: invalid_client: client authentication failed"));
        assertThat(REQUEST_COUNT.get(), is(1));
    }

    @Test
    void tokenEndpointRedirectIsNotFollowed() {
        responseStatus = 307;
        redirectLocation = redirectedTokenEndpointUri.toString();
        responseBody = JsonObject.builder()
                .set("error", "temporarily_unavailable")
                .build()
                .toString();
        OidcProvider provider = provider(confidentialTenant(OidcClientAuthenticationMethod.CLIENT_SECRET_POST));

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(),
                                                                      outboundEnvironment(),
                                                                      EndpointConfig.create());

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.FAILURE));
        assertThat(response.description().orElse(""), containsString("temporarily_unavailable"));
        assertThat(REQUEST_COUNT.get(), is(1));
        assertThat(REDIRECTED_REQUEST_COUNT.get(), is(0));
    }

    @Test
    void missingTokenEndpointMapsToOutboundFailure() {
        OidcProvider provider = provider(OidcTenantConfig.builder()
                                         .clientId(CLIENT_ID)
                                         .clientSecret(CLIENT_SECRET)
                                         .buildPrototype());
        EndpointConfig outboundConfig = EndpointConfig.builder()
                .customObject(OidcOutboundPolicy.class, OidcOutboundPolicy.clientCredentialsGrant())
                .build();

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest(),
                                                                      outboundEnvironment(),
                                                                      outboundConfig);

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.FAILURE));
        assertThat(response.description().orElse(""),
                   containsString("token-endpoint-uri or discovery-uri"));
        assertThat(REQUEST_COUNT.get(), is(0));
    }

    private static void handleTokenEndpoint(ServerRequest request, ServerResponse response) {
        int requestNumber = REQUEST_COUNT.incrementAndGet();
        RECORDED_REQUEST.set(new RecordedRequest(request.prologue().method().text(),
                                                request.headers().first(HeaderNames.AUTHORIZATION).orElse(""),
                                                request.headers().first(HeaderNames.CONTENT_TYPE).orElse(""),
                                                formParameters(request.content().as(Parameters.class))));
        String body = dynamicTokenResponse
                ? tokenResponse("access-token-" + requestNumber, dynamicExpiresIn).toString()
                : responseBody;
        response.status(responseStatus)
                .header(HeaderValues.CONTENT_TYPE_JSON);
        if (redirectLocation != null) {
            response.header(HeaderNames.LOCATION, redirectLocation);
        }
        response.send(body);
    }

    private static void handleRedirectedTokenEndpoint(ServerRequest request, ServerResponse response) {
        REDIRECTED_REQUEST_COUNT.incrementAndGet();
        response.header(HeaderValues.CONTENT_TYPE_JSON)
                .send(tokenResponse("redirected-access-token", 600));
    }

    private OidcTenantConfig confidentialTenant() {
        return confidentialTenant(null);
    }

    private OidcTenantConfig confidentialTenant(OidcClientAuthenticationMethod method) {
        return confidentialTenant(method, true);
    }

    private OidcTenantConfig confidentialTenantWithoutOutbound() {
        return confidentialTenant(null, false);
    }

    private OidcTenantConfig confidentialTenant(OidcClientAuthenticationMethod method, boolean outboundEnabled) {
        return OidcTenantConfig.builder()
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .update(builder -> {
                    if (method != null) {
                        builder.tokenEndpointAuthenticationMethod(method);
                    }
                })
                .endpoints(it -> it.tokenEndpointUri(tokenEndpointUri)
                        .tlsRequired(false))
                .update(builder -> {
                    if (outboundEnabled) {
                        builder.outbound(it -> it.clientCredentialsGrantEnabled(true));
                    }
                })
                .buildPrototype();
    }

    private static OutboundTarget clientCredentialsTarget() {
        return OutboundTarget.builder("api")
                .addTransport("https")
                .addHost("api.example.com")
                .addPath("/resource")
                .addMethod("GET")
                .customObject(OidcOutboundTargetConfig.class,
                              OidcOutboundTargetConfig.builder()
                                      .clientCredentialsGrantEnabled(true)
                                      .buildPrototype())
                .build();
    }

    private static OutboundTarget clientCredentialsTargetForAllTransports() {
        return OutboundTarget.builder("api")
                .addHost("api.example.com")
                .addPath("/resource")
                .addMethod("GET")
                .customObject(OidcOutboundTargetConfig.class,
                              OidcOutboundTargetConfig.builder()
                                      .clientCredentialsGrantEnabled(true)
                                      .buildPrototype())
                .build();
    }

    private static OidcProvider provider(OidcTenantConfig tenant, OutboundTarget... outboundTargets) {
        return OidcProvider.create(OidcProviderConfig.builder()
                                           .putTenant("default", tenant)
                                           .outboundTargets(List.of(outboundTargets))
                                           .buildPrototype());
    }

    private static ProviderRequest providerRequest() {
        return OidcProviderTest.request(null, SecurityEnvironment.create());
    }

    private static SecurityEnvironment outboundEnvironment() {
        return outboundEnvironment("https://api.example.com/resource", "/resource");
    }

    private static SecurityEnvironment outboundEnvironment(long timeShiftSeconds) {
        return outboundEnvironment("https://api.example.com/resource", "/resource", timeShiftSeconds);
    }

    private static SecurityEnvironment outboundEnvironment(String targetUri, String path) {
        return outboundEnvironment(targetUri, path, "GET");
    }

    private static SecurityEnvironment outboundEnvironment(String targetUri, String path, String method) {
        return outboundEnvironment(targetUri, path, method, 0);
    }

    private static SecurityEnvironment outboundEnvironment(String targetUri, String path, long timeShiftSeconds) {
        return outboundEnvironment(targetUri, path, "GET", timeShiftSeconds);
    }

    private static SecurityEnvironment outboundEnvironment(String targetUri,
                                                          String path,
                                                          String method,
                                                          long timeShiftSeconds) {
        URI uri = URI.create(targetUri);
        return SecurityEnvironment.builder()
                .targetUri(uri)
                .transport(uri.getScheme())
                .path(path)
                .method(method)
                .header(EXISTING_HEADER_NAME, EXISTING_HEADER_VALUE)
                .time(SecurityTime.builder()
                              .shiftBySeconds(timeShiftSeconds)
                              .build())
                .build();
    }

    private static JsonObject tokenResponse(String accessToken, Integer expiresIn) {
        JsonObject.Builder builder = JsonObject.builder()
                .set("access_token", accessToken)
                .set("token_type", "Bearer");
        if (expiresIn != null) {
            builder.set("expires_in", expiresIn);
        }
        return builder.build();
    }

    private static Map<String, List<String>> formParameters(Parameters parameters) {
        Map<String, List<String>> result = new LinkedHashMap<>();
        for (String name : parameters.names()) {
            result.put(name, parameters.all(name));
        }
        return result;
    }

    private record RecordedRequest(String method,
                                   String authorization,
                                   String contentType,
                                   Map<String, List<String>> formParameters) {
    }
}
