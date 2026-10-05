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

package io.helidon.security.providers.oidc.next.idcs;

import java.net.URI;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import io.helidon.common.configurable.Resource;
import io.helidon.common.parameters.Parameters;
import io.helidon.common.pki.Keys;
import io.helidon.common.tls.Tls;
import io.helidon.common.uri.UriQuery;
import io.helidon.http.HeaderNames;
import io.helidon.http.HeaderValues;
import io.helidon.http.Status;
import io.helidon.json.JsonObject;
import io.helidon.security.AuthenticationResponse;
import io.helidon.security.ProviderRequest;
import io.helidon.security.Security;
import io.helidon.security.SecurityEnvironment;
import io.helidon.security.SecurityResponse;
import io.helidon.security.jwt.Jwt;
import io.helidon.security.jwt.SignedJwt;
import io.helidon.security.jwt.jwk.JwkKeys;
import io.helidon.security.providers.oidc.next.OidcFeature;
import io.helidon.security.providers.oidc.next.OidcJwtAccessTokenProfile;
import io.helidon.security.providers.oidc.next.OidcProvider;
import io.helidon.security.providers.oidc.next.OidcProviderConfig;
import io.helidon.security.providers.oidc.next.OidcTenantConfig;
import io.helidon.security.providers.oidc.next.OidcTokenValidationMethod;
import io.helidon.webclient.api.HttpClientResponse;
import io.helidon.webclient.api.WebClient;
import io.helidon.webclient.api.WebClientConfig;
import io.helidon.webserver.WebServer;
import io.helidon.webserver.http.HttpRouting;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.hamcrest.MatcherAssert.assertThat;

@Execution(ExecutionMode.SAME_THREAD)
class IdcsProtectedJwkAuthenticationTest {
    private static final String ISSUER = "https://identity.oraclecloud.com/";
    private static final String AUDIENCE = "api://idcs";
    private static final AtomicInteger JWKS_REQUESTS = new AtomicInteger();
    private static final AtomicInteger TOKEN_REQUESTS = new AtomicInteger();
    private static final AtomicReference<String> TOKEN_FORM = new AtomicReference<>();
    private static final AtomicReference<String> TOKEN_AUTHORIZATION = new AtomicReference<>();
    private static final AtomicReference<String> CODE_FLOW_NONCE = new AtomicReference<>();

    private static WebServer idcsServer;
    private static WebServer secondIdcsServer;
    private static URI domainUri;
    private static URI secondDomainUri;
    private static Keys trustedServer;
    private static Keys serverKeys;
    private static JwkKeys signingKeys;
    private static String publicJwkSet;
    private static volatile boolean publicSigningKeys;

    @BeforeAll
    static void start() {
        serverKeys = Keys.builder().pem(pem -> pem
                .key(Resource.create("oidc-next-par-localhost.key"))
                .certChain(Resource.create("oidc-next-par-localhost.crt"))).build();
        trustedServer = Keys.builder().pem(pem -> pem.certificates(Resource.create("oidc-next-par-localhost.crt"))).build();
        signingKeys = JwkKeys.builder().resource(Resource.create("oidc-next-it-sign-jwk.json")).build();
        publicJwkSet = Resource.create("oidc-next-it-verify-jwk.json").string();

        HttpRouting.Builder routing = HttpRouting.builder();
        routing.post("/oauth2/v1/token", (request, response) -> {
            TOKEN_REQUESTS.incrementAndGet();
            Parameters form = request.content().as(Parameters.class);
            TOKEN_FORM.set(form.first("grant_type").orElse("") + ":" + form.first("scope").orElse(""));
            TOKEN_AUTHORIZATION.set(request.headers().first(HeaderNames.AUTHORIZATION).orElse(""));
            response.header(HeaderValues.CONTENT_TYPE_JSON)
                    .header(HeaderNames.CACHE_CONTROL, "no-store")
                    .header(HeaderNames.PRAGMA, "no-cache");
            if ("authorization_code".equals(form.first("grant_type").orElse(""))) {
                Instant now = Instant.now();
                String idToken = SignedJwt.sign(Jwt.builder()
                                                        .type("JWT")
                                                        .algorithm("RS256")
                                                        .keyId("verify-rsa")
                                                        .issuer(ISSUER)
                                                        .subject("alice")
                                                        .issueTime(now)
                                                        .expirationTime(now.plus(1, ChronoUnit.HOURS))
                                                        .addAudience("client")
                                                        .addAudience(ISSUER)
                                                        .addPayloadClaim("azp", "client")
                                                        .nonce(CODE_FLOW_NONCE.get())
                                                        .build(),
                                                signingKeys.forKeyId("sign-rsa").orElseThrow()).tokenContent();
                response.send(JsonObject.builder()
                                      .set("access_token", "idcs-user-access")
                                      .set("id_token", idToken)
                                      .set("token_type", "Bearer")
                                      .set("expires_in", 300)
                                      .build().toString());
            } else {
                response.send(JsonObject.builder()
                                      .set("access_token", "idcs-key-reader")
                                      .set("token_type", "Bearer")
                                      .set("expires_in", 300)
                                      .build().toString());
            }
        });
        routing.get("/admin/v1/SigningCert/jwk", (request, response) -> {
            JWKS_REQUESTS.incrementAndGet();
            if (!publicSigningKeys
                    && request.headers().first(HeaderNames.AUTHORIZATION)
                            .filter("Bearer idcs-key-reader"::equals).isEmpty()) {
                response.status(Status.UNAUTHORIZED_401).send();
            } else {
                response.header(HeaderValues.CONTENT_TYPE_JSON).send(publicJwkSet);
            }
        });
        idcsServer = WebServer.builder()
                .port(0)
                .tls(Tls.builder().privateKey(serverKeys).privateKeyCertChain(serverKeys).build())
                .addRouting(routing)
                .build().start();
        domainUri = URI.create("https://localhost:" + idcsServer.port());
        HttpRouting.Builder secondRouting = HttpRouting.builder();
        secondRouting.get("/admin/v1/SigningCert/jwk", (_, response) -> response
                .header(HeaderValues.CONTENT_TYPE_JSON)
                .send(publicJwkSet));
        secondIdcsServer = WebServer.builder()
                .port(0)
                .tls(Tls.builder().privateKey(serverKeys).privateKeyCertChain(serverKeys).build())
                .addRouting(secondRouting)
                .build().start();
        secondDomainUri = URI.create("https://localhost:" + secondIdcsServer.port());
    }

    @AfterAll
    static void stop() {
        if (idcsServer != null) {
            idcsServer.stop();
        }
        if (secondIdcsServer != null) {
            secondIdcsServer.stop();
        }
    }

    @BeforeEach
    void reset() {
        JWKS_REQUESTS.set(0);
        TOKEN_REQUESTS.set(0);
        TOKEN_FORM.set("");
        TOKEN_AUTHORIZATION.set("");
        CODE_FLOW_NONCE.set(null);
        publicSigningKeys = false;
    }

    @Test
    void protectedSigningKeysAllowIdcsAccessTokenAuthentication() {
        try (OidcProvider provider = provider(true)) {
            AuthenticationResponse first = provider.authenticate(request(signedAccessToken()));
            AuthenticationResponse second = provider.authenticate(request(signedAccessToken()));

            assertThat(first.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
            assertThat(second.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
            assertThat(JWKS_REQUESTS.get(), is(2));
            assertThat(TOKEN_REQUESTS.get(), is(1));
            assertThat(TOKEN_FORM.get(), is("client_credentials:urn:opc:idm:__myscopes__"));
            assertThat(TOKEN_AUTHORIZATION.get(), is("Basic " + Base64.getEncoder()
                    .encodeToString("client:secret".getBytes(java.nio.charset.StandardCharsets.UTF_8))));
        }
    }

    @Test
    void defaultIdcsJwtLayoutVerifiesDocumentedUntypedAccessTokensWithProtectedSigningKeys() {
        try (OidcProvider provider = providerWithIdcsJwtDefaults()) {
            AuthenticationResponse untyped = provider.authenticate(request(signedIdcsAccessToken(_ -> { })));
            AuthenticationResponse typed = provider.authenticate(request(signedIdcsAccessToken(jwt -> jwt.type("JWT"))));

            assertThat(untyped.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
            assertThat(typed.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
            assertThat(JWKS_REQUESTS.get(), is(2));
            assertThat(TOKEN_REQUESTS.get(), is(1));
        }
    }

    @Test
    void defaultIdcsJwtLayoutRejectsIdTokensAndTokensOutsideTheConfiguredResource() {
        try (OidcProvider provider = providerWithIdcsJwtDefaults()) {
            List<String> invalid = List.of(
                    signedIdcsAccessToken(jwt -> jwt.addPayloadClaim("tok_type", "IT")),
                    signedIdcsAccessToken(jwt -> jwt.removePayloadClaim("tok_type")),
                    signedIdcsAccessToken(jwt -> jwt.addPayloadClaim("tok_type", List.of("AT"))),
                    signedIdcsAccessToken(jwt -> jwt.type("id+jwt")),
                    signedIdcsAccessToken(jwt -> jwt.audience(List.of("api://other"))),
                    signedIdcsAccessToken(jwt -> jwt.issuer("https://other-issuer.example")),
                    signedIdcsAccessToken(jwt -> jwt.expirationTime(Instant.now().minusSeconds(300))));

            for (String token : invalid) {
                AuthenticationResponse response = provider.authenticate(request(token));
                assertThat(response.status(), is(SecurityResponse.SecurityStatus.FAILURE));
                assertThat(response.statusCode().orElse(-1), is(Status.UNAUTHORIZED_401.code()));
            }

            String signed = signedIdcsAccessToken(_ -> { });
            int signatureStart = signed.lastIndexOf('.') + 1;
            char replacement = signed.charAt(signatureStart) == 'A' ? 'B' : 'A';
            String tampered = signed.substring(0, signatureStart) + replacement + signed.substring(signatureStart + 1);
            assertThat(provider.authenticate(request(tampered)).status(), is(SecurityResponse.SecurityStatus.FAILURE));
        }
    }

    @Test
    void ordinaryTenantDoesNotAcquireIdcsSigningKeyCredentials() {
        try (OidcProvider provider = provider(false)) {
            AuthenticationResponse response = provider.authenticate(request(signedAccessToken()));

            assertThat(response.status(), is(SecurityResponse.SecurityStatus.FAILURE));
            assertThat(JWKS_REQUESTS.get(), is(1));
            assertThat(TOKEN_REQUESTS.get(), is(0));
        }
    }

    @Test
    void publicSigningKeysNeedNoClientCredentialsGrant() {
        publicSigningKeys = true;
        try (OidcProvider provider = provider(true)) {
            assertThat(provider.authenticate(request(signedAccessToken())).status(),
                       is(SecurityResponse.SecurityStatus.SUCCESS));
            assertThat(JWKS_REQUESTS.get(), is(1));
            assertThat(TOKEN_REQUESTS.get(), is(0));
        }
    }

    @Test
    void identityFromSameIssuerAndSubjectRemainsSeparateAcrossIdcsDomains() {
        publicSigningKeys = true;
        try (OidcProvider first = provider(true);
             OidcProvider second = provider(true, secondDomainUri)) {
            String accessToken = signedAccessToken();
            AuthenticationResponse firstResponse = first.authenticate(request(accessToken));
            AuthenticationResponse secondResponse = second.authenticate(request(accessToken));

            assertThat(firstResponse.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
            assertThat(secondResponse.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
            assertThat(firstResponse.user().orElseThrow().principal().id(),
                       is(not(secondResponse.user().orElseThrow().principal().id())));
        }
    }

    @Test
    void browserCodeFlowVerifiesIdTokenUsingProtectedIdcsSigningKeys() {
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .adapter(IdcsTenantAdapter.builder().domainUri(domainUri).build())
                .clientId("client")
                .clientSecret("secret")
                .authorizationCode(code -> code.redirectionEndpointUri(URI.create("/oidc/idcs-callback")))
                .cookies(cookies -> cookies.protection(protection -> protection
                        .password("a-long-enough-code-flow-cookie-password")))
                .webClient(WebClientConfig.builder().tls(tls -> tls.trust(trustedServer)).buildPrototype())
                .buildPrototype();
        OidcProvider provider = OidcProvider.create(OidcProviderConfig.builder()
                                                            .putTenant("idcs", tenant)
                                                            .buildPrototype());
        HttpRouting.Builder routing = HttpRouting.builder();
        OidcFeature.create(provider).setup(routing);
        WebServer rpServer = WebServer.builder()
                .port(0)
                .tls(Tls.builder().privateKey(serverKeys).privateKeyCertChain(serverKeys).build())
                .addRouting(routing)
                .build().start();
        WebClient browser = WebClient.create(WebClientConfig.builder().tls(tls -> tls.trust(trustedServer)).buildPrototype());
        try {
            URI rpUri = URI.create("https://localhost:" + rpServer.port());
            AuthenticationResponse initiation = provider.authenticate(request(null, rpUri.resolve("/resource")));
            assertThat(initiation.statusCode().orElse(-1), is(Status.SEE_OTHER_303_CODE));
            URI authorization = URI.create(initiation.responseHeaders().get("Location").getFirst());
            UriQuery query = UriQuery.create(authorization);
            CODE_FLOW_NONCE.set(query.get("nonce"));
            String cookies = initiation.responseHeaders().get("Set-Cookie").stream()
                    .map(value -> value.substring(0, value.indexOf(';')))
                    .reduce((first, second) -> first + "; " + second)
                    .orElseThrow();
            String browserCookies;
            try (HttpClientResponse callback = browser.get()
                    .uri(rpUri.resolve("/oidc/idcs-callback"))
                    .queryParam("code", "idcs-code")
                    .queryParam("state", query.get("state"))
                    .followRedirects(false)
                    .header(HeaderNames.COOKIE, cookies)
                    .request()) {
                assertThat(callback.status(), is(Status.SEE_OTHER_303));
                String sessionCookies = callback.headers().get(HeaderNames.SET_COOKIE).allValues().stream()
                        .map(value -> value.substring(0, value.indexOf(';')))
                        .filter(value -> value.startsWith("__Host-helidon-oidc-auth=")
                                || value.startsWith("__Host-helidon-oidc-auth."))
                        .reduce((first, second) -> first + "; " + second)
                        .orElseThrow();
                browserCookies = cookies + "; " + sessionCookies;
            }
            AuthenticationResponse restored = provider.authenticate(request(null,
                                                                            rpUri.resolve("/resource"),
                                                                            browserCookies));
            assertThat(restored.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
            assertThat(restored.user().orElseThrow().principal().id(), startsWith("oidc-adapter:"));
            assertThat(TOKEN_REQUESTS.get(), is(2));
            assertThat(JWKS_REQUESTS.get(), is(2));
        } finally {
            browser.closeResource();
            rpServer.stop();
            provider.close();
        }
    }

    private static OidcProvider provider(boolean idcsAdapter) {
        return provider(idcsAdapter, domainUri);
    }

    private static OidcProvider providerWithIdcsJwtDefaults() {
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .adapter(IdcsTenantAdapter.builder().domainUri(domainUri).build())
                .clientId("client")
                .clientSecret("secret")
                .protectedResource(resource -> resource.tokenValidation(validation -> validation
                        .method(OidcTokenValidationMethod.JWT)
                        .audience(AUDIENCE)))
                .webClient(WebClientConfig.builder().tls(tls -> tls.trust(trustedServer)).buildPrototype())
                .buildPrototype();
        return OidcProvider.create(OidcProviderConfig.builder()
                                           .putTenant("default", tenant)
                                           .buildPrototype());
    }

    private static OidcProvider provider(boolean idcsAdapter, URI adapterDomain) {
        OidcTenantConfig.Builder tenant = OidcTenantConfig.builder()
                .issuer(ISSUER)
                .clientId("client")
                .clientSecret("secret")
                .endpoints(endpoints -> endpoints.jwksUri(adapterDomain.resolve("/admin/v1/SigningCert/jwk")))
                .protectedResource(resource -> resource.tokenValidation(validation -> validation
                        .method(OidcTokenValidationMethod.JWT)
                        .audience(AUDIENCE)
                        .jwt(layout -> layout.profile(OidcJwtAccessTokenProfile.CUSTOM)
                                .allowedTypes(List.of("JWT"))
                                .putRequiredStringClaim("typ", "Bearer"))))
                .webClient(WebClientConfig.builder().tls(tls -> tls.trust(trustedServer)).buildPrototype());
        if (idcsAdapter) {
            tenant.adapter(IdcsTenantAdapter.builder().domainUri(adapterDomain).build());
        }
        return OidcProvider.create(OidcProviderConfig.builder()
                                           .putTenant("default", tenant.buildPrototype())
                                           .buildPrototype());
    }

    private static String signedAccessToken() {
        Instant now = Instant.now();
        return SignedJwt.sign(Jwt.builder()
                                      .type("JWT")
                                      .algorithm("RS256")
                                      .keyId("verify-rsa")
                                      .issuer(ISSUER)
                                      .subject("alice")
                                      .issueTime(now)
                                      .expirationTime(now.plus(1, ChronoUnit.HOURS))
                                      .addAudience(AUDIENCE)
                                      .addPayloadClaim("typ", "Bearer")
                                      .build(),
                              signingKeys.forKeyId("sign-rsa").orElseThrow())
                .tokenContent();
    }

    private static String signedIdcsAccessToken(Consumer<Jwt.Builder> customizer) {
        Instant now = Instant.now();
        Jwt.Builder jwt = Jwt.builder()
                .algorithm("RS256")
                .keyId("verify-rsa")
                .issuer(ISSUER)
                .subject("alice")
                .issueTime(now)
                .expirationTime(now.plus(1, ChronoUnit.HOURS))
                .addAudience(AUDIENCE)
                .addPayloadClaim("tok_type", "AT");
        customizer.accept(jwt);
        return SignedJwt.sign(jwt.build(), signingKeys.forKeyId("sign-rsa").orElseThrow()).tokenContent();
    }

    private static ProviderRequest request(String token) {
        return request(token, URI.create("https://rp.example/resource"));
    }

    private static ProviderRequest request(String token, URI targetUri) {
        return request(token, targetUri, null);
    }

    private static ProviderRequest request(String token, URI targetUri, String cookieHeader) {
        SecurityEnvironment.Builder environmentBuilder = SecurityEnvironment.builder().targetUri(targetUri);
        if (token != null) {
            environmentBuilder.header("Authorization", "Bearer " + token);
        }
        if (cookieHeader != null) {
            environmentBuilder.header("Cookie", cookieHeader);
        }
        // This fixture tests the IDCS provider, not the global tracing service registry.
        return ProviderRequest.create(Security.builder().disableTracing().build()
                                              .contextBuilder("idcs-test")
                                              .env(environmentBuilder.build())
                                              .build(),
                                      Map.of());
    }
}
