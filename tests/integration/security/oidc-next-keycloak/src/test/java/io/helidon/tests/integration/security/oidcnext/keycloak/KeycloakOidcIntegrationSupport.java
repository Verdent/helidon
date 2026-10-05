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
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import io.helidon.common.context.Contexts;
import io.helidon.common.parameters.Parameters;
import io.helidon.http.HeaderNames;
import io.helidon.http.HttpMediaTypes;
import io.helidon.http.SetCookie;
import io.helidon.json.JsonObject;
import io.helidon.json.JsonParser;
import io.helidon.security.Security;
import io.helidon.security.SecurityContext;
import io.helidon.security.Subject;
import io.helidon.security.providers.common.OutboundTarget;
import io.helidon.security.providers.oidc.next.OidcAuthorizationCodeConfig;
import io.helidon.security.providers.oidc.next.OidcEndpointConfig;
import io.helidon.security.providers.oidc.next.OidcEndpointPolicyConfig;
import io.helidon.security.providers.oidc.next.OidcFeature;
import io.helidon.security.providers.oidc.next.OidcOutboundPolicyConfig;
import io.helidon.security.providers.oidc.next.OidcProvider;
import io.helidon.security.providers.oidc.next.OidcProviderConfig;
import io.helidon.security.providers.oidc.next.OidcPushedAuthorizationRequestMode;
import io.helidon.security.providers.oidc.next.OidcTenantConfig;
import io.helidon.security.providers.oidc.next.OidcTokenValidationMethod;
import io.helidon.webclient.api.HttpClientResponse;
import io.helidon.webclient.api.HttpClientRequest;
import io.helidon.webclient.api.WebClient;
import io.helidon.webclient.security.WebClientSecurity;
import io.helidon.webserver.WebServer;
import io.helidon.webserver.http.HttpFeature;
import io.helidon.webserver.http.HttpRouting;
import io.helidon.webserver.security.SecurityFeature;
import io.helidon.webserver.security.SecurityHandler;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

final class KeycloakOidcIntegrationSupport {
    static final String API_AUDIENCE = "helidon-api";
    static final String API_CLIENT_SECRET = "api-secret";
    static final String WEB_CLIENT_ID = "helidon-web";
    static final String WEB_CLIENT_SECRET = "web-secret";
    // This client's native 45-second access-token lifetime triggers the RP's one-minute renewal margin.
    static final String REFRESH_CLIENT_ID = "helidon-web-refresh";
    static final String SERVICE_CLIENT_ID = "helidon-service";
    static final String SERVICE_CLIENT_SECRET = "service-secret";
    static final String USERNAME = "alice";
    static final String PASSWORD = "secret";

    private static final String COOKIE_PASSWORD = "keycloak-integration-test-cookie-password";
    private static final Pattern LOGIN_FORM_ACTION = Pattern.compile(
            "<form[^>]+action=\"([^\"]+/login-actions/authenticate[^\"]*)\"");

    private KeycloakOidcIntegrationSupport() {
    }

    static String alicePrincipalResponse() {
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        return "oidc-sub:" + encoder.encodeToString(KeycloakOidcContainer.issuer().toString()
                                                          .getBytes(StandardCharsets.UTF_8))
                + "." + encoder.encodeToString("11111111-1111-1111-1111-111111111111".getBytes(StandardCharsets.UTF_8))
                + "|alice|alice@example.org";
    }

    static OidcProviderConfig protectedResourceProviderConfig(OidcTokenValidationMethod method) {
        return protectedResourceProviderConfig(method, API_AUDIENCE, method == OidcTokenValidationMethod.JWT);
    }

    static OidcProviderConfig protectedResourceProviderConfig(OidcTokenValidationMethod method,
                                                              String audience,
                                                              boolean audienceValidationEnabled) {
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .issuer(KeycloakOidcContainer.issuer().toString())
                .clientId(API_AUDIENCE)
                .clientSecret(API_CLIENT_SECRET)
                .endpoints(endpoints -> endpoints
                        .wellKnownUri(KeycloakOidcContainer.metadataUri())
                        .tlsRequired(false))
                .tokenTransport(transport -> transport.secureTransportRequired(false))
                .protectedResource(resource -> resource
                        .tokenValidation(validation -> validation
                                .method(method)
                                .audience(audience)
                                .introspection(introspection -> introspection
                                        .clientId(API_AUDIENCE)
                                        .clientSecret(API_CLIENT_SECRET))
                                .audienceValidationEnabled(audienceValidationEnabled)))
                .buildPrototype();
        return OidcProviderConfig.builder()
                .putTenant("default", tenant)
                .buildPrototype();
    }

    static OidcProviderConfig authorizationCodeProviderConfig() {
        return authorizationCodeProviderConfig(_ -> {
        });
    }

    static OidcProviderConfig authorizationCodeProviderConfig(
            Consumer<OidcAuthorizationCodeConfig.Builder> authorizationCodeCustomizer) {
        return authorizationCodeProviderConfig(authorizationCodeCustomizer, _ -> {
        });
    }

    static OidcProviderConfig authorizationCodeProviderConfig(
            Consumer<OidcAuthorizationCodeConfig.Builder> authorizationCodeCustomizer,
            Consumer<OidcTenantConfig.Builder> tenantCustomizer) {
        URI issuer = KeycloakOidcContainer.issuer();
        URI protocol = URI.create(issuer + "/protocol/openid-connect/");
        // Keycloak's HTTP dev-mode metadata advertises an HTTP PAR URL even if this client disables PAR.
        // Explicit endpoints keep these HTTP tests independent of PAR; the HTTPS PAR test still exercises discovery.
        return configuredAuthorizationCodeProviderConfig(issuer,
                                                         endpoints -> endpoints
                                                                 .authorizationEndpointUri(protocol.resolve("auth"))
                                                                 .tokenEndpointUri(protocol.resolve("token"))
                                                                 .jwksUri(protocol.resolve("certs"))
                                                                 .introspectionEndpointUri(protocol.resolve("token/introspect"))
                                                                 .userInfoEndpointUri(protocol.resolve("userinfo"))
                                                                 .endSessionEndpointUri(protocol.resolve("logout"))
                                                                 .tlsRequired(false),
                                                         authorizationCodeCustomizer,
                                                         tenantCustomizer);
    }

    static OidcProviderConfig authorizationCodeProviderConfig(
            URI issuer,
            URI metadataUri,
            Consumer<OidcAuthorizationCodeConfig.Builder> authorizationCodeCustomizer,
            Consumer<OidcTenantConfig.Builder> tenantCustomizer) {
        return configuredAuthorizationCodeProviderConfig(issuer,
                                                         endpoints -> endpoints.wellKnownUri(metadataUri).tlsRequired(false),
                                                         authorizationCodeCustomizer,
                                                         tenantCustomizer);
    }

    static OidcProviderConfig mixedProviderConfig() {
        return authorizationCodeProviderConfig(
                _ -> {
                },
                tenant -> tenant
                        .tokenTransport(transport -> transport.secureTransportRequired(false))
                        .protectedResource(resource -> resource
                                .tokenValidation(validation -> validation
                                        .method(OidcTokenValidationMethod.INTROSPECTION)
                                        .audience(API_AUDIENCE)
                                        .introspection(introspection -> introspection
                                                .clientId(API_AUDIENCE)
                                                .clientSecret(API_CLIENT_SECRET))
                                        .audienceValidationEnabled(false))));
    }

    static OidcProviderConfig authorizationCodeRefreshProviderConfig() {
        return authorizationCodeProviderConfig(
                _ -> {
                },
                tenant -> tenant.clientId(REFRESH_CLIENT_ID));
    }

    static OidcProviderConfig outboundClientCredentialsProviderConfig(OutboundTarget outboundTarget) {
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .issuer(KeycloakOidcContainer.issuer().toString())
                .clientId(SERVICE_CLIENT_ID)
                .clientSecret(SERVICE_CLIENT_SECRET)
                .endpoints(endpoints -> endpoints
                        .wellKnownUri(KeycloakOidcContainer.metadataUri())
                        .tlsRequired(false))
                .tokenTransport(transport -> transport.secureTransportRequired(false))
                .protectedResource(resource -> resource
                        .tokenValidation(validation -> validation
                                .method(OidcTokenValidationMethod.INTROSPECTION)
                                .audience(API_AUDIENCE)
                                .introspection(introspection -> introspection
                                        .clientId(API_AUDIENCE)
                                        .clientSecret(API_CLIENT_SECRET))
                                .audienceValidationEnabled(false)))
                .subjectMapping(subjectMapping -> subjectMapping
                        .principalIdClaimPaths(List.of("client_id", "preferred_username", "sub")))
                .buildPrototype();
        return OidcProviderConfig.builder()
                .putTenant("default", tenant)
                .addOutboundTarget(outboundTarget)
                .buildPrototype();
    }

    static OidcProviderConfig tokenPropagationProviderConfig(OutboundTarget outboundTarget) {
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .issuer(KeycloakOidcContainer.issuer().toString())
                .clientId(API_AUDIENCE)
                .clientSecret(API_CLIENT_SECRET)
                .endpoints(endpoints -> endpoints
                        .wellKnownUri(KeycloakOidcContainer.metadataUri())
                        .tlsRequired(false))
                .tokenTransport(transport -> transport.secureTransportRequired(false))
                .protectedResource(resource -> resource
                        .tokenValidation(validation -> validation
                                .method(OidcTokenValidationMethod.INTROSPECTION)
                                .audience(API_AUDIENCE)
                                .introspection(introspection -> introspection
                                        .clientId(API_AUDIENCE)
                                        .clientSecret(API_CLIENT_SECRET))
                                .audienceValidationEnabled(false)))
                .subjectMapping(subjectMapping -> subjectMapping
                        .principalIdClaimPaths(List.of("preferred_username", "client_id", "sub")))
                .buildPrototype();
        return OidcProviderConfig.builder()
                .putTenant("default", tenant)
                .addOutboundTarget(outboundTarget)
                .buildPrototype();
    }

    static OidcProviderConfig tokenExchangeProviderConfig(OutboundTarget outboundTarget) {
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .issuer(KeycloakOidcContainer.issuer().toString())
                .clientId(SERVICE_CLIENT_ID)
                .clientSecret(SERVICE_CLIENT_SECRET)
                .endpoints(endpoints -> endpoints
                        .tokenEndpointUri(KeycloakOidcContainer.tokenEndpointUri())
                        .introspectionEndpointUri(KeycloakOidcContainer.introspectionEndpointUri())
                        .tlsRequired(false))
                .tokenTransport(transport -> transport.secureTransportRequired(false))
                .protectedResource(resource -> resource
                        .tokenValidation(validation -> validation
                                .method(OidcTokenValidationMethod.INTROSPECTION)
                                .audience(API_AUDIENCE)
                                .introspection(introspection -> introspection
                                        .clientId(API_AUDIENCE)
                                        .clientSecret(API_CLIENT_SECRET))
                                .audienceValidationEnabled(false)))
                .subjectMapping(subjectMapping -> subjectMapping
                        .principalIdClaimPaths(List.of("preferred_username", "client_id", "sub")))
                .buildPrototype();
        return OidcProviderConfig.builder()
                .putTenant("default", tenant)
                .addOutboundTarget(outboundTarget)
                .buildPrototype();
    }

    static WebServer rpServer(OidcProviderConfig providerConfig, Consumer<HttpRouting.Builder> routes) {
        return rpServer(0, providerConfig, routes);
    }

    static WebServer rpServer(int port, OidcProviderConfig providerConfig, Consumer<HttpRouting.Builder> routes) {
        OidcProvider provider = OidcProvider.create(providerConfig);
        Security security = Security.builder()
                .addProvider(provider, "oidc-next")
                .build();
        HttpRouting.Builder routing = HttpRouting.builder();
        OidcFeature.create(provider).setup(routing);
        // This fixture owns one provider for this server; the OIDC feature itself only borrows it.
        routing.addFeature(new HttpFeature() {
            @Override
            public void setup(HttpRouting.Builder routing) {
            }

            @Override
            public void afterStop() {
                provider.close();
            }
        });
        routes.accept(routing);
        return WebServer.builder()
                .port(port)
                .addFeature(SecurityFeature.builder()
                                    .security(security)
                                    .build())
                .addRouting(routing)
                .build()
                .start();
    }

    static URI rpBaseUri(WebServer server) {
        return URI.create("http://localhost:" + server.port());
    }

    static X509Certificate certificate(String resourceName) throws IOException, CertificateException {
        try (InputStream input = KeycloakOidcIntegrationSupport.class.getResourceAsStream("/" + resourceName)) {
            if (input == null) {
                throw new IllegalArgumentException("Missing test certificate: " + resourceName);
            }
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(input);
        }
    }

    static void protectedRoute(HttpRouting.Builder routing, String path) {
        protectedRoute(routing, path, SecurityFeature.authenticate());
    }

    static void protectedRoute(HttpRouting.Builder routing, String path, OidcEndpointPolicyConfig endpointPolicy) {
        protectedRoute(routing, path, SecurityFeature.authenticate().customObject(endpointPolicy));
    }

    static void protectedRoute(HttpRouting.Builder routing, String path, SecurityHandler securityHandler) {
        routing.get(path, securityHandler, (_, response) -> {
            Subject subject = currentSubject();
            Object email = subject.principal().abacAttributeRaw("email");
            response.headers().contentType(HttpMediaTypes.PLAINTEXT_UTF_8);
            response.send(subject.principal().id() + "|" + subject.principal().getName() + "|"
                                  + (email == null ? "" : email));
        });
    }

    static Subject currentSubject() {
        return Contexts.context()
                .flatMap(context -> context.get(SecurityContext.class))
                .flatMap(SecurityContext::user)
                .orElseThrow();
    }

    static WebClient outboundClient() {
        return WebClient.builder()
                .servicesDiscoverServices(false)
                .addService(WebClientSecurity.create())
                .build();
    }

    static String passwordAccessToken() {
        return accessToken(passwordTokenResponse());
    }

    static JsonObject passwordTokenResponse() {
        return tokenResponse(Parameters.builder("token")
                                     .add("grant_type", "password")
                                     .add("username", USERNAME)
                                     .add("password", PASSWORD)
                                     .add("scope", "openid profile email")
                                     .build(),
                             WEB_CLIENT_ID,
                             WEB_CLIENT_SECRET);
    }

    static String clientCredentialsAccessToken() {
        return accessToken(tokenResponse(Parameters.builder("token")
                                   .add("grant_type", "client_credentials")
                                   .build(),
                           SERVICE_CLIENT_ID,
                           SERVICE_CLIENT_SECRET));
    }

    static JsonObject metadata() {
        WebClient client = WebClient.builder()
                .build();
        try {
            try (HttpClientResponse response = client.get()
                    .uri(KeycloakOidcContainer.metadataUri())
                    .request()) {
                return JsonParser.create(response.as(String.class)).readJsonObject();
            }
        } finally {
            client.closeResource();
        }
    }

    static URI authenticate(BrowserSession browser, URI resourceUri) {
        URI authorizationUri;
        try (HttpClientResponse start = browser.get(resourceUri)) {
            assertThat(start.status().code(), is(303));
            authorizationUri = URI.create(start.headers().first(HeaderNames.LOCATION).orElseThrow());
        }

        URI callbackUri;
        try (HttpClientResponse loginPage = browser.get(authorizationUri)) {
            assertThat(loginPage.status().code(), is(200));
            URI loginAction = loginAction(loginPage.as(String.class));
            try (HttpClientResponse login = browser.post(loginAction,
                                                         Parameters.builder("login")
                                                                 .add("username", USERNAME)
                                                                 .add("password", PASSWORD)
                                                                 .build())) {
                assertThat(login.status().code(), is(302));
                callbackUri = URI.create(login.headers().first(HeaderNames.LOCATION).orElseThrow());
            }
        }

        try (HttpClientResponse callback = browser.get(callbackUri)) {
            assertThat(callback.status().code(), is(303));
        }
        return authorizationUri;
    }

    static OutboundTarget tokenPropagationOutboundTarget(URI downstreamUri) {
        return OutboundTarget.builder("keycloak-token-propagation")
                .addTransport(downstreamUri.getScheme())
                .addHost(downstreamUri.getHost())
                .addPath("/downstream")
                .addMethod("GET")
                .customObject(OidcOutboundPolicyConfig.class,
                              OidcOutboundPolicyConfig.builder()
                                      .tokenPropagationEnabled(true)
                                      .audienceValidationEnabled(false)
                                      .buildPrototype())
                .build();
    }

    static OutboundTarget clientCredentialsOutboundTarget(URI downstreamUri) {
        return OutboundTarget.builder("keycloak-client-credentials")
                .addTransport(downstreamUri.getScheme())
                .addHost(downstreamUri.getHost())
                .addPath("/downstream")
                .addMethod("GET")
                .customObject(OidcOutboundPolicyConfig.class,
                              OidcOutboundPolicyConfig.builder()
                                      .clientCredentialsGrantEnabled(true)
                                      .buildPrototype())
                .build();
    }

    static OutboundTarget tokenExchangeOutboundTarget(URI downstreamUri) {
        return OutboundTarget.builder("keycloak-token-exchange")
                .addTransport(downstreamUri.getScheme())
                .addHost(downstreamUri.getHost())
                .addPath("/downstream")
                .addMethod("GET")
                .customObject(OidcOutboundPolicyConfig.class,
                              OidcOutboundPolicyConfig.builder()
                                      .tokenExchangeEnabled(true)
                                      .tokenExchangeAudience(API_AUDIENCE)
                                      .buildPrototype())
                .build();
    }

    private static JsonObject tokenResponse(Parameters form, String clientId, String clientSecret) {
        WebClient client = WebClient.builder()
                .build();
        try {
            try (HttpClientResponse response = client.post()
                    .uri(KeycloakOidcContainer.tokenEndpointUri())
                    .header(HeaderNames.AUTHORIZATION, basicAuthorization(clientId, clientSecret))
                    .submit(form)) {
                return JsonParser.create(response.as(String.class)).readJsonObject();
            }
        } finally {
            client.closeResource();
        }
    }

    private static String accessToken(JsonObject tokenResponse) {
        return tokenResponse.stringValue("access_token").orElseThrow();
    }

    private static String basicAuthorization(String clientId, String clientSecret) {
        return "Basic " + Base64.getEncoder()
                .encodeToString((clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8));
    }

    private static URI loginAction(String html) {
        Matcher matcher = LOGIN_FORM_ACTION.matcher(html);
        if (!matcher.find()) {
            throw new IllegalStateException("Keycloak login form action was not found");
        }
        return URI.create(matcher.group(1).replace("&amp;", "&"));
    }

    private static OidcProviderConfig configuredAuthorizationCodeProviderConfig(
            URI issuer,
            Consumer<OidcEndpointConfig.Builder> endpointCustomizer,
            Consumer<OidcAuthorizationCodeConfig.Builder> authorizationCodeCustomizer,
            Consumer<OidcTenantConfig.Builder> tenantCustomizer) {
        OidcTenantConfig.Builder tenant = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId(WEB_CLIENT_ID)
                .clientSecret(WEB_CLIENT_SECRET)
                .endpoints(endpointCustomizer)
                .authorizationCode(authorizationCode -> {
                    authorizationCode.pushedAuthorizationRequests(OidcPushedAuthorizationRequestMode.DISABLED);
                    authorizationCode.scopes(List.of("openid", "profile", "email"));
                    authorizationCodeCustomizer.accept(authorizationCode);
                })
                .userInfo(userInfo -> userInfo.attributeClaimPaths(List.of("email")))
                .logout(logout -> logout.endSession(_ -> {
                }))
                .cookies(cookies -> cookies.protection(protection -> protection.password(COOKIE_PASSWORD)));
        tenantCustomizer.accept(tenant);
        return OidcProviderConfig.builder()
                .putTenant("default", tenant.buildPrototype())
                .buildPrototype();
    }

    static final class BrowserSession implements AutoCloseable {
        private final WebClient client;
        private final Map<String, String> cookies = new LinkedHashMap<>();

        BrowserSession() {
            client = WebClient.builder().followRedirects(false).build();
        }

        BrowserSession(X509Certificate trustedCertificate) {
            client = WebClient.builder()
                    .followRedirects(false)
                    .tls(tls -> tls.trust(List.of(trustedCertificate)))
                    .build();
        }

        HttpClientResponse get(URI uri) {
            HttpClientRequest request = client.get().uri(uri);
            cookieHeader().ifPresent(header -> request.header(HeaderNames.COOKIE, header));
            HttpClientResponse response = request.request();
            rememberCookies(response);
            return response;
        }

        HttpClientResponse post(URI uri, Parameters form) {
            return post(uri, form, _ -> {
            });
        }

        HttpClientResponse post(URI uri, Parameters form, Consumer<HttpClientRequest> customizer) {
            HttpClientRequest request = client.post().uri(uri);
            cookieHeader().ifPresent(header -> request.header(HeaderNames.COOKIE, header));
            customizer.accept(request);
            HttpClientResponse response = request.submit(form);
            rememberCookies(response);
            return response;
        }

        @Override
        public void close() {
            client.closeResource();
        }

        Optional<String> cookieValue(String name) {
            return Optional.ofNullable(cookies.get(name));
        }

        void applySetCookieHeaders(List<String> setCookieHeaders) {
            for (String setCookieHeader : setCookieHeaders) {
                SetCookie cookie = SetCookie.parse(setCookieHeader);
                boolean removed = cookie.maxAge()
                        .map(maxAge -> maxAge.isZero() || maxAge.isNegative())
                        .orElseGet(() -> cookie.expires()
                                .filter(expires -> !expires.toInstant().isAfter(Instant.now()))
                                .isPresent());
                if (removed) {
                    cookies.remove(cookie.name());
                } else {
                    cookies.put(cookie.name(), cookie.value());
                }
            }
        }

        Optional<String> cookieHeader() {
            if (cookies.isEmpty()) {
                return Optional.empty();
            }
            return Optional.of(String.join("; ",
                                           cookies.entrySet()
                                                   .stream()
                                                   .map(entry -> entry.getKey() + "=" + entry.getValue())
                                                   .toList()));
        }

        private void rememberCookies(HttpClientResponse response) {
            if (!response.headers().contains(HeaderNames.SET_COOKIE)) {
                return;
            }
            applySetCookieHeaders(response.headers().get(HeaderNames.SET_COOKIE).allValues());
        }
    }
}
