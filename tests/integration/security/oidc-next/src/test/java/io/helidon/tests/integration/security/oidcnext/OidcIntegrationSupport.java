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

package io.helidon.tests.integration.security.oidcnext;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;

import io.helidon.common.context.Contexts;
import io.helidon.common.parameters.Parameters;
import io.helidon.common.uri.UriQuery;
import io.helidon.http.HeaderNames;
import io.helidon.http.HttpMediaTypes;
import io.helidon.http.SetCookie;
import io.helidon.json.JsonObject;
import io.helidon.json.JsonParser;
import io.helidon.security.Security;
import io.helidon.security.SecurityContext;
import io.helidon.security.Subject;
import io.helidon.security.providers.oidc.next.OidcAuthorizationCodeConfig;
import io.helidon.security.providers.oidc.next.OidcFeature;
import io.helidon.security.providers.oidc.next.OidcProvider;
import io.helidon.security.providers.oidc.next.OidcProviderConfig;
import io.helidon.security.providers.oidc.next.OidcTenantConfig;
import io.helidon.security.providers.oidc.next.OidcTokenValidationMethod;
import io.helidon.tests.integration.security.oidcnext.idp.TestOidcServer;
import io.helidon.webclient.api.HttpClientResponse;
import io.helidon.webclient.api.WebClient;
import io.helidon.webserver.WebServer;
import io.helidon.webserver.http.HttpRouting;
import io.helidon.webserver.security.SecurityFeature;

final class OidcIntegrationSupport {
    static final String CLIENT_ID = "client-id";
    static final String CLIENT_SECRET = "client-secret";
    static final String COOKIE_SECRET = "integration-test-cookie-secret";

    private OidcIntegrationSupport() {
    }

    static OidcProviderConfig authorizationCodeProviderConfig(TestOidcServer idp,
                                                              Consumer<OidcAuthorizationCodeConfig.Builder>
                                                                      authorizationCodeCustomizer) {
        return authorizationCodeProviderConfig(idp, authorizationCodeCustomizer, tenant -> {
        });
    }

    static OidcProviderConfig authorizationCodeProviderConfig(TestOidcServer idp,
                                                              Consumer<OidcAuthorizationCodeConfig.Builder>
                                                                      authorizationCodeCustomizer,
                                                              Consumer<OidcTenantConfig.Builder> tenantCustomizer) {
        OidcTenantConfig.Builder tenant = OidcTenantConfig.builder()
                .issuer(idp.issuer())
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .endpoints(endpoints -> endpoints
                        .authorizationEndpointUri(idp.authorizationEndpointUri())
                        .tokenEndpointUri(idp.tokenEndpointUri())
                        .jwksUri(idp.jwksUri())
                        .introspectionEndpointUri(idp.introspectionEndpointUri())
                        .userInfoEndpointUri(idp.userInfoEndpointUri())
                        .tlsRequired(false))
                .authorizationCode(authorizationCode -> {
                    authorizationCode.scopes(List.of("openid", "profile"));
                    authorizationCodeCustomizer.accept(authorizationCode);
                })
                .userInfo(userInfo -> {
                })
                .cookies(cookies -> cookies.encryptionSecret(COOKIE_SECRET));
        tenantCustomizer.accept(tenant);
        return OidcProviderConfig.builder()
                .putTenant("default", tenant.buildPrototype())
                .buildPrototype();
    }

    static OidcProviderConfig protectedResourceProviderConfig(TestOidcServer idp, String clientId, String audience) {
        return protectedResourceProviderConfig(idp, clientId, null, audience, OidcTokenValidationMethod.JWT);
    }

    static OidcProviderConfig protectedResourceProviderConfig(TestOidcServer idp,
                                                              String clientId,
                                                              String clientSecret,
                                                              String audience,
                                                              OidcTokenValidationMethod method) {
        OidcTenantConfig.Builder tenant = OidcTenantConfig.builder()
                .issuer(idp.issuer())
                .clientId(clientId)
                .endpoints(endpoints -> endpoints
                        .jwksUri(idp.jwksUri())
                        .introspectionEndpointUri(idp.introspectionEndpointUri())
                        .tlsRequired(false))
                .protectedResource(resource -> resource
                        .tokenValidation(validation -> validation
                                .method(method)
                                .audience(audience)));
        if (clientSecret != null) {
            tenant.clientSecret(clientSecret);
        }
        return OidcProviderConfig.builder()
                .putTenant("default", tenant.buildPrototype())
                .buildPrototype();
    }

    static WebServer rpServer(OidcProviderConfig providerConfig,
                              Consumer<HttpRouting.Builder> routeCustomizer) {
        Security security = Security.builder()
                .addProvider(OidcProvider.create(providerConfig), "oidc-next")
                .build();
        HttpRouting.Builder routing = HttpRouting.builder();
        OidcFeature.create(providerConfig).setup(routing);
        routeCustomizer.accept(routing);
        return WebServer.builder()
                .port(0)
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

    static void protectedRoute(HttpRouting.Builder routing, String path) {
        routing.get(path, SecurityFeature.authenticate(), (request, response) -> {
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

    static String basicAuthorization(String clientId, String clientSecret) {
        return "Basic " + Base64.getEncoder()
                .encodeToString((clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8));
    }

    static String clientCredentialsToken(TestOidcServer idp, String clientId, String clientSecret) {
        WebClient client = WebClient.builder()
                .build();
        Parameters form = Parameters.builder("token")
                .add("grant_type", "client_credentials")
                .build();
        try (HttpClientResponse response = client.post()
                .uri(idp.tokenEndpointUri())
                .header(HeaderNames.AUTHORIZATION, basicAuthorization(clientId, clientSecret))
                .submit(form)) {
            JsonObject json = JsonParser.create(response.as(String.class)).readJsonObject();
            return json.stringValue("access_token").orElseThrow();
        }
    }

    static Parameters loginForm(URI authorizationUri, String username, String password) {
        UriQuery query = UriQuery.create(authorizationUri);
        Parameters.Builder builder = Parameters.builder("login");
        query.names().forEach(name -> query.all(name).forEach(value -> builder.add(name, value)));
        builder.add("username", username);
        builder.add("password", password);
        return builder.build();
    }

    static final class BrowserSession {
        private final WebClient client = WebClient.builder()
                .followRedirects(false)
                .build();
        private final Map<String, String> cookies = new LinkedHashMap<>();

        HttpClientResponse get(URI uri) {
            HttpClientResponse response = cookieHeader()
                    .map(header -> client.get().uri(uri).header(HeaderNames.COOKIE, header).request())
                    .orElseGet(() -> client.get().uri(uri).request());
            rememberCookies(response);
            return response;
        }

        HttpClientResponse post(URI uri, Parameters form) {
            HttpClientResponse response = cookieHeader()
                    .map(header -> client.post().uri(uri).header(HeaderNames.COOKIE, header).submit(form))
                    .orElseGet(() -> client.post().uri(uri).submit(form));
            rememberCookies(response);
            return response;
        }

        private Optional<String> cookieHeader() {
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
            response.headers()
                    .get(HeaderNames.SET_COOKIE)
                    .allValues()
                    .stream()
                    .map(SetCookie::parse)
                    .forEach(cookie -> cookies.put(cookie.name(), cookie.value()));
        }
    }
}
