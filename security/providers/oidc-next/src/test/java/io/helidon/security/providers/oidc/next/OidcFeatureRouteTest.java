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
import java.util.List;

import io.helidon.http.HeaderNames;
import io.helidon.http.SetCookie;
import io.helidon.http.Status;
import io.helidon.webclient.api.HttpClientResponse;
import io.helidon.webclient.api.WebClient;
import io.helidon.webserver.http.HttpRouting;
import io.helidon.webserver.testing.junit5.ServerTest;
import io.helidon.webserver.testing.junit5.SetUpRoute;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;

@ServerTest
class OidcFeatureRouteTest {
    private static final URI ISSUER = URI.create("https://issuer.example");
    private static final URI AUTHORIZATION_ENDPOINT_URI = URI.create("https://issuer.example/authorize");
    private static final URI TOKEN_ENDPOINT_URI = URI.create("https://issuer.example/token");
    private static final URI CONFIGURED_REDIRECTION_ENDPOINT_URI = URI.create("https://rp.example/oidc/callback");
    private static final String COOKIE_SECRET = "test-cookie-secret";

    @SetUpRoute
    static void routing(HttpRouting.Builder routing) {
        OidcFeature.create(providerConfig()).setup(routing);
    }

    @Test
    void redirectionEndpointRouteRejectsMissingState(WebClient client) {
        try (HttpClientResponse response = client.get("/oidc/callback")
                .queryParam("code", "authorization-code")
                .request()) {
            assertThat(response.status(), is(Status.BAD_REQUEST_400));
            assertThat(response.as(String.class), is("Authorization Response is invalid"));
        }
    }

    @Test
    void redirectionEndpointRouteHandlesAuthorizationErrorBeforeTokenExchange(WebClient client, URI serverUri) {
        Instant now = Instant.now();
        URI callbackUri = serverUri.resolve("oidc/callback");
        SetCookie stateCookie = OidcCookieStateHandler.create(tenantConfig())
                .createAuthenticationRequestCookie(OidcAuthenticationRequestState.create("default",
                                                                                         "stored-state",
                                                                                         "nonce",
                                                                                         "pkce-verifier",
                                                                                         serverUri.resolve("resource"),
                                                                                         callbackUri,
                                                                                         now.minusSeconds(1),
                                                                                         now.plusSeconds(60)));

        try (HttpClientResponse response = client.get("/oidc/callback")
                .queryParam("error", "access_denied")
                .queryParam("state", "stored-state")
                .header(HeaderNames.COOKIE, stateCookie.name() + "=" + stateCookie.value())
                .request()) {
            assertThat(response.status(), is(Status.BAD_REQUEST_400));
            assertThat(response.as(String.class), is("OpenID Provider returned an Authorization Error Response"));

            List<String> removalCookies = response.headers().get(HeaderNames.SET_COOKIE).allValues();
            assertThat(removalCookies.size(), is(1));
            assertThat(removalCookies.getFirst(), containsString("__Host-helidon-oidc-state="));
            assertThat(removalCookies.getFirst(), containsString("Expires="));
        }
    }

    private static OidcProviderConfig providerConfig() {
        return OidcProviderConfig.builder()
                .putTenant("default", tenantConfig())
                .buildPrototype();
    }

    private static OidcTenantConfig tenantConfig() {
        return OidcTenantConfig.builder()
                .issuer(ISSUER)
                .clientId("client-id")
                .clientSecret("client-secret")
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .authorizationCode(it -> it.enabled(true)
                        .redirectionEndpointUri(CONFIGURED_REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret(COOKIE_SECRET))
                .buildPrototype();
    }
}
