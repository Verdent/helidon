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

package io.helidon.tests.integration.security.oidcnext.providers;

import java.net.URI;
import java.util.Optional;

import io.helidon.http.HeaderNames;
import io.helidon.http.Status;
import io.helidon.security.providers.oidc.next.OidcCookieConfig;
import io.helidon.webclient.api.HttpClientResponse;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

class KeycloakOidcIT extends OidcProviderContract {
    @Override
    IdpAdapter createAdapter() {
        return new KeycloakAdapter();
    }

    @Test
    void administratorLogoutDeliversSidBoundBackChannelNotification() throws Exception {
        assertAdministratorBackChannelLogout(true);
    }

    @Test
    void administratorLogoutDeliversBackChannelNotificationWithoutRequiredSid() throws Exception {
        assertAdministratorBackChannelLogout(false);
    }

    private void assertAdministratorBackChannelLogout(boolean sessionRequired) throws Exception {
        KeycloakAdapter keycloak = (KeycloakAdapter) adapter();
        // The shared test certificate covers auth.authelia.test. The RP routes by path; the actual public port is
        // known only after the test server starts and is registered separately at Keycloak.
        URI route = URI.create("https://auth.authelia.test/oidc/backchannel");
        try (RelyingParty rp = new RelyingParty(keycloak, IdpAdapter.ClientMode.BASIC, true,
                tenant -> tenant.logout(logout -> logout.backChannel(backChannel -> backChannel
                        .uri(route).sessionRequired(sessionRequired))), true);
             TestBrowser browser = new TestBrowser(keycloak.webClient())) {
            URI reachable = URI.create("https://auth.authelia.test:" + rp.baseUri().getPort() + route.getPath());
            try (AutoCloseable _ = keycloak.registerBackChannelLogout(IdpAdapter.ClientMode.BASIC,
                                                                       reachable, sessionRequired)) {
                authenticate(browser, rp);
                try (HttpClientResponse response = browser.get(rp.baseUri().resolve("/resource"))) {
                    assertThat(response.status(), is(Status.OK_200));
                }

                // Admin logout cannot access the browser cookie; the OP-signed POST is what reaches the RP.
                String cookieName = OidcCookieConfig.create().localAuthenticationCookieName();
                assertThat(browser.cookieValue(cookieName).isPresent(), is(true));
                keycloak.logoutUser("alice");
                assertThat(rp.awaitBackChannelLogout(), is(Status.OK_200));
                try (HttpClientResponse response = browser.get(rp.baseUri().resolve("/resource"))) {
                    assertThat(response.status(), is(Status.SEE_OTHER_303));
                    assertThat(response.headers().contains(HeaderNames.SET_COOKIE), is(true));
                }
                assertThat(browser.cookieValue(cookieName), is(Optional.empty()));
            }
        }
    }
}
