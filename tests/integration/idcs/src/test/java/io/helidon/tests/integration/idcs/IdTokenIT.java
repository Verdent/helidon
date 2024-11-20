/*
 * Copyright (c) 2023, 2024 Oracle and/or its affiliates.
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

package io.helidon.tests.integration.idcs;

import java.time.Instant;
import java.util.Set;

import io.helidon.microprofile.testing.junit5.AddConfig;
import io.helidon.security.jwt.Jwt;
import io.helidon.security.jwt.SignedJwt;
import io.helidon.security.jwt.jwk.Jwk;

import jakarta.ws.rs.client.Invocation;
import jakarta.ws.rs.client.WebTarget;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import org.glassfish.jersey.client.ClientProperties;
import org.junit.jupiter.api.Test;
import org.openqa.selenium.Cookie;

import static io.helidon.security.providers.oidc.common.OidcConfig.DEFAULT_ID_COOKIE_NAME;
import static io.helidon.tests.integration.idcs.TestResource.EXPECTED_TEST_MESSAGE;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;

class IdTokenIT extends CommonLoginBase {

    @Test
    public void testAuthenticationWithoutIdToken(WebTarget webTarget) {
        Set<Cookie> cookies = browser.manage().getCookies();

        //Ignore ID token cookie
        Invocation.Builder request = client.target(ipCheckWorkaround(webTarget)).path("/test").request();
        for (Cookie cookie : cookies) {
            if (!cookie.getName().equals(DEFAULT_ID_COOKIE_NAME)) {
                request.header(HttpHeaders.COOKIE, cookie.getName() + "=" + cookie.getValue());
            }
        }

        try (Response response = request.get()) {
            assertThat(response.getStatus(), is(Response.Status.OK.getStatusCode()));
            assertThat(response.readEntity(String.class), is(EXPECTED_TEST_MESSAGE));
            assertThat(response.getHeaderString(HttpHeaders.SET_COOKIE), nullValue());
        }
    }

    @Test
    @AddConfig(key = "security.providers.1.oidc.id-token-signature-validation", value = "false")
    @AddConfig(key = "security.providers.1.oidc.cookie-encryption-id-enabled", value = "false")
    public void testAuthenticationWithExpiredIdToken(WebTarget webTarget) {
        Set<Cookie> cookies = browser.manage().getCookies();

        //Since id token validation is disabled, it is enough to just create some invalid one in terms of date.
        Jwt jwt = Jwt.builder()
                .issueTime(Instant.ofEpochMilli(1))
                .expirationTime(Instant.ofEpochMilli(1))
                .notBefore(Instant.ofEpochMilli(1))
                .build();
        SignedJwt signedJwt = SignedJwt.sign(jwt, Jwk.NONE_JWK);

        //Ignore ID token cookie
        Invocation.Builder request = client.target(ipCheckWorkaround(webTarget))
                .path("/test")
                .request()
                .property(ClientProperties.FOLLOW_REDIRECTS, false);
        for (Cookie cookie : cookies) {
            if (cookie.getName().equals(DEFAULT_ID_COOKIE_NAME)) {
                request.header(HttpHeaders.COOKIE, DEFAULT_ID_COOKIE_NAME + "=" + signedJwt.tokenContent());
            } else {
                request.header(HttpHeaders.COOKIE, cookie.getName() + "=" + cookie.getValue());
            }
        }

        try (Response response = request.get()) {
            assertThat(response.getStatus(), is(Response.Status.TEMPORARY_REDIRECT.getStatusCode()));
        }

    }

}
