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

import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Set;

import io.helidon.microprofile.testing.junit5.AddConfig;
import io.helidon.security.jwt.Jwt;
import io.helidon.security.jwt.SignedJwt;
import io.helidon.security.jwt.jwk.Jwk;
import io.helidon.security.providers.oidc.common.OidcConfig;

import jakarta.json.JsonObject;
import jakarta.ws.rs.client.Invocation;
import jakarta.ws.rs.client.WebTarget;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;
import org.openqa.selenium.Cookie;

import static io.helidon.tests.integration.idcs.TestResource.EXPECTED_TEST_MESSAGE;
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;

@AddConfig(key = "security.providers.1.oidc.token-signature-validation", value = "false")
class RefreshTokenIT extends CommonLoginBase {

    @Test
    public void testRefreshToken(WebTarget webTarget) {
        Set<Cookie> browserCookies = browser.manage().getCookies();
        Cookie accessTokenCookie = browser.manage().getCookieNamed(OidcConfig.DEFAULT_COOKIE_NAME);

        //Since access token validation is disabled, it is enough to just create some invalid one in terms of date.
        Jwt jwt = Jwt.builder()
                .issueTime(Instant.ofEpochMilli(1))
                .expirationTime(Instant.ofEpochMilli(1))
                .notBefore(Instant.ofEpochMilli(1))
                .build();
        SignedJwt signedJwt = SignedJwt.sign(jwt, Jwk.NONE_JWK);

        String originalAccessValue = new String(Base64.getDecoder().decode(accessTokenCookie.getValue()), StandardCharsets.UTF_8);
        JsonObject original = JSON_READER_FACTORY.createReader(new StringReader(originalAccessValue)).readObject();
        JsonObject jsonObject = JSON_OBJECT_BUILDER_FACTORY.createObjectBuilder(original)
                .add("accessToken", signedJwt.tokenContent())
//                .add("remotePeer", "127.0.0.1") //Workaround for Chrome using IPv6
                .build();
        String base64 = Base64.getEncoder().encodeToString(jsonObject.toString().getBytes(StandardCharsets.UTF_8));

        Invocation.Builder request = client.target(ipCheckWorkaround(webTarget))
                .path("/test")
                .request();

        for (Cookie cookie : browserCookies) {
            if (cookie.getName().equals(OidcConfig.DEFAULT_COOKIE_NAME)) {
                request.header(HttpHeaders.COOKIE, OidcConfig.DEFAULT_COOKIE_NAME + "=" + base64);
            } else {
                request.header(HttpHeaders.COOKIE, cookie.getName() + "=" + cookie.getValue());
            }
        }

        try (Response response = request.get()) {
            assertThat(response.getStatus(), is(Response.Status.OK.getStatusCode()));
            assertThat(response.readEntity(String.class), is(EXPECTED_TEST_MESSAGE));
            //Since invalid access token has been provided, this means that the new one has been obtained
            List<String> cookies = response.getStringHeaders().get(HttpHeaders.SET_COOKIE);
            assertThat(cookies, not(empty()));
            assertThat(cookies, hasItem(startsWith(OidcConfig.DEFAULT_COOKIE_NAME)));
        }

        //next request should have cookie set, and we do not need to authenticate again
        try (Response response = client.target(ipCheckWorkaround(webTarget)).path("/test").request().get()) {
            assertThat(response.getStatus(), is(Response.Status.OK.getStatusCode()));
            assertThat(response.readEntity(String.class), is(EXPECTED_TEST_MESSAGE));
            assertThat(response.getHeaderString(HttpHeaders.SET_COOKIE), nullValue());
        }

    }

}
