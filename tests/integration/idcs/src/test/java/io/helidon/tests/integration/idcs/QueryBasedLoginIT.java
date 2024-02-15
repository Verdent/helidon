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

import io.helidon.microprofile.testing.junit5.AddConfig;

import jakarta.ws.rs.client.WebTarget;
import jakarta.ws.rs.core.Response;
import org.glassfish.jersey.client.ClientProperties;
import org.junit.jupiter.api.Test;

import static io.helidon.tests.integration.idcs.TestResource.EXPECTED_TEST_MESSAGE;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

@AddConfig(key = "security.providers.1.oidc.cookie-use", value = "false")
@AddConfig(key = "security.providers.1.oidc.query-param-use", value = "true")
@AddConfig(key = "server.protocols.http_1_1.max-prologue-length", value = "8192")
class QueryBasedLoginIT extends CommonLoginBase {

    @Test
    void testSuccessfulLogin(WebTarget webTarget) {
        String redirectUri = browser.getCurrentUrl(); //This URL contains all authentication information

        //Request with query parameters should pass
        try (Response response = client.target(redirectUri).request().get()) {
            assertThat(response.getStatus(), is(Response.Status.OK.getStatusCode()));
            assertThat(response.readEntity(String.class), is(EXPECTED_TEST_MESSAGE));
        }

        //Another request with query parameters should pass as well
        try (Response response = client.target(redirectUri).request().get()) {
            assertThat(response.getStatus(), is(Response.Status.OK.getStatusCode()));
            assertThat(response.readEntity(String.class), is(EXPECTED_TEST_MESSAGE));
        }

        //Request without query parameters should be redirected to the identity server again
        try (Response response = webTarget.property(ClientProperties.FOLLOW_REDIRECTS, Boolean.FALSE)
                .path("/test")
                .request()
                .get()) {
            assertThat(response.getStatus(), is(Response.Status.TEMPORARY_REDIRECT.getStatusCode()));
        }
    }

}
