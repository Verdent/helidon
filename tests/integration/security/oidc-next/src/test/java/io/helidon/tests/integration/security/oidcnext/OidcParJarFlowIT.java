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
import java.util.List;
import java.util.Set;

import io.helidon.common.uri.UriQuery;
import io.helidon.http.HeaderNames;
import io.helidon.http.Status;
import io.helidon.json.JsonObject;
import io.helidon.json.JsonParser;
import io.helidon.security.providers.oidc.next.OidcProviderConfig;
import io.helidon.security.providers.oidc.next.OidcRequestObjectMode;
import io.helidon.tests.integration.security.oidcnext.OidcIntegrationSupport.BrowserSession;
import io.helidon.tests.integration.security.oidcnext.idp.TestOidcRequest;
import io.helidon.tests.integration.security.oidcnext.idp.TestOidcServer;
import io.helidon.webclient.api.HttpClientResponse;
import io.helidon.webserver.WebServer;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

class OidcParJarFlowIT {
    @Test
    void authorizationCodeFlowUsesPushedAuthorizationRequestFromWellKnownMetadata() {
        try (TestOidcServer idp = TestOidcServer.builder()
                .client(OidcIntegrationSupport.CLIENT_ID, client -> client
                        .clientSecret(OidcIntegrationSupport.CLIENT_SECRET))
                .user("alice", user -> user
                        .subject("alice-id")
                        .claim("preferred_username", "alice")
                        .claim("email", "alice@example.org"))
                .defaultScopes("openid", "profile")
                .tokenDefaults(tokens -> tokens
                        .idToken(id -> id.includeUserClaims("preferred_username")))
                .build()) {
            OidcProviderConfig providerConfig = OidcIntegrationSupport.authorizationCodeProviderConfigFromWellKnown(idp,
                                                                                                                    it -> {
                                                                                                                    });
            WebServer rpServer = OidcIntegrationSupport.rpServer(providerConfig,
                                                                 routing -> OidcIntegrationSupport
                                                                         .protectedRoute(routing, "/resource"));
            try {
                BrowserSession browser = new BrowserSession();
                URI resourceUri = OidcIntegrationSupport.rpBaseUri(rpServer).resolve("/resource");
                URI authorizationUri = startAuthorization(browser, resourceUri);
                UriQuery authorizationQuery = UriQuery.create(authorizationUri);
                assertThat(authorizationQuery.get("client_id"), is(OidcIntegrationSupport.CLIENT_ID));
                assertThat(authorizationQuery.contains("request_uri"), is(true));
                assertThat(authorizationQuery.contains("scope"), is(false));
                assertThat(authorizationQuery.contains("state"), is(false));

                assertThat(idp.pushedAuthorizationEndpointRequests().size(), is(1));
                TestOidcRequest pushedAuthorization = idp.pushedAuthorizationEndpointRequests().getFirst();
                assertThat(pushedAuthorization.formParam("response_type").orElse(""), is("code"));
                assertThat(pushedAuthorization.formParam("client_id").orElse(""), is(OidcIntegrationSupport.CLIENT_ID));
                assertThat(pushedAuthorization.formParam("scope").orElse(""), is("openid profile"));
                assertThat(pushedAuthorization.formParam("code_challenge").orElse("").isBlank(), is(false));
                assertThat(pushedAuthorization.formParam("code_challenge_method").orElse(""), is("S256"));
                assertThat(pushedAuthorization.formParameters().containsKey("request_uri"), is(false));

                completeAuthorization(browser, authorizationUri, resourceUri);

                try (HttpClientResponse authenticated = browser.get(resourceUri)) {
                    assertThat(authenticated.status(), is(Status.OK_200));
                    assertThat(authenticated.as(String.class), is("alice-id|alice|alice@example.org"));
                }
            } finally {
                rpServer.stop();
            }
        }
    }

    @Test
    void authorizationCodeFlowUsesSignedRequestObjectWithPushedAuthorizationRequest() {
        try (TestOidcServer idp = TestOidcServer.builder()
                .client(OidcIntegrationSupport.CLIENT_ID, client -> client
                        .clientSecret(OidcIntegrationSupport.CLIENT_SECRET))
                .user("alice", user -> user
                        .subject("alice-id")
                        .claim("preferred_username", "alice")
                        .claim("email", "alice@example.org"))
                .defaultScopes("openid", "profile")
                .tokenDefaults(tokens -> tokens
                        .idToken(id -> id.includeUserClaims("preferred_username")))
                .build()) {
            OidcProviderConfig providerConfig = OidcIntegrationSupport.authorizationCodeProviderConfig(
                    idp,
                    authorizationCode -> authorizationCode
                            .requestObject(requestObject -> requestObject
                                    .mode(OidcRequestObjectMode.REQUIRED)
                                    .signingJwk(jwk -> jwk.resourcePath("oidc-next-it-sign-jwk.json"))
                                    .signingKeyId("sign-rsa")
                                    .signingAlgorithm("RS256")),
                    tenant -> tenant.endpoints(endpoints -> {
                        OidcIntegrationSupport.authorizationCodeEndpoints(idp, endpoints);
                        endpoints.pushedAuthorizationRequestEndpointUri(idp.pushedAuthorizationRequestEndpointUri());
                    }));
            WebServer rpServer = OidcIntegrationSupport.rpServer(providerConfig,
                                                                 routing -> OidcIntegrationSupport
                                                                         .protectedRoute(routing, "/resource"));
            try {
                BrowserSession browser = new BrowserSession();
                URI resourceUri = OidcIntegrationSupport.rpBaseUri(rpServer).resolve("/resource");
                URI authorizationUri = startAuthorization(browser, resourceUri);
                UriQuery authorizationQuery = UriQuery.create(authorizationUri);
                assertThat(authorizationQuery.get("client_id"), is(OidcIntegrationSupport.CLIENT_ID));
                assertThat(authorizationQuery.contains("request_uri"), is(true));
                assertThat(authorizationQuery.contains("request"), is(false));
                assertThat(authorizationQuery.contains("state"), is(false));

                TestOidcRequest pushedAuthorization = idp.pushedAuthorizationEndpointRequests().getFirst();
                assertThat(pushedAuthorization.formParameters().keySet(), is(Set.of("request")));

                JsonObject requestObject = requestObjectPayload(pushedAuthorization.formParam("request").orElseThrow());
                assertThat(requestObject.stringValue("iss").orElse(""), is(OidcIntegrationSupport.CLIENT_ID));
                assertThat(requestObject.value("aud").orElseThrow()
                                   .asArray()
                                   .values()
                                   .getFirst()
                                   .asString()
                                   .value(),
                           is(idp.issuer().toString()));
                assertThat(requestObject.stringValue("response_type").orElse(""), is("code"));
                assertThat(requestObject.stringValue("client_id").orElse(""), is(OidcIntegrationSupport.CLIENT_ID));
                assertThat(requestObject.stringValue("scope").orElse(""), is("openid profile"));
                assertThat(requestObject.stringValue("code_challenge").orElse("").isBlank(), is(false));
                assertThat(requestObject.stringValue("code_challenge_method").orElse(""), is("S256"));
                assertThat(requestObject.containsKey("state"), is(true));
                assertThat(requestObject.containsKey("nonce"), is(true));
                assertThat(requestObject.containsKey("request_uri"), is(false));

                completeAuthorization(browser, authorizationUri, resourceUri);
            } finally {
                rpServer.stop();
            }
        }
    }

    private static URI startAuthorization(BrowserSession browser, URI resourceUri) {
        try (HttpClientResponse start = browser.get(resourceUri)) {
            assertThat(start.status(), is(Status.SEE_OTHER_303));
            URI authorizationUri = URI.create(start.headers().first(HeaderNames.LOCATION).orElseThrow());
            assertThat(authorizationUri.getPath(), is("/authorize"));
            return authorizationUri;
        }
    }

    private static void completeAuthorization(BrowserSession browser, URI authorizationUri, URI resourceUri) {
        try (HttpClientResponse authorization = browser.get(authorizationUri)) {
            assertThat(authorization.status(), is(Status.SEE_OTHER_303));
            URI callback = URI.create(authorization.headers().first(HeaderNames.LOCATION).orElseThrow());
            assertThat(callback.getPath(), is("/oidc/callback"));
            try (HttpClientResponse callbackResponse = browser.get(callback)) {
                assertThat(callbackResponse.status(), is(Status.SEE_OTHER_303));
                assertThat(callbackResponse.headers().first(HeaderNames.LOCATION).orElseThrow(),
                           is(resourceUri.getPath()));
            }
        }
    }

    private static JsonObject requestObjectPayload(String requestObject) {
        String[] parts = requestObject.split("\\.", -1);
        assertThat(parts.length, is(3));
        return JsonParser.create(new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8))
                .readJsonObject();
    }
}
