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
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import io.helidon.common.parameters.Parameters;
import io.helidon.http.HeaderNames;
import io.helidon.http.HeaderValues;
import io.helidon.json.JsonObject;
import io.helidon.security.AuthenticationResponse;
import io.helidon.security.Grant;
import io.helidon.security.Role;
import io.helidon.security.SecurityEnvironment;
import io.helidon.security.SecurityResponse;
import io.helidon.security.Subject;
import io.helidon.security.providers.common.TokenCredential;
import io.helidon.webserver.http.HttpRouting;
import io.helidon.webserver.http.ServerRequest;
import io.helidon.webserver.http.ServerResponse;
import io.helidon.webserver.testing.junit5.ServerTest;
import io.helidon.webserver.testing.junit5.SetUpRoute;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

@ServerTest
class OidcIntrospectionAccessTokenValidationTest {
    private static final URI ISSUER = URI.create("https://issuer.example");
    private static final String AUDIENCE = "api://default";
    private static final String SUBJECT = "user1-id";
    private static final String USERNAME = "user1";
    private static final String CLIENT_ID = "client/id";
    private static final String CLIENT_SECRET = "client+secret=value";
    private static final String OPAQUE_TOKEN = "opaque-token+value/=";

    private static int responseStatus;
    private static String responseBody;
    private static final AtomicReference<RecordedRequest> RECORDED_REQUEST = new AtomicReference<>();

    private URI introspectionEndpointUri;

    @SetUpRoute
    static void routing(HttpRouting.Builder routing) {
        routing.post("/introspect", OidcIntrospectionAccessTokenValidationTest::handleIntrospection);
    }

    @BeforeEach
    void setUp(URI serverUri) {
        introspectionEndpointUri = serverUri.resolve("introspect");
        responseStatus = 200;
        responseBody = validResponse(it -> { }).toString();
        RECORDED_REQUEST.set(null);
    }

    @Test
    void validIntrospectionAuthenticatesSubject() {
        AuthenticationResponse response = authenticate(provider(), OPAQUE_TOKEN);

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        Subject subject = response.user().orElseThrow();
        assertThat(subject.principal().id(), is(SUBJECT));
        assertThat(subject.principal().getName(), is(USERNAME));
        assertThat(subject.principal().abacAttributeRaw("email"), is("user1@example.org"));
        assertThat(subject.grants(Role.class).stream().map(Role::getName).toList(), is(List.of("admin", "auditor")));
        assertThat(subject.grantsByType("scope").stream().map(Grant::getName).toList(),
                   is(List.of("resource.read", "resource.write")));

        TokenCredential credential = subject.publicCredential(TokenCredential.class).orElseThrow();
        assertThat(credential.token(), is(OPAQUE_TOKEN));
        assertThat(credential.getIssuer().orElse(""), is(ISSUER.toString()));
        assertThat(credential.getIssueTime().isPresent(), is(true));
        assertThat(credential.getExpTime().isPresent(), is(true));
        assertThat(credential.getTokenInstance(JsonObject.class).isPresent(), is(true));

        RecordedRequest request = RECORDED_REQUEST.get();
        assertThat(request != null, is(true));
        assertThat(request.method(), is("POST"));
        assertThat(request.authorization(), is(basicAuthorization()));
        assertThat(request.contentType(), is("application/x-www-form-urlencoded"));
        assertThat(request.formParameters(), is(Map.of("token", List.of(OPAQUE_TOKEN),
                                                       "token_type_hint", List.of("access_token"))));
        assertThat(response.responseHeaders().containsKey("Location"), is(false));
    }

    @Test
    void clientIdCanBePrincipalWhenSubjectIsMissing() {
        responseBody = validResponse(it -> it.unset("sub")
                .unset("username")
                .unset("preferred_username")
                .set("client_id", "service-client")).toString();

        AuthenticationResponse response = authenticate(provider(), OPAQUE_TOKEN);

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.user().orElseThrow().principal().id(), is("service-client"));
        assertThat(response.user().orElseThrow().principal().getName(), is("service-client"));
    }

    @Test
    void bearerEvidenceWinsOverAuthorizationCodeFlowForIntrospection() {
        AuthenticationResponse response = provider().authenticate(
                OidcProviderTest.request(OidcEndpointPolicy.protectedResourceAndAuthorizationCodeFlow(),
                                         SecurityEnvironment.builder()
                                                 .header("Authorization", "Bearer " + OPAQUE_TOKEN)
                                                 .build()));

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.responseHeaders().containsKey("Location"), is(false));
    }

    @Test
    void inactiveIntrospectionResponseIsRejected() {
        responseBody = JsonObject.builder()
                .set("active", false)
                .build()
                .toString();

        AuthenticationResponse response = authenticate(provider(), OPAQUE_TOKEN);

        assertInvalidToken(response, "Bearer Token introspection response is inactive");
    }

    @Test
    void wrongIssuerIsRejectedWhenReturned() {
        responseBody = validResponse(it -> it.set("iss", "https://other.example")).toString();

        AuthenticationResponse response = authenticate(provider(), OPAQUE_TOKEN);

        assertInvalidToken(response, "Bearer Token introspection claims are invalid");
    }

    @Test
    void wrongAudienceIsRejectedWhenReturned() {
        responseBody = validResponse(it -> it.setStrings("aud", List.of("api://other"))).toString();

        AuthenticationResponse response = authenticate(provider(), OPAQUE_TOKEN);

        assertInvalidToken(response, "Bearer Token introspection claims are invalid");
    }

    @Test
    void missingAudienceIsRejectedWhenAudienceValidationIsEnabled() {
        responseBody = validResponse(it -> it.unset("aud")).toString();

        AuthenticationResponse response = authenticate(provider(), OPAQUE_TOKEN);

        assertInvalidToken(response, "Bearer Token introspection claims are invalid");
    }

    @Test
    void audienceValidationCanBeDisabled() {
        responseBody = validResponse(it -> it.setStrings("aud", List.of("api://other"))).toString();

        AuthenticationResponse response = authenticate(provider(false), OPAQUE_TOKEN);

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
    }

    @Test
    void audienceValidationCanBeDisabledWithoutConfiguredAudience() {
        responseBody = validResponse(it -> it.setStrings("aud", List.of("api://other"))).toString();

        AuthenticationResponse response = authenticate(provider(false, false), OPAQUE_TOKEN);

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
    }

    @Test
    void expiredTokenIsRejectedWhenReturned() {
        responseBody = validResponse(it -> it.set("exp", Instant.now().minus(5, ChronoUnit.MINUTES).getEpochSecond()))
                .toString();

        AuthenticationResponse response = authenticate(provider(), OPAQUE_TOKEN);

        assertInvalidToken(response, "Bearer Token introspection claims are invalid");
    }

    @Test
    void futureNotBeforeIsRejectedWhenReturned() {
        responseBody = validResponse(it -> it.set("nbf", Instant.now().plus(5, ChronoUnit.MINUTES).getEpochSecond()))
                .toString();

        AuthenticationResponse response = authenticate(provider(), OPAQUE_TOKEN);

        assertInvalidToken(response, "Bearer Token introspection claims are invalid");
    }

    @Test
    void missingPrincipalClaimIsRejected() {
        responseBody = validResponse(it -> it.unset("sub")
                .unset("username")
                .unset("preferred_username")
                .unset("client_id")).toString();

        AuthenticationResponse response = authenticate(provider(), OPAQUE_TOKEN);

        assertInvalidToken(response, "Bearer Token introspection response has no principal claim");
    }

    @Test
    void unsupportedTokenTypeIsRejectedWhenReturned() {
        responseBody = validResponse(it -> it.set("token_type", "mac")).toString();

        AuthenticationResponse response = authenticate(provider(), OPAQUE_TOKEN);

        assertInvalidToken(response, "Bearer Token introspection claims are invalid");
    }

    @Test
    void malformedIntrospectionResponseIsRejected() {
        responseBody = "{not-json";

        AuthenticationResponse response = authenticate(provider(), OPAQUE_TOKEN);

        assertInvalidToken(response, "Bearer Token introspection response is invalid");
    }

    @Test
    void nonSuccessfulIntrospectionResponseIsRejected() {
        responseStatus = 400;
        responseBody = JsonObject.builder()
                .set("error", "invalid_request")
                .build()
                .toString();

        AuthenticationResponse response = authenticate(provider(), OPAQUE_TOKEN);

        assertInvalidToken(response, "Bearer Token introspection endpoint rejected the token");
    }

    @Test
    void unavailableIntrospectionEndpointIsRejected() {
        responseStatus = 503;
        responseBody = JsonObject.builder()
                .set("error", "temporarily_unavailable")
                .build()
                .toString();

        AuthenticationResponse response = authenticate(provider(), OPAQUE_TOKEN);

        assertInvalidToken(response, "Bearer Token introspection endpoint is unavailable");
    }

    private static void handleIntrospection(ServerRequest request, ServerResponse response) {
        RECORDED_REQUEST.set(new RecordedRequest(request.prologue().method().text(),
                                                request.headers().first(HeaderNames.AUTHORIZATION).orElse(""),
                                                request.headers().first(HeaderNames.CONTENT_TYPE).orElse(""),
                                                formParameters(request.content().as(Parameters.class))));
        response.status(responseStatus)
                .header(HeaderValues.CONTENT_TYPE_JSON)
                .send(responseBody);
    }

    private AuthenticationResponse authenticate(OidcProvider provider, String token) {
        return provider.authenticate(OidcProviderTest.request(null,
                                                              SecurityEnvironment.builder()
                                                                      .header("Authorization", "Bearer " + token)
                                                                      .build()));
    }

    private OidcProvider provider() {
        return provider(true);
    }

    private OidcProvider provider(boolean audienceValidationEnabled) {
        return provider(audienceValidationEnabled, true);
    }

    private OidcProvider provider(boolean audienceValidationEnabled, boolean audienceConfigured) {
        return OidcProvider.create(OidcProviderConfig.builder()
                                           .putTenant("default", OidcTenantConfig.builder()
                                                   .issuer(ISSUER)
                                                   .clientId(CLIENT_ID)
                                                   .clientSecret(CLIENT_SECRET)
                                                   .endpoints(it -> it
                                                           .introspectionEndpointUri(introspectionEndpointUri))
                                                   .protectedResource(it -> it.enabled(true)
                                                           .tokenValidation(validation -> {
                                                               validation
                                                                       .method(OidcTokenValidationMethod.INTROSPECTION)
                                                                       .audienceValidationEnabled(
                                                                               audienceValidationEnabled);
                                                               if (audienceConfigured) {
                                                                   validation.audience(AUDIENCE);
                                                               }
                                                           }))
                                                   .buildPrototype())
                                           .buildPrototype());
    }

    private JsonObject validResponse(Consumer<JsonObject.Builder> customizer) {
        Instant now = Instant.now();
        JsonObject.Builder builder = JsonObject.builder()
                .set("active", true)
                .set("sub", SUBJECT)
                .set("username", USERNAME)
                .set("preferred_username", USERNAME)
                .set("email", "user1@example.org")
                .set("iss", ISSUER.toString())
                .setStrings("aud", List.of(AUDIENCE))
                .set("exp", now.plus(1, ChronoUnit.HOURS).getEpochSecond())
                .set("iat", now.minus(1, ChronoUnit.MINUTES).getEpochSecond())
                .set("nbf", now.minus(1, ChronoUnit.MINUTES).getEpochSecond())
                .set("scope", "resource.read resource.write")
                .setStrings("groups", List.of("admin", "auditor"))
                .set("client_id", "calling-client")
                .set("token_type", "Bearer");
        customizer.accept(builder);
        return builder.build();
    }

    private static String basicAuthorization() {
        byte[] credentials = (formEncode(CLIENT_ID) + ":" + formEncode(CLIENT_SECRET))
                .getBytes(StandardCharsets.UTF_8);
        return "Basic " + Base64.getEncoder()
                .encodeToString(credentials);
    }

    private static String formEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static void assertInvalidToken(AuthenticationResponse response, String description) {
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.FAILURE));
        assertThat(response.statusCode().orElse(-1), is(401));
        assertThat(response.description().orElse(""), is(description));
        assertThat(response.responseHeaders().get("WWW-Authenticate").get(0),
                   is("Bearer error=\"invalid_token\", error_description=\"" + description + "\""));
        assertThat(response.responseHeaders().containsKey("Location"), is(false));
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
