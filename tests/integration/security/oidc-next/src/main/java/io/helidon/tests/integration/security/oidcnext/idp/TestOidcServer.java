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

package io.helidon.tests.integration.security.oidcnext.idp;

import java.io.UncheckedIOException;
import java.math.BigDecimal;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

import io.helidon.common.configurable.Resource;
import io.helidon.common.parameters.Parameters;
import io.helidon.http.HeaderNames;
import io.helidon.http.HeaderValues;
import io.helidon.http.Status;
import io.helidon.json.JsonObject;
import io.helidon.json.JsonValue;
import io.helidon.security.jwt.Jwt;
import io.helidon.security.jwt.SignedJwt;
import io.helidon.security.jwt.jwk.JwkKeys;
import io.helidon.webserver.WebServer;
import io.helidon.webserver.http.HttpRouting;
import io.helidon.webserver.http.ServerRequest;
import io.helidon.webserver.http.ServerResponse;

/**
 * In-process OpenID Connect identity provider for integration tests.
 */
public final class TestOidcServer implements AutoCloseable {
    private static final String SIGNING_RESOURCE = "oidc-next-it-sign-jwk.json";
    private static final String VERIFY_RESOURCE = "oidc-next-it-verify-jwk.json";
    private static final String SIGNING_KEY_ID = "sign-rsa";
    private static final String VERIFY_KEY_ID = "verify-rsa";
    private static final String SIGNING_ALGORITHM = "RS256";

    private final TestOidcServerConfig config;
    private final WebServer server;
    private final JwkKeys signingKeys;
    private final String jwks;
    private final AtomicLong ids = new AtomicLong();
    private final Map<String, AuthorizationCode> authorizationCodes = new ConcurrentHashMap<>();
    private final Map<String, RefreshState> refreshTokens = new ConcurrentHashMap<>();
    private final Map<String, IssuedAccessToken> accessTokens = new ConcurrentHashMap<>();
    private final List<TestOidcRequest> metadataRequests = new CopyOnWriteArrayList<>();
    private final List<TestOidcRequest> authorizationRequests = new CopyOnWriteArrayList<>();
    private final List<TestOidcRequest> tokenRequests = new CopyOnWriteArrayList<>();
    private final List<TestOidcRequest> jwksRequests = new CopyOnWriteArrayList<>();
    private final List<TestOidcRequest> userInfoRequests = new CopyOnWriteArrayList<>();
    private final List<TestOidcRequest> logoutRequests = new CopyOnWriteArrayList<>();

    private URI issuer;

    private TestOidcServer(TestOidcServerConfig config) {
        this.config = Objects.requireNonNull(config);
        this.signingKeys = JwkKeys.builder()
                .resource(Resource.create(SIGNING_RESOURCE))
                .build();
        this.jwks = Resource.create(VERIFY_RESOURCE).string();

        HttpRouting.Builder routing = HttpRouting.builder();
        routing.get("/.well-known/openid-configuration", this::metadataEndpoint);
        routing.get("/authorize", this::authorizationEndpoint);
        routing.post("/authorize/login", this::loginEndpoint);
        routing.post("/token", this::tokenEndpoint);
        routing.get("/jwks", this::jwksEndpoint);
        routing.get("/userinfo", this::userInfoEndpoint);
        routing.get("/logout", this::logoutEndpoint);
        this.server = WebServer.builder()
                .port(0)
                .addRouting(routing)
                .build()
                .start();
        this.issuer = config.issuer()
                .orElseGet(() -> URI.create("http://localhost:" + server.port()));
    }

    /**
     * Create a new builder.
     *
     * @return builder
     */
    public static Builder builder() {
        return new Builder();
    }

    static TestOidcServer create(TestOidcServerConfig config) {
        return new TestOidcServer(config);
    }

    /**
     * Issuer URI.
     *
     * @return issuer URI
     */
    public URI issuer() {
        return issuer;
    }

    /**
     * Metadata endpoint URI.
     *
     * @return metadata URI
     */
    public URI metadataUri() {
        return issuer.resolve("/.well-known/openid-configuration");
    }

    /**
     * Authorization endpoint URI.
     *
     * @return authorization endpoint URI
     */
    public URI authorizationEndpointUri() {
        return issuer.resolve("/authorize");
    }

    /**
     * Token endpoint URI.
     *
     * @return token endpoint URI
     */
    public URI tokenEndpointUri() {
        return issuer.resolve("/token");
    }

    /**
     * JWKS endpoint URI.
     *
     * @return JWKS endpoint URI
     */
    public URI jwksUri() {
        return issuer.resolve("/jwks");
    }

    /**
     * UserInfo endpoint URI.
     *
     * @return UserInfo endpoint URI
     */
    public URI userInfoEndpointUri() {
        return issuer.resolve("/userinfo");
    }

    /**
     * Logout endpoint URI.
     *
     * @return logout endpoint URI
     */
    public URI logoutEndpointUri() {
        return issuer.resolve("/logout");
    }

    /**
     * Recorded token endpoint requests.
     *
     * @return requests
     */
    public List<TestOidcRequest> tokenRequests() {
        return List.copyOf(tokenRequests);
    }

    /**
     * Recorded authorization endpoint requests.
     *
     * @return requests
     */
    public List<TestOidcRequest> authorizationRequests() {
        return List.copyOf(authorizationRequests);
    }

    /**
     * Recorded UserInfo endpoint requests.
     *
     * @return requests
     */
    public List<TestOidcRequest> userInfoRequests() {
        return List.copyOf(userInfoRequests);
    }

    /**
     * Current metadata JSON.
     *
     * @return metadata
     */
    public JsonObject metadata() {
        JsonObject.Builder builder = JsonObject.builder()
                .set("issuer", issuer.toString())
                .set("authorization_endpoint", authorizationEndpointUri().toString())
                .set("token_endpoint", tokenEndpointUri().toString())
                .set("jwks_uri", jwksUri().toString())
                .set("userinfo_endpoint", userInfoEndpointUri().toString())
                .set("end_session_endpoint", logoutEndpointUri().toString())
                .setStrings("response_types_supported", List.of("code"))
                .setStrings("grant_types_supported", List.of("authorization_code", "refresh_token", "client_credentials"))
                .setStrings("subject_types_supported", List.of("public"))
                .setStrings("id_token_signing_alg_values_supported", List.of(SIGNING_ALGORITHM));
        config.metadata().claims().forEach((name, value) -> TestOidcJsonSupport.set(builder, name, value));
        return builder.build();
    }

    @Override
    public void close() {
        server.stop();
    }

    private void metadataEndpoint(ServerRequest request, ServerResponse response) {
        TestOidcRequest oidcRequest = TestOidcRequest.create(request, false);
        metadataRequests.add(oidcRequest);
        Optional<TestOidcEndpointHandler<TestOidcEndpointContext>> handler = config.endpoints().metadata();
        if (handler.isPresent()) {
            handler.orElseThrow().handle(new EndpointContext(oidcRequest, response, this::defaultMetadata));
            return;
        }
        defaultMetadata(oidcRequest, response);
    }

    private void authorizationEndpoint(ServerRequest request, ServerResponse response) {
        TestOidcRequest oidcRequest = TestOidcRequest.create(request, false);
        authorizationRequests.add(oidcRequest);
        Optional<TestOidcEndpointHandler<TestOidcEndpointContext>> handler = config.endpoints().authorization();
        if (handler.isPresent()) {
            handler.orElseThrow().handle(new EndpointContext(oidcRequest, response, this::defaultAuthorization));
            return;
        }
        defaultAuthorization(oidcRequest, response);
    }

    private void loginEndpoint(ServerRequest request, ServerResponse response) {
        TestOidcRequest oidcRequest = TestOidcRequest.create(request, true);
        authorizationRequests.add(oidcRequest);
        defaultLogin(oidcRequest, response);
    }

    private void tokenEndpoint(ServerRequest request, ServerResponse response) {
        TestOidcRequest oidcRequest = TestOidcRequest.create(request, true);
        tokenRequests.add(oidcRequest);
        Optional<TestOidcEndpointHandler<TestOidcTokenEndpointContext>> handler = config.endpoints().token();
        if (handler.isPresent()) {
            handler.orElseThrow().handle(new TokenEndpointContext(oidcRequest, response));
            return;
        }
        defaultToken(oidcRequest, response);
    }

    private void jwksEndpoint(ServerRequest request, ServerResponse response) {
        TestOidcRequest oidcRequest = TestOidcRequest.create(request, false);
        jwksRequests.add(oidcRequest);
        Optional<TestOidcEndpointHandler<TestOidcEndpointContext>> handler = config.endpoints().jwks();
        if (handler.isPresent()) {
            handler.orElseThrow().handle(new EndpointContext(oidcRequest, response, this::defaultJwks));
            return;
        }
        defaultJwks(oidcRequest, response);
    }

    private void userInfoEndpoint(ServerRequest request, ServerResponse response) {
        TestOidcRequest oidcRequest = TestOidcRequest.create(request, false);
        userInfoRequests.add(oidcRequest);
        Optional<TestOidcEndpointHandler<TestOidcEndpointContext>> handler = config.endpoints().userinfo();
        if (handler.isPresent()) {
            handler.orElseThrow().handle(new EndpointContext(oidcRequest, response, this::defaultUserInfo));
            return;
        }
        defaultUserInfo(oidcRequest, response);
    }

    private void logoutEndpoint(ServerRequest request, ServerResponse response) {
        TestOidcRequest oidcRequest = TestOidcRequest.create(request, false);
        logoutRequests.add(oidcRequest);
        Optional<TestOidcEndpointHandler<TestOidcEndpointContext>> handler = config.endpoints().logout();
        if (handler.isPresent()) {
            handler.orElseThrow().handle(new EndpointContext(oidcRequest, response, this::defaultLogout));
            return;
        }
        defaultLogout(oidcRequest, response);
    }

    private void defaultMetadata(TestOidcRequest request, ServerResponse response) {
        sendJson(response, metadata());
    }

    private void defaultAuthorization(TestOidcRequest request, ServerResponse response) {
        if (config.browserLogin()) {
            response.header(HeaderNames.CONTENT_TYPE, "text/html; charset=UTF-8")
                    .send(loginForm(request.queryParameters()));
            return;
        }
        authorize(request.queryParameters(), authorizationUser().username(), response);
    }

    private void defaultLogin(TestOidcRequest request, ServerResponse response) {
        String username = required(request.formParameters(), "username");
        TestOidcUserConfig user = user(username);
        Optional<String> expectedPassword = user.password();
        if (expectedPassword.isPresent()
                && !expectedPassword.orElseThrow().equals(required(request.formParameters(), "password"))) {
            throw new IllegalArgumentException("Invalid test user password");
        }
        authorize(request.formParameters(), username, response);
    }

    private void authorize(Map<String, List<String>> parameters, String username, ServerResponse response) {
        String clientId = required(parameters, "client_id");
        TestOidcClientConfig client = client(clientId);
        URI redirectUri = URI.create(required(parameters, "redirect_uri"));
        if (!client.redirectUris().isEmpty() && !client.redirectUris().contains(redirectUri)) {
            throw new IllegalArgumentException("redirect_uri is not allowed");
        }
        List<String> scopes = scopes(first(parameters, "scope"));
        String code = "code-" + ids.incrementAndGet();
        authorizationCodes.put(code,
                               new AuthorizationCode(clientId,
                                                     username,
                                                     redirectUri,
                                                     scopes,
                                                     first(parameters, "nonce").orElse(null),
                                                     first(parameters, "code_challenge").orElse(null),
                                                     first(parameters, "code_challenge_method").orElse("plain")));
        Map<String, String> redirectParams = new LinkedHashMap<>();
        redirectParams.put("code", code);
        first(parameters, "state").ifPresent(state -> redirectParams.put("state", state));
        response.status(Status.SEE_OTHER_303)
                .header(HeaderNames.LOCATION, appendQuery(redirectUri, redirectParams))
                .send();
    }

    private void defaultToken(TestOidcRequest request, ServerResponse response) {
        try {
            TestOidcTokenResponse tokenResponse = issueTokens(request);
            sendTokenResponse(response, tokenResponse);
        } catch (RuntimeException e) {
            JsonObject body = JsonObject.builder()
                    .set("error", "invalid_request")
                    .set("error_description", e.getMessage())
                    .build();
            response.status(Status.BAD_REQUEST_400)
                    .header(HeaderValues.CONTENT_TYPE_JSON)
                    .send(body.toString());
        }
    }

    private TestOidcTokenResponse issueTokens(TestOidcRequest request) {
        String grantType = required(request.formParameters(), "grant_type");
        return switch (grantType) {
        case "authorization_code" -> authorizationCodeTokens(request);
        case "client_credentials" -> clientCredentialsTokens(request);
        case "refresh_token" -> refreshTokenTokens(request);
        default -> throw new IllegalArgumentException("Unsupported grant_type: " + grantType);
        };
    }

    private void sendTokenResponse(ServerResponse response, TestOidcTokenResponse tokenResponse) {
        response.status(Status.OK_200)
                .header(HeaderValues.CONTENT_TYPE_JSON)
                .header(HeaderNames.CACHE_CONTROL, "no-store")
                .header(HeaderNames.PRAGMA, "no-cache")
                .send(tokenResponse.asJson().toString());
    }

    private TestOidcTokenResponse authorizationCodeTokens(TestOidcRequest request) {
        TestOidcClientConfig client = authenticateClient(request);
        String codeValue = required(request.formParameters(), "code");
        AuthorizationCode code = Optional.ofNullable(authorizationCodes.remove(codeValue))
                .orElseThrow(() -> new IllegalArgumentException("Authorization code is invalid"));
        if (!client.clientId().equals(code.clientId())) {
            throw new IllegalArgumentException("Authorization code client mismatch");
        }
        request.formParam("redirect_uri")
                .map(URI::create)
                .filter(code.redirectUri()::equals)
                .orElseThrow(() -> new IllegalArgumentException("redirect_uri mismatch"));
        validatePkce(code, request.formParam("code_verifier"));

        TestOidcUserConfig user = user(code.username());
        String subject = subject(code.username(), user);
        return tokenResponse(client.clientId(), subject, code.username(), code.scopes(), code.nonce(), true);
    }

    private TestOidcTokenResponse clientCredentialsTokens(TestOidcRequest request) {
        TestOidcClientConfig client = authenticateClient(request);
        List<String> scopes = scopes(request.formParam("scope"));
        return tokenResponse(client.clientId(), client.clientId(), null, scopes, null, false);
    }

    private TestOidcTokenResponse refreshTokenTokens(TestOidcRequest request) {
        TestOidcClientConfig client = authenticateClient(request);
        String refreshToken = required(request.formParameters(), "refresh_token");
        RefreshState state = Optional.ofNullable(refreshTokens.get(refreshToken))
                .orElseThrow(() -> new IllegalArgumentException("Refresh token is invalid"));
        if (!client.clientId().equals(state.clientId())) {
            throw new IllegalArgumentException("Refresh token client mismatch");
        }
        if (config.tokenDefaults().refreshToken().rotate()) {
            refreshTokens.remove(refreshToken);
        }
        return tokenResponse(state.clientId(), state.subject(), state.username(), state.scopes(), null, false);
    }

    private TestOidcTokenResponse tokenResponse(String clientId,
                                                String subject,
                                                String username,
                                                List<String> scopes,
                                                String nonce,
                                                boolean idTokenAllowed) {
        String scope = String.join(" ", scopes);
        String accessToken = accessToken(clientId, subject, scope);
        String idToken = idTokenAllowed && scopes.contains("openid")
                ? idToken(clientId, subject, username, nonce)
                : null;
        String refreshToken = null;
        if (config.tokenDefaults().refreshToken().enabled() && username != null) {
            refreshToken = "refresh-" + ids.incrementAndGet();
            refreshTokens.put(refreshToken, new RefreshState(clientId, subject, username, scopes));
        }
        accessTokens.put(accessToken, new IssuedAccessToken(clientId, subject, username, scopes));
        return new TestOidcTokenResponse(accessToken,
                                         "Bearer",
                                         config.tokenDefaults().accessToken().expiresIn().toSeconds(),
                                         scope,
                                         idToken,
                                         refreshToken);
    }

    private String accessToken(String clientId, String subject, String scope) {
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        TestOidcTokenConfig token = config.tokenDefaults().accessToken();
        Jwt.Builder builder = Jwt.builder()
                .type("at+jwt")
                .algorithm(SIGNING_ALGORITHM)
                .keyId(VERIFY_KEY_ID)
                .issuer(issuer.toString())
                .subject(subject)
                .issueTime(now)
                .expirationTime(now.plus(token.expiresIn()))
                .jwtId(UUID.randomUUID().toString())
                .addPayloadClaim("client_id", clientId)
                .addPayloadClaim("scope", scope);
        audiences(token, clientId).forEach(builder::addAudience);
        token.claims().forEach(builder::addPayloadClaim);
        return SignedJwt.sign(builder.build(), signingKeys.forKeyId(SIGNING_KEY_ID).orElseThrow())
                .tokenContent();
    }

    private String idToken(String clientId, String subject, String username, String nonce) {
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        TestOidcTokenConfig token = config.tokenDefaults().idToken();
        Jwt.Builder builder = Jwt.builder()
                .type("JWT")
                .algorithm(SIGNING_ALGORITHM)
                .keyId(VERIFY_KEY_ID)
                .issuer(issuer.toString())
                .subject(subject)
                .issueTime(now)
                .expirationTime(now.plus(token.expiresIn()))
                .addAudience(clientId);
        if (nonce != null) {
            builder.nonce(nonce);
        }
        if (username != null) {
            TestOidcUserConfig user = user(username);
            for (String claim : token.includeUserClaims()) {
                JsonValue value = user.claims().get(claim);
                if (value != null) {
                    builder.addPayloadClaim(claim, value);
                }
            }
        }
        token.claims().forEach(builder::addPayloadClaim);
        return SignedJwt.sign(builder.build(), signingKeys.forKeyId(SIGNING_KEY_ID).orElseThrow())
                .tokenContent();
    }

    private void defaultJwks(TestOidcRequest request, ServerResponse response) {
        response.header(HeaderValues.CONTENT_TYPE_JSON)
                .send(jwks);
    }

    private void defaultUserInfo(TestOidcRequest request, ServerResponse response) {
        String token = request.bearerToken()
                .orElseThrow(() -> new IllegalArgumentException("Bearer token is required"));
        IssuedAccessToken issuedToken = Optional.ofNullable(accessTokens.get(token))
                .orElseThrow(() -> new IllegalArgumentException("Access token is unknown"));
        if (issuedToken.username() == null) {
            response.status(Status.UNAUTHORIZED_401).send();
            return;
        }
        TestOidcUserConfig user = user(issuedToken.username());
        JsonObject.Builder builder = JsonObject.builder()
                .set("sub", subject(issuedToken.username(), user));
        user.claims().forEach((name, value) -> TestOidcJsonSupport.set(builder, name, value));
        sendJson(response, builder.build());
    }

    private void defaultLogout(TestOidcRequest request, ServerResponse response) {
        URI redirectUri = request.queryParam("post_logout_redirect_uri")
                .map(URI::create)
                .orElse(issuer);
        response.status(Status.SEE_OTHER_303)
                .header(HeaderNames.LOCATION, redirectUri.toString())
                .send();
    }

    private TestOidcClientConfig authenticateClient(TestOidcRequest request) {
        Optional<TestOidcRequest.BasicCredentials> basicCredentials = request.basicCredentials();
        if (basicCredentials.isPresent()) {
            TestOidcRequest.BasicCredentials credentials = basicCredentials.orElseThrow();
            return authenticatedClient(credentials.username(), credentials.password());
        }

        String clientId = required(request.formParameters(), "client_id");
        TestOidcClientConfig client = client(clientId);
        Optional<String> expectedSecret = client.clientSecret();
        if (expectedSecret.isPresent()) {
            String secret = required(request.formParameters(), "client_secret");
            if (!expectedSecret.orElseThrow().equals(secret)) {
                throw new IllegalArgumentException("client_secret is invalid");
            }
        }
        return client;
    }

    private TestOidcClientConfig authenticatedClient(String clientId, String secret) {
        TestOidcClientConfig client = client(clientId);
        if (!client.clientSecret().orElse("").equals(secret)) {
            throw new IllegalArgumentException("Client authentication failed");
        }
        return client;
    }

    private void validatePkce(AuthorizationCode code, Optional<String> verifier) {
        if (code.codeChallenge() == null) {
            return;
        }
        String actual = verifier.orElseThrow(() -> new IllegalArgumentException("code_verifier is required"));
        String expected = "S256".equals(code.codeChallengeMethod())
                ? sha256Base64Url(actual)
                : actual;
        if (!code.codeChallenge().equals(expected)) {
            throw new IllegalArgumentException("code_verifier does not match");
        }
    }

    private String sha256Base64Url(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private TestOidcClientConfig client(String clientId) {
        return Optional.ofNullable(config.clients().get(clientId))
                .orElseThrow(() -> new IllegalArgumentException("Unknown client: " + clientId));
    }

    private TestOidcUserConfig user(String username) {
        return Optional.ofNullable(config.users().get(username))
                .orElseThrow(() -> new IllegalArgumentException("Unknown user: " + username));
    }

    private AuthorizationUser authorizationUser() {
        if (config.defaultAuthorizationUser().isPresent()) {
            String username = config.defaultAuthorizationUser().orElseThrow();
            return new AuthorizationUser(username, user(username));
        }
        if (config.users().size() == 1) {
            Map.Entry<String, TestOidcUserConfig> user = config.users().entrySet().iterator().next();
            return new AuthorizationUser(user.getKey(), user.getValue());
        }
        throw new IllegalArgumentException("Default authorization user is ambiguous");
    }

    private String subject(String username, TestOidcUserConfig user) {
        return user.subject().orElse(username);
    }

    private List<String> scopes(Optional<String> requestedScope) {
        Set<String> allowed = new LinkedHashSet<>(config.defaultScopes());
        allowed.addAll(config.allowedScopes());
        List<String> requested = requestedScope
                .filter(scope -> !scope.isBlank())
                .map(scope -> List.of(scope.split(" ")))
                .orElseGet(config::defaultScopes);
        for (String scope : requested) {
            if (!allowed.contains(scope)) {
                throw new IllegalArgumentException("Scope is not allowed: " + scope);
            }
        }
        return List.copyOf(requested);
    }

    private List<String> audiences(TestOidcTokenConfig token, String clientId) {
        return token.audience().isEmpty() ? List.of(clientId) : token.audience();
    }

    private String loginForm(Map<String, List<String>> parameters) {
        StringBuilder form = new StringBuilder();
        form.append("<!doctype html><html><body><form method=\"post\" action=\"/authorize/login\">");
        parameters.forEach((name, values) -> values.forEach(value -> form.append("<input type=\"hidden\" name=\"")
                .append(escapeHtml(name))
                .append("\" value=\"")
                .append(escapeHtml(value))
                .append("\">")));
        form.append("<input name=\"username\">")
                .append("<input name=\"password\" type=\"password\">")
                .append("<button type=\"submit\">Login</button>")
                .append("</form></body></html>");
        return form.toString();
    }

    private static void sendJson(ServerResponse response, JsonObject json) {
        response.header(HeaderValues.CONTENT_TYPE_JSON)
                .send(json.toString());
    }

    private static String appendQuery(URI uri, Map<String, String> parameters) {
        StringBuilder result = new StringBuilder(uri.toString());
        result.append(uri.getQuery() == null ? '?' : '&');
        boolean first = true;
        for (Map.Entry<String, String> entry : parameters.entrySet()) {
            if (!first) {
                result.append('&');
            }
            first = false;
            result.append(urlEncode(entry.getKey()))
                    .append('=')
                    .append(urlEncode(entry.getValue()));
        }
        return result.toString();
    }

    private static String required(Map<String, List<String>> parameters, String name) {
        return first(parameters, name)
                .filter(value -> !value.isBlank())
                .orElseThrow(() -> new IllegalArgumentException(name + " is required"));
    }

    private static Optional<String> first(Map<String, List<String>> parameters, String name) {
        return Optional.ofNullable(parameters.get(name))
                .filter(values -> !values.isEmpty())
                .map(List::getFirst);
    }

    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static String escapeHtml(String value) {
        return value.replace("&", "&amp;")
                .replace("\"", "&quot;")
                .replace("<", "&lt;")
                .replace(">", "&gt;");
    }

    /**
     * Builder for {@link TestOidcServer}.
     */
    public static final class Builder implements io.helidon.common.Builder<Builder, TestOidcServer> {
        private final TestOidcServerConfig.Builder delegate = TestOidcServerConfig.builder();

        private Builder() {
        }

        /**
         * Configure issuer.
         *
         * @param issuer issuer
         * @return this builder
         */
        public Builder issuer(URI issuer) {
            delegate.issuer(issuer);
            return this;
        }

        /**
         * Configure a confidential client.
         *
         * @param clientId client id
         * @param clientSecret client secret
         * @return this builder
         */
        public Builder client(String clientId, String clientSecret) {
            return client(clientId, client -> client.clientSecret(clientSecret));
        }

        /**
         * Configure a client.
         *
         * @param clientId client id
         * @param customizer client customizer
         * @return this builder
         */
        public Builder client(String clientId, Consumer<ClientBuilder> customizer) {
            ClientBuilder builder = new ClientBuilder(clientId);
            customizer.accept(builder);
            delegate.putClient(clientId, builder.build());
            return this;
        }

        /**
         * Configure a user.
         *
         * @param username username
         * @param customizer user customizer
         * @return this builder
         */
        public Builder user(String username, Consumer<UserBuilder> customizer) {
            UserBuilder builder = new UserBuilder();
            customizer.accept(builder);
            delegate.putUser(username, builder.build());
            return this;
        }

        /**
         * Configure the default authorization user.
         *
         * @param username username
         * @return this builder
         */
        public Builder defaultAuthorizationUser(String username) {
            delegate.defaultAuthorizationUser(username);
            return this;
        }

        /**
         * Configure default scopes.
         *
         * @param scopes scopes
         * @return this builder
         */
        public Builder defaultScopes(String... scopes) {
            delegate.defaultScopes(List.of(scopes));
            return this;
        }

        /**
         * Add allowed scopes that are not issued by default.
         *
         * @param scopes scopes
         * @return this builder
         */
        public Builder allowedScopes(String... scopes) {
            delegate.allowedScopes(List.of(scopes));
            return this;
        }

        /**
         * Enable or disable browser login mode.
         *
         * @param enabled whether browser login is enabled
         * @return this builder
         */
        public Builder browserLogin(boolean enabled) {
            delegate.browserLogin(enabled);
            return this;
        }

        /**
         * Configure token defaults.
         *
         * @param customizer customizer
         * @return this builder
         */
        public Builder tokenDefaults(Consumer<TokenDefaultsBuilder> customizer) {
            TokenDefaultsBuilder builder = new TokenDefaultsBuilder();
            customizer.accept(builder);
            delegate.tokenDefaults(builder.build());
            return this;
        }

        /**
         * Configure endpoint overrides.
         *
         * @param customizer customizer
         * @return this builder
         */
        public Builder endpoints(Consumer<TestOidcEndpointsConfig.Builder> customizer) {
            delegate.endpoints(customizer);
            return this;
        }

        /**
         * Add provider metadata claim.
         *
         * @param name claim name
         * @param value claim value
         * @return this builder
         */
        public Builder metadata(String name, Object value) {
            TestOidcProviderMetadataConfig.Builder metadata = TestOidcProviderMetadataConfig.builder();
            metadata.putClaim(name, TestOidcJsonSupport.jsonValue(value));
            delegate.metadata(metadata.buildPrototype());
            return this;
        }

        @Override
        public TestOidcServer build() {
            return TestOidcServer.create(delegate.buildPrototype());
        }
    }

    /**
     * Client builder.
     */
    public static final class ClientBuilder {
        private final TestOidcClientConfig.Builder delegate;

        private ClientBuilder(String clientId) {
            this.delegate = TestOidcClientConfig.builder()
                    .clientId(clientId);
        }

        /**
         * Configure client secret.
         *
         * @param secret secret
         * @return this builder
         */
        public ClientBuilder clientSecret(String secret) {
            delegate.clientSecret(secret);
            return this;
        }

        /**
         * Add allowed redirect URI.
         *
         * @param uri redirect URI
         * @return this builder
         */
        public ClientBuilder redirectUri(URI uri) {
            delegate.addRedirectUri(uri);
            return this;
        }

        private TestOidcClientConfig build() {
            return delegate.buildPrototype();
        }
    }

    /**
     * User builder.
     */
    public static final class UserBuilder {
        private final TestOidcUserConfig.Builder delegate = TestOidcUserConfig.builder();

        private UserBuilder() {
        }

        /**
         * Configure subject.
         *
         * @param subject subject
         * @return this builder
         */
        public UserBuilder subject(String subject) {
            delegate.subject(subject);
            return this;
        }

        /**
         * Configure password.
         *
         * @param password password
         * @return this builder
         */
        public UserBuilder password(String password) {
            delegate.password(password);
            return this;
        }

        /**
         * Add user claim.
         *
         * @param name claim name
         * @param value claim value
         * @return this builder
         */
        public UserBuilder claim(String name, Object value) {
            delegate.putClaim(name, TestOidcJsonSupport.jsonValue(value));
            return this;
        }

        private TestOidcUserConfig build() {
            return delegate.buildPrototype();
        }
    }

    /**
     * Token defaults builder.
     */
    public static final class TokenDefaultsBuilder {
        private final TestOidcTokenDefaults.Builder delegate = TestOidcTokenDefaults.builder();

        private TokenDefaultsBuilder() {
        }

        /**
         * Configure access token defaults.
         *
         * @param customizer customizer
         * @return this builder
         */
        public TokenDefaultsBuilder accessToken(Consumer<TokenBuilder> customizer) {
            TokenBuilder builder = new TokenBuilder();
            customizer.accept(builder);
            delegate.accessToken(builder.build());
            return this;
        }

        /**
         * Configure ID token defaults.
         *
         * @param customizer customizer
         * @return this builder
         */
        public TokenDefaultsBuilder idToken(Consumer<TokenBuilder> customizer) {
            TokenBuilder builder = new TokenBuilder();
            customizer.accept(builder);
            delegate.idToken(builder.build());
            return this;
        }

        /**
         * Configure refresh token defaults.
         *
         * @param customizer customizer
         * @return this builder
         */
        public TokenDefaultsBuilder refreshToken(Consumer<RefreshTokenBuilder> customizer) {
            RefreshTokenBuilder builder = new RefreshTokenBuilder();
            customizer.accept(builder);
            delegate.refreshToken(builder.build());
            return this;
        }

        private TestOidcTokenDefaults build() {
            return delegate.buildPrototype();
        }
    }

    /**
     * Token builder.
     */
    public static final class TokenBuilder {
        private final TestOidcTokenConfig.Builder delegate = TestOidcTokenConfig.builder();

        private TokenBuilder() {
        }

        /**
         * Configure token lifetime.
         *
         * @param duration lifetime
         * @return this builder
         */
        public TokenBuilder expiresIn(Duration duration) {
            delegate.expiresIn(duration);
            return this;
        }

        /**
         * Add claim.
         *
         * @param name claim name
         * @param value claim value
         * @return this builder
         */
        public TokenBuilder claim(String name, Object value) {
            delegate.putClaim(name, TestOidcJsonSupport.jsonValue(value));
            return this;
        }

        /**
         * Include selected user claims.
         *
         * @param claims claims
         * @return this builder
         */
        public TokenBuilder includeUserClaims(String... claims) {
            delegate.includeUserClaims(List.of(claims));
            return this;
        }

        /**
         * Configure audience.
         *
         * @param audience audience values
         * @return this builder
         */
        public TokenBuilder audience(String... audience) {
            delegate.audience(List.of(audience));
            return this;
        }

        private TestOidcTokenConfig build() {
            return delegate.buildPrototype();
        }
    }

    /**
     * Refresh token builder.
     */
    public static final class RefreshTokenBuilder {
        private final TestOidcRefreshTokenConfig.Builder delegate = TestOidcRefreshTokenConfig.builder();

        private RefreshTokenBuilder() {
        }

        /**
         * Enable refresh tokens.
         *
         * @param enabled whether enabled
         * @return this builder
         */
        public RefreshTokenBuilder enabled(boolean enabled) {
            delegate.enabled(enabled);
            return this;
        }

        /**
         * Enable refresh token rotation.
         *
         * @param rotate whether rotation is enabled
         * @return this builder
         */
        public RefreshTokenBuilder rotate(boolean rotate) {
            delegate.rotate(rotate);
            return this;
        }

        private TestOidcRefreshTokenConfig build() {
            return delegate.buildPrototype();
        }
    }

    private interface DefaultSender {
        void send(TestOidcRequest request, ServerResponse response);
    }

    private class EndpointContext implements TestOidcEndpointContext {
        private final TestOidcRequest request;
        private final ServerResponse response;
        private final DefaultSender defaultSender;

        private EndpointContext(TestOidcRequest request, ServerResponse response, DefaultSender defaultSender) {
            this.request = request;
            this.response = response;
            this.defaultSender = defaultSender;
        }

        @Override
        public TestOidcRequest request() {
            return request;
        }

        @Override
        public ServerResponse response() {
            return response;
        }

        @Override
        public TestOidcServer idp() {
            return TestOidcServer.this;
        }

        @Override
        public void sendDefault() {
            defaultSender.send(request, response);
        }
    }

    private final class TokenEndpointContext extends EndpointContext implements TestOidcTokenEndpointContext {
        private TokenEndpointContext(TestOidcRequest request, ServerResponse response) {
            super(request, response, TestOidcServer.this::defaultToken);
        }

        @Override
        public TestOidcTokenResponse issueTokens() {
            return TestOidcServer.this.issueTokens(request());
        }

        @Override
        public void send(TestOidcTokenResponse tokenResponse) {
            TestOidcServer.this.sendTokenResponse(response(), tokenResponse);
        }
    }

    private record AuthorizationCode(String clientId,
                                     String username,
                                     URI redirectUri,
                                     List<String> scopes,
                                     String nonce,
                                     String codeChallenge,
                                     String codeChallengeMethod) {
    }

    private record RefreshState(String clientId, String subject, String username, List<String> scopes) {
    }

    private record IssuedAccessToken(String clientId, String subject, String username, List<String> scopes) {
    }

    private record AuthorizationUser(String username, TestOidcUserConfig user) {
    }
}
