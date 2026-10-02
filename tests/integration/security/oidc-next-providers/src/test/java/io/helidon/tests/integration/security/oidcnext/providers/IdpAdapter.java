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
import java.util.Set;

import io.helidon.security.providers.oidc.next.OidcJwtAccessTokenConfig;
import io.helidon.webclient.api.WebClientConfig;

interface IdpAdapter extends AutoCloseable {
    /**
     * Audience accepted by the protected resource.
     */
    String AUDIENCE = "it-api";
    /**
     * Shared secret for confidential fixture clients.
     */
    String SECRET = "integration-test-client-secret-with-at-least-32-bytes";
    /**
     * Registered redirect intercepted by the token broker without opening a listener.
     */
    String COLLECTOR = "https://localhost/collect";

    void start() throws Exception;

    URI issuer();

    WebClientConfig webClient();

    Set<Capability> capabilities();

    String unavailableReason(Capability capability);

    String diagnostics();

    void registerCallback(ClientMode mode, URI callback) throws Exception;

    URI login(TestBrowser browser, URI authorization, URI callback) throws Exception;

    OidcJwtAccessTokenConfig jwtLayout();

    AutoCloseable rotateSigningKey() throws Exception;

    @Override
    void close();

    enum Capability {
        /**
         * Authorization code with a public client and S256 PKCE.
         */
        PUBLIC_CLIENT,
        /**
         * Client authentication using form parameters.
         */
        CLIENT_SECRET_POST,
        /**
         * Client authentication using an asymmetric JWT assertion.
         */
        PRIVATE_KEY_JWT,
        /**
         * Client authentication using an HMAC JWT assertion.
         */
        CLIENT_SECRET_JWT,
        /**
         * Pushed Authorization Requests.
         */
        PAR,
        /**
         * Signed authorization Request Objects.
         */
        JAR,
        /**
         * RFC 9126 pushed authorization using a signed Request Object.
         */
        PAR_WITH_JAR,
        /**
         * Standards compliant signed UserInfo responses.
         */
        SIGNED_USERINFO,
        /**
         * Encrypted ID Tokens.
         */
        ENCRYPTED_ID_TOKEN,
        /**
         * Locally verifiable JWT access tokens.
         */
        JWT_ACCESS_TOKEN,
        /**
         * JWT access tokens issued through client credentials.
         */
        JWT_CLIENT_CREDENTIALS,
        /**
         * Native access token revocation.
         */
        ACCESS_TOKEN_REVOCATION,
        /**
         * Native refresh token revocation with an invalid_grant response to subsequent refresh attempts.
         */
        REFRESH_TOKEN_REVOCATION,
        /**
         * Replacing the active issuer key while retaining the previous verification key.
         */
        SIGNING_KEY_ROTATION,
        /**
         * RP-initiated provider logout.
         */
        RP_LOGOUT,
        /**
         * OAuth token exchange.
         */
        TOKEN_EXCHANGE
    }

    enum ClientMode {
        /**
         * Confidential browser client using Basic authentication.
         */
        BASIC("it-basic"),
        /**
         * Public browser client with no client secret.
         */
        PUBLIC("it-public"),
        /**
         * Browser client using client secret POST authentication.
         */
        POST("it-post"),
        /**
         * Browser client using private key JWT authentication.
         */
        PRIVATE_JWT("it-private-jwt"),
        /**
         * Browser client using client secret JWT authentication.
         */
        SECRET_JWT("it-secret-jwt"),
        /**
         * Browser client requiring PAR.
         */
        PAR("it-par"),
        /**
         * Browser client requiring a signed Request Object.
         */
        JAR("it-jar"),
        /**
         * Browser client requiring both PAR and a signed Request Object.
         */
        PAR_JAR("it-par-jar"),
        /**
         * Browser client receiving signed UserInfo.
         */
        SIGNED_USERINFO("it-signed-userinfo"),
        /**
         * Browser client receiving encrypted ID Tokens.
         */
        ENCRYPTED_ID_TOKEN("it-encrypted-id-token"),
        /**
         * Browser client receiving JWT access tokens.
         */
        JWT_ACCESS("it-jwt-access"),
        /**
         * Service client for client credentials and token exchange.
         */
        SERVICE("it-service"),
        /**
         * Service client issuing JWT access tokens.
         */
        JWT_SERVICE("it-jwt-service"),
        /**
         * Protected resource client authorized to introspect tokens.
         */
        API("it-api");

        private final String id;

        ClientMode(String id) {
            this.id = id;
        }

        String id() {
            return id;
        }
    }
}
