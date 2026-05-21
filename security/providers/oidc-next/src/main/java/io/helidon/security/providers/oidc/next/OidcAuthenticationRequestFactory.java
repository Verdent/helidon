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
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;

import io.helidon.common.uri.UriQueryWriteable;
import io.helidon.http.SetCookie;
import io.helidon.security.SecurityEnvironment;

final class OidcAuthenticationRequestFactory {
    private static final int RANDOM_VALUE_BYTES = 32;

    private final SecureRandom secureRandom;

    private OidcAuthenticationRequestFactory(SecureRandom secureRandom) {
        this.secureRandom = secureRandom;
    }

    static OidcAuthenticationRequestFactory create() {
        return new OidcAuthenticationRequestFactory(new SecureRandom());
    }

    OidcAuthenticationRequest create(OidcRequestContext context) {
        OidcTenantContext tenantContext = context.tenantContext().orElseThrow();
        OidcTenantConfig tenantConfig = tenantContext.tenantConfig();
        OidcAuthorizationCodeConfig authorizationCode = tenantConfig.authorizationCode();
        URI authorizationEndpointUri = tenantContext.endpointClient()
                .authorizationEndpointUri()
                .orElseThrow(() -> new IllegalStateException("authorization-endpoint-uri is not configured"));
        URI redirectionEndpointUri = authorizationCode.redirectionEndpointUri()
                .orElseThrow(() -> new IllegalStateException("redirection-endpoint-uri is not configured"));

        String state = randomValue();
        String nonce = randomValue();
        String pkceVerifier = authorizationCode.pkceRequired() ? randomValue() : null;
        SecurityEnvironment environment = context.environment();
        Instant createdAt = environment.time().toInstant();

        OidcAuthenticationRequestState requestState = OidcAuthenticationRequestState.create(
                tenantContext.tenantId(),
                state,
                nonce,
                pkceVerifier,
                originalUri(environment),
                redirectionEndpointUri,
                createdAt,
                createdAt.plus(tenantContext.cookieStateHandler().cookieConfig().authenticationRequestLifetime()));
        SetCookie stateCookie = tenantContext.cookieStateHandler()
                .createAuthenticationRequestCookie(requestState);
        URI authorizationUri = authorizationUri(authorizationEndpointUri,
                                                tenantConfig.clientId().orElseThrow(),
                                                redirectionEndpointUri,
                                                authorizationCode,
                                                state,
                                                nonce,
                                                pkceVerifier);

        return OidcAuthenticationRequest.create(authorizationUri, stateCookie.toString());
    }

    static String codeChallenge(String verifier, OidcPkceMethod method) {
        return switch (method) {
        case S256 -> base64Url(sha256(verifier));
        };
    }

    private URI authorizationUri(URI authorizationEndpointUri,
                                 String clientId,
                                 URI redirectionEndpointUri,
                                 OidcAuthorizationCodeConfig authorizationCode,
                                 String state,
                                 String nonce,
                                 String pkceVerifier) {
        /*
         * Spec: OpenID Connect Core 1.0, 3.1.2.1 Authentication Request
         * https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
         * Quotes: "MUST contain the `openid` scope value"; "this value is `code`";
         * "Opaque value used to maintain state"; "Sufficient entropy MUST be present".
         */
        UriQueryWriteable query = UriQueryWriteable.create()
                .set("response_type", "code")
                .set("client_id", clientId)
                .set("redirect_uri", redirectionEndpointUri.toString())
                .set("scope", String.join(" ", authorizationCode.scopes()))
                .set("state", state)
                .set("nonce", nonce);
        if (pkceVerifier != null) {
            /*
             * Spec: RFC 7636, 4.1 Client Creates a Code Verifier and 4.2 Client Creates the Code Challenge
             * https://www.rfc-editor.org/rfc/rfc7636.html#section-4.1
             * https://www.rfc-editor.org/rfc/rfc7636.html#section-4.2
             * Quotes: "high-entropy cryptographic random STRING"; "32-octet sequence";
             * "code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))"; "MUST use \"S256\"".
             */
            query.set("code_challenge", codeChallenge(pkceVerifier, authorizationCode.pkceMethod()))
                    .set("code_challenge_method", authorizationCode.pkceMethod().name());
        }

        return URI.create(authorizationEndpointUri
                                  + (authorizationEndpointUri.getRawQuery() == null ? "?" : "&")
                                  + query.rawValue());
    }

    private URI originalUri(SecurityEnvironment environment) {
        URI targetUri = environment.targetUri();
        if (targetUri != null) {
            return targetUri;
        }
        return URI.create(environment.path().orElse("/"));
    }

    private String randomValue() {
        byte[] bytes = new byte[RANDOM_VALUE_BYTES];
        secureRandom.nextBytes(bytes);
        return base64Url(bytes);
    }

    private static byte[] sha256(String value) {
        try {
            return MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.US_ASCII));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    private static String base64Url(byte[] bytes) {
        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(bytes);
    }
}
