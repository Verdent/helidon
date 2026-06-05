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
import java.util.List;
import java.util.Locale;

import io.helidon.common.uri.UriQueryWriteable;
import io.helidon.http.HeaderNames;
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
        OidcAuthorizationCodeConfig authorizationCode = tenantConfig.authorizationCode().orElseThrow();
        URI authorizationEndpointUri = tenantContext.metadata()
                .authorizationEndpointUri()
                .orElseThrow(() -> new IllegalStateException("authorization-endpoint-uri is not configured"));
        String expectedIssuer = tenantContext.metadata()
                .issuer()
                .orElseThrow(() -> new IllegalStateException("issuer is not configured"));
        URI redirectionEndpointUri = resolveRedirectionEndpointUri(
                OidcConfigSupport.redirectionEndpointUri(authorizationCode),
                context.environment());
        if (tenantConfig.endpoints().tlsRequired() && !"https".equalsIgnoreCase(redirectionEndpointUri.getScheme())) {
            throw new IllegalStateException(
                    "redirection-endpoint-uri must use https unless endpoints.tls-required is disabled: "
                            + redirectionEndpointUri);
        }

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
                expectedIssuer,
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
        case PLAIN -> verifier;
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
             * "code_challenge = code_verifier";
             * "code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))";
             * "If the client is capable of using \"S256\", it MUST use \"S256\"".
             */
            query.set("code_challenge", codeChallenge(pkceVerifier, authorizationCode.pkceMethod()))
                    .set("code_challenge_method", authorizationCode.pkceMethod().wireName());
        }

        return URI.create(authorizationEndpointUri
                                  + (authorizationEndpointUri.getRawQuery() == null ? "?" : "&")
                                  + query.rawValue());
    }

    private URI originalUri(SecurityEnvironment environment) {
        URI targetUri = environment.targetUri();
        if (targetUri != null) {
            return OidcUri.localReference(targetUri);
        }
        return OidcUri.localReference(environment.path().orElse("/"), null);
    }

    private URI resolveRedirectionEndpointUri(URI configuredUri, SecurityEnvironment environment) {
        if (configuredUri.isAbsolute()) {
            return configuredUri;
        }
        return requestOrigin(environment).resolve(configuredUri);
    }

    private URI requestOrigin(SecurityEnvironment environment) {
        URI targetUri = environment.targetUri();
        if (targetUri != null && targetUri.getScheme() != null && targetUri.getRawAuthority() != null) {
            return URI.create(targetUri.getScheme() + "://" + targetUri.getRawAuthority());
        }

        List<String> host = environment.headers().get(HeaderNames.HOST.defaultCase());
        if (host != null && !host.isEmpty()) {
            return URI.create(environment.transport().toLowerCase(Locale.ROOT) + "://" + host.getFirst());
        }

        throw new IllegalStateException(
                "Host header or target URI is required when redirection-endpoint-uri is configured as a local path");
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
