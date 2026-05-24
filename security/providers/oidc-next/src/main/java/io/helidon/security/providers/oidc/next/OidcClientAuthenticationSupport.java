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
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import io.helidon.common.parameters.Parameters;
import io.helidon.http.HeaderNames;
import io.helidon.json.JsonObject;
import io.helidon.security.jwt.Jwt;
import io.helidon.security.jwt.SignedJwt;
import io.helidon.security.jwt.jwk.Jwk;
import io.helidon.security.jwt.jwk.JwkEC;
import io.helidon.security.jwt.jwk.JwkKeys;
import io.helidon.security.jwt.jwk.JwkOctet;
import io.helidon.security.jwt.jwk.JwkRSA;
import io.helidon.webclient.api.HttpClientRequest;

final class OidcClientAuthenticationSupport {
    private static final String CLIENT_ASSERTION_TYPE =
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    private static final String DEFAULT_CLIENT_SECRET_JWT_ALGORITHM = JwkOctet.ALG_HS256;
    private static final List<String> CLIENT_SECRET_JWT_ALGORITHMS =
            List.of(JwkOctet.ALG_HS256, JwkOctet.ALG_HS384, JwkOctet.ALG_HS512);
    private static final List<String> PRIVATE_KEY_JWT_ALGORITHMS =
            List.of(JwkRSA.ALG_RS256,
                    JwkRSA.ALG_RS384,
                    JwkRSA.ALG_RS512,
                    JwkEC.ALG_ES256,
                    JwkEC.ALG_ES384,
                    JwkEC.ALG_ES512);

    private final OidcTenantConfig tenantConfig;
    private final OidcClientAuthenticationMethod method;
    private final Jwk privateKeyJwk;

    private OidcClientAuthenticationSupport(OidcTenantConfig tenantConfig) {
        this.tenantConfig = tenantConfig;
        this.method = tokenEndpointAuthenticationMethod(tenantConfig);
        this.privateKeyJwk = method == OidcClientAuthenticationMethod.PRIVATE_KEY_JWT
                ? privateKeyJwk(tenantConfig.clientAssertion())
                : null;
    }

    static OidcClientAuthenticationSupport create(OidcTenantConfig tenantConfig) {
        return new OidcClientAuthenticationSupport(tenantConfig);
    }

    void applyTokenEndpointAuthentication(URI tokenEndpointUri,
                                          Parameters.Builder form,
                                          HttpClientRequest request) {
        String clientId = tenantConfig.clientId().orElseThrow();
        switch (method) {
        case CLIENT_SECRET_BASIC -> request.header(HeaderNames.AUTHORIZATION,
                                                  basicAuthorization(clientId, requireClientSecret(tenantConfig)));
        case CLIENT_SECRET_POST -> {
            /*
             * Spec: RFC 6749, 2.3.1 Client Password
             * https://www.rfc-editor.org/rfc/rfc6749.html#section-2.3.1
             * Quote: "including the client credentials in the request-body".
             */
            form.add("client_id", clientId)
                    .add("client_secret", requireClientSecret(tenantConfig));
        }
        case CLIENT_SECRET_JWT, PRIVATE_KEY_JWT -> {
            /*
             * Spec: OpenID Connect Core 1.0, 9 Client Authentication
             * https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
             * Quotes: "client_assertion_type"; "client_assertion";
             * "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".
             */
            form.add("client_assertion_type", CLIENT_ASSERTION_TYPE)
                    .add("client_assertion", clientAssertion(tokenEndpointUri));
        }
        case NONE -> {
            /*
             * Spec: RFC 6749, 3.2.1 Client Authentication
             * https://www.rfc-editor.org/rfc/rfc6749.html#section-3.2.1
             * Quote: "MUST send its `client_id`".
             */
            form.add("client_id", clientId);
        }
        default -> throw new IllegalStateException("Unexpected client authentication method: "
                                                           + method);
        }
    }

    static OidcClientAuthenticationMethod tokenEndpointAuthenticationMethod(OidcTenantConfig tenantConfig) {
        return tenantConfig.tokenEndpointAuthenticationMethod()
                .orElseGet(() -> tenantConfig.clientSecret()
                        .isPresent()
                        ? OidcClientAuthenticationMethod.CLIENT_SECRET_BASIC
                        : OidcClientAuthenticationMethod.NONE);
    }

    static boolean isClientSecretJwtAlgorithm(String algorithm) {
        return CLIENT_SECRET_JWT_ALGORITHMS.contains(algorithm);
    }

    static boolean isPrivateKeyJwtAlgorithm(String algorithm) {
        return PRIVATE_KEY_JWT_ALGORITHMS.contains(algorithm);
    }

    static String clientSecretJwtAlgorithms() {
        return CLIENT_SECRET_JWT_ALGORITHMS.toString();
    }

    static String privateKeyJwtAlgorithms() {
        return PRIVATE_KEY_JWT_ALGORITHMS.toString();
    }

    private String clientAssertion(URI tokenEndpointUri) {
        String clientId = tenantConfig.clientId().orElseThrow();
        OidcClientAssertionConfig assertion = tenantConfig.clientAssertion();
        Jwk jwk = switch (method) {
        case CLIENT_SECRET_JWT -> clientSecretJwk(tenantConfig, assertion);
        case PRIVATE_KEY_JWT -> privateKeyJwk;
        default -> throw new IllegalStateException("Unexpected client assertion authentication method: " + method);
        };
        String algorithm = method == OidcClientAuthenticationMethod.CLIENT_SECRET_JWT
                ? assertion.algorithm().orElse(DEFAULT_CLIENT_SECRET_JWT_ALGORITHM)
                : jwk.algorithm();
        Instant now = Instant.now();

        /*
         * Spec: OpenID Connect Core 1.0, 9 Client Authentication
         * https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
         * Quotes: "iss"; "sub"; "aud"; "jti"; "exp".
         */
        Jwt.Builder jwt = Jwt.builder()
                .algorithm(algorithm)
                .issuer(clientId)
                .subject(clientId)
                .addAudience(tokenEndpointUri.toString())
                .issueTime(now)
                .expirationTime(now.plus(assertion.lifetime()))
                .jwtId(UUID.randomUUID().toString());
        if (method == OidcClientAuthenticationMethod.PRIVATE_KEY_JWT) {
            Optional.ofNullable(jwk.keyId()).ifPresent(jwt::keyId);
        } else {
            assertion.keyId().ifPresent(jwt::keyId);
        }

        return SignedJwt.sign(jwt.build(), jwk).tokenContent();
    }

    static String basicAuthorization(String clientId, String clientSecret) {
        /*
         * Spec: RFC 6749, 2.3.1 Client Password
         * https://www.rfc-editor.org/rfc/rfc6749.html#section-2.3.1
         * Quote: "The authorization server MUST support the HTTP Basic authentication scheme".
         */
        String credentials = formEncode(clientId) + ":" + formEncode(clientSecret);
        return "Basic " + Base64.getEncoder()
                .encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
    }

    private static String formEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static Jwk clientSecretJwk(OidcTenantConfig tenantConfig, OidcClientAssertionConfig assertion) {
        String algorithm = assertion.algorithm().orElse(DEFAULT_CLIENT_SECRET_JWT_ALGORITHM);
        if (!isClientSecretJwtAlgorithm(algorithm)) {
            throw new IllegalArgumentException("client-assertion.algorithm must be one of "
                                                       + clientSecretJwtAlgorithms()
                                                       + " for CLIENT_SECRET_JWT Token Endpoint authentication");
        }
        JsonObject.Builder builder = JsonObject.builder()
                .set("kty", "oct")
                .set("alg", algorithm)
                .set("kid", assertion.keyId().orElse("client-secret"))
                .set("k", base64Url(requireClientSecret(tenantConfig).getBytes(StandardCharsets.UTF_8)));
        return JwkOctet.create(builder.build());
    }

    private static Jwk privateKeyJwk(OidcClientAssertionConfig assertion) {
        JwkKeys keys = JwkKeys.builder()
                .resource(assertion.jwk().orElseThrow(() -> new IllegalArgumentException(
                        "client-assertion.jwk must be configured for PRIVATE_KEY_JWT Token Endpoint authentication")))
                .build();
        Optional<String> keyId = assertion.keyId();
        if (keyId.isPresent()) {
            return validatePrivateKeyJwk(assertion,
                                         keys.forKeyId(keyId.orElseThrow())
                                                 .orElseThrow(() -> new IllegalArgumentException(
                                                         "client-assertion.key-id does not match a configured JWK")));
        }
        List<Jwk> jwks = keys.keys();
        if (jwks.size() == 1) {
            return validatePrivateKeyJwk(assertion, jwks.get(0));
        }
        throw new IllegalArgumentException(
                "client-assertion.key-id must be configured when client-assertion.jwk contains multiple keys");
    }

    private static Jwk validatePrivateKeyJwk(OidcClientAssertionConfig assertion, Jwk jwk) {
        if (!Jwk.KEY_TYPE_RSA.equals(jwk.keyType()) && !Jwk.KEY_TYPE_EC.equals(jwk.keyType())) {
            throw new IllegalArgumentException(
                    "client-assertion.jwk must select an RSA or EC private JWK for PRIVATE_KEY_JWT");
        }
        String algorithm = jwk.algorithm();
        if (!isPrivateKeyJwtAlgorithm(algorithm)) {
            throw new IllegalArgumentException("client-assertion.jwk selected key algorithm must be one of "
                                                       + privateKeyJwtAlgorithms()
                                                       + " for PRIVATE_KEY_JWT Token Endpoint authentication");
        }
        assertion.algorithm()
                .filter(configuredAlgorithm -> !configuredAlgorithm.equals(algorithm))
                .ifPresent(configuredAlgorithm -> {
                    throw new IllegalArgumentException("client-assertion.algorithm must match the selected JWK "
                                                               + "algorithm for PRIVATE_KEY_JWT Token Endpoint "
                                                               + "authentication");
                });
        return jwk;
    }

    private static String base64Url(byte[] bytes) {
        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(bytes);
    }

    private static String requireClientSecret(OidcTenantConfig tenantConfig) {
        OidcClientAuthenticationMethod method = tokenEndpointAuthenticationMethod(tenantConfig);
        return tenantConfig.clientSecret()
                .orElseThrow(() -> new IllegalArgumentException("client-secret must be configured for "
                                                                        + method
                                                                        + " Token Endpoint authentication"));
    }
}
