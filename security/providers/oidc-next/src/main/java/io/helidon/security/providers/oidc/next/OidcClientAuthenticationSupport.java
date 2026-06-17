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

    private final OidcClientAuthenticationMethod method;
    private final Optional<String> clientId;
    private final Optional<String> clientSecret;
    private final OidcClientAssertionConfig assertion;
    private final String endpointName;
    private final Jwk privateKeyJwk;

    private OidcClientAuthenticationSupport(OidcClientAuthenticationMethod method,
                                            Optional<String> clientId,
                                            Optional<String> clientSecret,
                                            OidcClientAssertionConfig assertion,
                                            String endpointName) {
        this.method = method;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.assertion = assertion;
        this.endpointName = endpointName;
        this.privateKeyJwk = method == OidcClientAuthenticationMethod.PRIVATE_KEY_JWT
                ? privateKeyJwk(assertion, endpointName)
                : null;
    }

    static OidcClientAuthenticationSupport create(OidcTenantConfig tenantConfig) {
        return tokenEndpoint(tenantConfig);
    }

    static OidcClientAuthenticationSupport tokenEndpoint(OidcTenantConfig tenantConfig) {
        return new OidcClientAuthenticationSupport(tokenEndpointAuthenticationMethod(tenantConfig),
                                                   tenantConfig.clientId(),
                                                   tenantConfig.clientSecret(),
                                                   tenantConfig.clientAssertion(),
                                                   "Token Endpoint");
    }

    static OidcClientAuthenticationSupport introspectionEndpoint(OidcTenantConfig tenantConfig) {
        if (tenantConfig.protectedResource()
                .map(OidcProtectedResourceConfig::tokenValidation)
                .flatMap(OidcTokenValidationConfig::method)
                .filter(OidcTokenValidationMethod.INTROSPECTION::equals)
                .isEmpty()) {
            return new OidcClientAuthenticationSupport(OidcClientAuthenticationMethod.NONE,
                                                       Optional.empty(),
                                                       Optional.empty(),
                                                       OidcClientAssertionConfig.create(),
                                                       "Introspection Endpoint");
        }
        OidcIntrospectionConfig introspection = introspectionConfig(tenantConfig);
        return new OidcClientAuthenticationSupport(introspectionEndpointAuthenticationMethod(tenantConfig),
                                                   introspection.clientId().or(tenantConfig::clientId),
                                                   introspection.clientSecret().or(tenantConfig::clientSecret),
                                                   introspection.clientAssertion().orElseGet(tenantConfig::clientAssertion),
                                                   "Introspection Endpoint");
    }

    void applyTokenEndpointAuthentication(URI tokenEndpointUri,
                                          Parameters.Builder form,
                                          HttpClientRequest request) {
        applyAuthentication(tokenEndpointUri, form, request, false);
    }

    void applyPushedAuthorizationRequestAuthentication(URI pushedAuthorizationRequestEndpointUri,
                                                       Optional<String> issuer,
                                                       Parameters.Builder form,
                                                       HttpClientRequest request) {
        /*
         * Spec: RFC 9126, 2 Pushed Authorization Request Endpoint
         * https://www.rfc-editor.org/rfc/rfc9126.html#section-2
         * Quote: "The rules for client authentication as defined in [RFC6749] for token endpoint requests, including
         * the applicable authentication methods, apply for the PAR endpoint as well."
         * Quote: "the issuer identifier URL of the authorization server according to [RFC8414] SHOULD be used as the
         * value of the audience."
         */
        URI assertionAudience = issuer.map(URI::create)
                .orElse(pushedAuthorizationRequestEndpointUri);
        applyAuthentication(assertionAudience, form, request, true);
    }

    void applyIntrospectionEndpointAuthentication(URI introspectionEndpointUri,
                                                 Parameters.Builder form,
                                                 HttpClientRequest request) {
        /*
         * Spec: RFC 7662, 4 Security Considerations
         * https://www.rfc-editor.org/rfc/rfc7662.html#section-4
         * Quote: "To prevent this, the authorization server MUST require authentication of protected resources that
         * need to access the introspection endpoint and SHOULD require protected resources to be specifically
         * authorized to call the introspection endpoint."
         * Quote: "The specifics of such authentication credentials are out of scope of this specification, but commonly
         * these credentials could take the form of any valid client authentication mechanism used with the token
         * endpoint, an OAuth 2.0 access token, or other HTTP authorization or authentication mechanism."
         */
        if (method == OidcClientAuthenticationMethod.NONE) {
            throw new IllegalStateException("Introspection Endpoint authentication cannot be NONE");
        }
        applyAuthentication(introspectionEndpointUri, form, request, false);
    }

    private void applyAuthentication(URI endpointUri,
                                     Parameters.Builder form,
                                     HttpClientRequest request,
                                     boolean clientIdAlreadyPresent) {
        String clientId = this.clientId.orElseThrow();
        switch (method) {
        case CLIENT_SECRET_BASIC -> request.header(HeaderNames.AUTHORIZATION,
                                                  basicAuthorization(clientId, requireClientSecret()));
        case CLIENT_SECRET_POST -> {
            /*
             * Spec: RFC 6749, 2.3.1 Client Password
             * https://www.rfc-editor.org/rfc/rfc6749.html#section-2.3.1
             * Quote: "Including the client credentials in the request-body using the two parameters is NOT RECOMMENDED
             * and SHOULD be limited to clients unable to directly utilize the HTTP Basic authentication scheme (or other
             * password-based HTTP authentication schemes)."
             */
            if (!clientIdAlreadyPresent) {
                form.add("client_id", clientId);
            }
            form.add("client_secret", requireClientSecret());
        }
        case CLIENT_SECRET_JWT, PRIVATE_KEY_JWT -> {
            /*
             * Spec: OpenID Connect Core 1.0, 9 Client Authentication
             * https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
             * Quote: "The authentication token MUST be sent as the value of the `client_assertion` parameter."
             * Quote: "The value of the `client_assertion_type` parameter MUST be
             * \"urn:ietf:params:oauth:client-assertion-type:jwt-bearer\"."
             */
            form.add("client_assertion_type", CLIENT_ASSERTION_TYPE)
                    .add("client_assertion", clientAssertion(endpointUri));
        }
        case TLS_CLIENT_AUTH, SELF_SIGNED_TLS_CLIENT_AUTH -> {
            /*
             * Spec: RFC 8705, 2 Mutual TLS for OAuth Client Authentication
             * https://www.rfc-editor.org/rfc/rfc8705.html#section-2
             * Quote: "In order to utilize TLS for OAuth client authentication, the TLS connection between the client
             * and the authorization server MUST have been established or re-established with mutual-TLS X.509
             * certificate authentication."
             * Quote: "For all requests to the authorization server utilizing mutual-TLS client authentication, the
             * client MUST include the `client_id` parameter described in Section 2.2 of OAuth 2.0."
             */
            if (!clientIdAlreadyPresent) {
                form.add("client_id", clientId);
            }
        }
        case NONE -> {
            /*
             * Spec: RFC 6749, 3.2.1 Client Authentication
             * https://www.rfc-editor.org/rfc/rfc6749.html#section-3.2.1
             * Quote: "In the `authorization_code` `grant_type` request to the token endpoint, an unauthenticated
             * client MUST send its `client_id` to prevent itself from inadvertently accepting a code intended for a
             * client with a different `client_id`."
             */
            if (!clientIdAlreadyPresent) {
                form.add("client_id", clientId);
            }
        }
        default -> throw new IllegalStateException("Unexpected client authentication method: "
                                                           + method);
        }
    }

    boolean usesMutualTls() {
        return method == OidcClientAuthenticationMethod.TLS_CLIENT_AUTH
                || method == OidcClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH;
    }

    Optional<String> clientAssertionAlgorithm() {
        return switch (method) {
        case CLIENT_SECRET_JWT -> Optional.of(assertion.algorithm().orElse(DEFAULT_CLIENT_SECRET_JWT_ALGORITHM));
        case PRIVATE_KEY_JWT -> Optional.of(privateKeyJwk.algorithm());
        default -> Optional.empty();
        };
    }

    static OidcClientAuthenticationMethod tokenEndpointAuthenticationMethod(OidcTenantConfig tenantConfig) {
        return tenantConfig.tokenEndpointAuthenticationMethod()
                .orElseGet(() -> tenantConfig.clientSecret()
                        .isPresent()
                        ? OidcClientAuthenticationMethod.CLIENT_SECRET_BASIC
                        : OidcClientAuthenticationMethod.NONE);
    }

    static OidcClientAuthenticationMethod introspectionEndpointAuthenticationMethod(OidcTenantConfig tenantConfig) {
        OidcIntrospectionConfig introspection = introspectionConfig(tenantConfig);
        return introspection.authenticationMethod()
                .orElseGet(() -> introspection.clientSecret()
                        .or(tenantConfig::clientSecret)
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

    static String defaultClientSecretJwtAlgorithm() {
        return DEFAULT_CLIENT_SECRET_JWT_ALGORITHM;
    }

    private String clientAssertion(URI endpointUri) {
        String clientId = this.clientId.orElseThrow();
        Jwk jwk = switch (method) {
        case CLIENT_SECRET_JWT -> clientSecretJwk();
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
         * Quote: "`iss` REQUIRED. Issuer. This MUST contain the `client_id` of the OAuth Client."
         * Quote: "`sub` REQUIRED. Subject. This MUST contain the `client_id` of the OAuth Client."
         * Quote: "`aud` REQUIRED. Audience(s). The Audience SHOULD be the URL of the Authorization Server's Token
         * Endpoint."
         * Quote: "`jti` REQUIRED. JWT ID. A unique identifier for the token, which can be used to prevent reuse of the
         * token."
         * Quote: "`exp` REQUIRED. Expiration time on or after which the JWT MUST NOT be accepted for processing."
         */
        Jwt.Builder jwt = Jwt.builder()
                .algorithm(algorithm)
                .issuer(clientId)
                .subject(clientId)
                .addAudience(endpointUri.toString())
                .issueTime(now)
                .expirationTime(now.plus(assertion.lifetime()))
                .jwtId(UUID.randomUUID().toString())
                .serializeDerivedClaims(false);
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

    private Jwk clientSecretJwk() {
        String algorithm = assertion.algorithm().orElse(DEFAULT_CLIENT_SECRET_JWT_ALGORITHM);
        if (!isClientSecretJwtAlgorithm(algorithm)) {
            throw new IllegalArgumentException("client-assertion.algorithm must be one of "
                                                       + clientSecretJwtAlgorithms()
                                                       + " for CLIENT_SECRET_JWT " + endpointName + " authentication");
        }
        JsonObject.Builder builder = JsonObject.builder()
                .set("kty", "oct")
                .set("alg", algorithm)
                .set("kid", assertion.keyId().orElse("client-secret"))
                .set("k", base64Url(requireClientSecret().getBytes(StandardCharsets.UTF_8)));
        return JwkOctet.create(builder.build());
    }

    private static Jwk privateKeyJwk(OidcClientAssertionConfig assertion, String endpointName) {
        JwkKeys keys = JwkKeys.builder()
                .resource(assertion.jwk().orElseThrow(() -> new IllegalArgumentException(
                        "client-assertion.jwk must be configured for PRIVATE_KEY_JWT "
                                + endpointName + " authentication")))
                .build();
        Optional<String> keyId = assertion.keyId();
        if (keyId.isPresent()) {
            return validatePrivateKeyJwk(assertion,
                                         endpointName,
                                         keys.forKeyId(keyId.orElseThrow())
                                                 .orElseThrow(() -> new IllegalArgumentException(
                                                         "client-assertion.key-id does not match a configured JWK")));
        }
        List<Jwk> jwks = keys.keys();
        if (jwks.size() == 1) {
            return validatePrivateKeyJwk(assertion, endpointName, jwks.get(0));
        }
        throw new IllegalArgumentException(
                "client-assertion.key-id must be configured when client-assertion.jwk contains multiple keys");
    }

    private static Jwk validatePrivateKeyJwk(OidcClientAssertionConfig assertion, String endpointName, Jwk jwk) {
        if (!Jwk.KEY_TYPE_RSA.equals(jwk.keyType()) && !Jwk.KEY_TYPE_EC.equals(jwk.keyType())) {
            throw new IllegalArgumentException(
                    "client-assertion.jwk must select an RSA or EC private JWK for PRIVATE_KEY_JWT");
        }
        String algorithm = jwk.algorithm();
        if (!isPrivateKeyJwtAlgorithm(algorithm)) {
            throw new IllegalArgumentException("client-assertion.jwk selected key algorithm must be one of "
                                                       + privateKeyJwtAlgorithms()
                                                       + " for PRIVATE_KEY_JWT " + endpointName + " authentication");
        }
        assertion.algorithm()
                .filter(configuredAlgorithm -> !configuredAlgorithm.equals(algorithm))
                .ifPresent(configuredAlgorithm -> {
                    throw new IllegalArgumentException("client-assertion.algorithm must match the selected JWK "
                                                               + "algorithm for PRIVATE_KEY_JWT " + endpointName + " "
                                                               + "authentication");
                });
        return jwk;
    }

    private static String base64Url(byte[] bytes) {
        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(bytes);
    }

    private String requireClientSecret() {
        return clientSecret
                .orElseThrow(() -> new IllegalArgumentException("client-secret must be configured for "
                                                                        + method
                                                                        + " " + endpointName + " authentication"));
    }

    private static OidcIntrospectionConfig introspectionConfig(OidcTenantConfig tenantConfig) {
        return tenantConfig.protectedResource()
                .map(OidcProtectedResourceConfig::tokenValidation)
                .map(OidcTokenValidationConfig::introspection)
                .orElseGet(OidcIntrospectionConfig::create);
    }
}
