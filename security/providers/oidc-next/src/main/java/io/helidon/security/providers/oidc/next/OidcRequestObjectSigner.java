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

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import io.helidon.common.configurable.Resource;
import io.helidon.common.configurable.ResourceConfig;
import io.helidon.common.parameters.Parameters;
import io.helidon.security.jwt.Jwt;
import io.helidon.security.jwt.SignedJwt;
import io.helidon.security.jwt.jwk.Jwk;
import io.helidon.security.jwt.jwk.JwkEC;
import io.helidon.security.jwt.jwk.JwkKeys;
import io.helidon.security.jwt.jwk.JwkRSA;

final class OidcRequestObjectSigner {
    private static final String REQUEST = "request";
    private static final String REQUEST_URI = "request_uri";

    private final OidcRequestObjectConfig requestObject;
    private final Jwk signingJwk;

    private OidcRequestObjectSigner(OidcRequestObjectConfig requestObject, Jwk signingJwk) {
        this.requestObject = requestObject;
        this.signingJwk = signingJwk;
    }

    static Optional<OidcRequestObjectSigner> create(OidcTenantConfig tenantConfig) {
        return tenantConfig.authorizationCode()
                .filter(OidcAuthorizationCodeConfig::enabled)
                .map(OidcAuthorizationCodeConfig::requestObject)
                .filter(requestObject -> requestObject.mode() != OidcRequestObjectMode.DISABLED)
                .filter(requestObject -> requestObject.jwk().isPresent())
                .map(requestObject -> new OidcRequestObjectSigner(requestObject, signingJwk(requestObject)));
    }

    static Optional<String> signingAlgorithm(OidcRequestObjectConfig requestObject) {
        return requestObject.jwk()
                .map(ignored -> signingJwk(requestObject).algorithm());
    }

    static boolean shouldUse(OidcAuthorizationCodeConfig authorizationCode, OidcProviderMetadata metadata) {
        OidcRequestObjectConfig requestObject = authorizationCode.requestObject();
        return switch (requestObject.mode()) {
        case DISABLED -> false;
        case AUTO -> requestObject.jwk().isPresent() || metadata.requireSignedRequestObject();
        case REQUIRED -> true;
        };
    }

    String algorithm() {
        return signingJwk.algorithm();
    }

    String sign(String clientId, String issuer, Parameters authorizationParameters, Instant now) {
        /*
         * Spec: RFC 9101, 4 Request Object
         * https://www.rfc-editor.org/rfc/rfc9101.html#section-4
         * Quote: "It MUST contain all the parameters (including extension parameters) used to process the OAuth 2.0
         * authorization request except the `request` and `request_uri` parameters".
         * Quote: "The parameters are represented as the JWT Claims of the object."
         * Quote: "The JWT Claims Set is then signed or signed and encrypted."
         * Quote: "The `request` and `request_uri` parameters MUST NOT be included in Request Objects."
         *
         * Spec: OpenID Connect Core 1.0, 6.1 Passing a Request Object by Value
         * https://openid.net/specs/openid-connect-core-1_0.html#RequestObject
         * Quote: "The Request Object MAY be signed or unsigned (plaintext). When it is plaintext, this is indicated by
         * use of the `none` algorithm".
         * Quote: "If signed, the Request Object SHOULD contain the Claims `iss` (issuer) and `aud` (audience) as
         * members."
         */
        Jwt.Builder jwt = Jwt.builder()
                .algorithm(signingJwk.algorithm())
                .issuer(clientId)
                .addAudience(issuer)
                .issueTime(now)
                .expirationTime(now.plus(requestObject.lifetime()))
                .jwtId(UUID.randomUUID().toString())
                .serializeDerivedClaims(false);
        Optional.ofNullable(signingJwk.keyId()).ifPresent(jwt::keyId);

        for (String name : authorizationParameters.names()) {
            if (REQUEST.equals(name) || REQUEST_URI.equals(name)) {
                continue;
            }
            List<String> values = authorizationParameters.all(name);
            if (values.size() == 1) {
                jwt.addPayloadClaim(name, values.getFirst());
            } else {
                jwt.addPayloadClaim(name, values);
            }
        }

        return SignedJwt.sign(jwt.build(), signingJwk).tokenContent();
    }

    private static Jwk signingJwk(OidcRequestObjectConfig requestObject) {
        ResourceConfig jwkConfig = requestObject.jwk().orElseThrow(() -> new IllegalArgumentException(
                "authorization-code.request-object.jwk must be configured for signed Request Objects"));
        if (jwkConfig.uri().isPresent()) {
            throw new IllegalArgumentException(
                    "authorization-code.request-object.jwk must be local private key material, not a URI");
        }
        Resource resource = jwkConfig.build();
        resource.cacheBytes();
        JwkKeys keys = JwkKeys.builder()
                .resource(resource)
                .build();
        Optional<String> keyId = requestObject.keyId();
        if (keyId.isPresent()) {
            return validateSigningJwk(requestObject,
                                      keys.forKeyId(keyId.orElseThrow())
                                              .orElseThrow(() -> new IllegalArgumentException(
                                                      "authorization-code.request-object.key-id does not match a "
                                                              + "configured JWK")));
        }
        List<Jwk> jwks = keys.keys();
        if (jwks.size() == 1) {
            return validateSigningJwk(requestObject, jwks.get(0));
        }
        throw new IllegalArgumentException(
                "authorization-code.request-object.key-id must be configured when authorization-code.request-object.jwk "
                        + "contains multiple keys");
    }

    private static Jwk validateSigningJwk(OidcRequestObjectConfig requestObject, Jwk jwk) {
        if (!Jwk.KEY_TYPE_RSA.equals(jwk.keyType()) && !Jwk.KEY_TYPE_EC.equals(jwk.keyType())) {
            throw new IllegalArgumentException(
                    "authorization-code.request-object.jwk must select an RSA or EC private JWK");
        }
        if ((jwk instanceof JwkRSA rsa && rsa.privateKey().isEmpty())
                || (jwk instanceof JwkEC ec && ec.privateKey().isEmpty())) {
            throw new IllegalArgumentException(
                    "authorization-code.request-object.jwk must select an RSA or EC private JWK");
        }
        String algorithm = jwk.algorithm();
        if (!OidcClientAuthenticationSupport.isPrivateKeyJwtAlgorithm(algorithm)) {
            throw new IllegalArgumentException("authorization-code.request-object.jwk selected key algorithm must be one "
                                                       + "of "
                                                       + OidcClientAuthenticationSupport.privateKeyJwtAlgorithms());
        }
        requestObject.algorithm()
                .filter(configuredAlgorithm -> !configuredAlgorithm.equals(algorithm))
                .ifPresent(configuredAlgorithm -> {
                    throw new IllegalArgumentException(
                            "authorization-code.request-object.algorithm must match the selected JWK algorithm");
                });
        return jwk;
    }
}
