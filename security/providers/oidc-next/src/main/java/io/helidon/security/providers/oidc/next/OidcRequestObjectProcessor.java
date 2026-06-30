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

import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import io.helidon.common.configurable.Resource;
import io.helidon.common.configurable.ResourceConfig;
import io.helidon.common.parameters.Parameters;
import io.helidon.security.jwt.EncryptedJwt;
import io.helidon.security.jwt.Jwt;
import io.helidon.security.jwt.SignedJwt;
import io.helidon.security.jwt.jwk.Jwk;
import io.helidon.security.jwt.jwk.JwkEC;
import io.helidon.security.jwt.jwk.JwkKeys;
import io.helidon.security.jwt.jwk.JwkRSA;

final class OidcRequestObjectProcessor {
    private static final String REQUEST = "request";
    private static final String REQUEST_URI = "request_uri";
    private static final int MINIMUM_RSA_KEY_BITS = 2048;

    private final OidcRequestObjectConfig requestObject;
    private final Jwk signingJwk;
    private final OidcJwkSetManager jwkSetManager;

    private OidcRequestObjectProcessor(OidcRequestObjectConfig requestObject,
                                       Jwk signingJwk,
                                       OidcJwkSetManager jwkSetManager) {
        this.requestObject = requestObject;
        this.signingJwk = signingJwk;
        this.jwkSetManager = jwkSetManager;
    }

    static Optional<OidcRequestObjectProcessor> create(OidcTenantConfig tenantConfig,
                                                       OidcJwkSetManager jwkSetManager) {
        return tenantConfig.authorizationCode()
                .filter(OidcAuthorizationCodeConfig::enabled)
                .map(OidcAuthorizationCodeConfig::requestObject)
                .filter(requestObject -> requestObject.mode() != OidcRequestObjectMode.DISABLED)
                .filter(requestObject -> requestObject.signingJwk().isPresent())
                .map(requestObject -> new OidcRequestObjectProcessor(requestObject,
                                                                     signingJwk(requestObject),
                                                                     jwkSetManager));
    }

    static Optional<String> signingAlgorithm(OidcRequestObjectConfig requestObject) {
        return requestObject.signingJwk()
                .map(_ -> signingJwk(requestObject).algorithm());
    }

    static boolean shouldUse(OidcAuthorizationCodeConfig authorizationCode, OidcProviderMetadata metadata) {
        OidcRequestObjectConfig requestObject = authorizationCode.requestObject();
        return switch (requestObject.mode()) {
        case DISABLED -> false;
        case AUTO -> requestObject.signingJwk().isPresent() || metadata.requireSignedRequestObject();
        case REQUIRED -> true;
        };
    }

    String process(String clientId, String issuer, Parameters authorizationParameters, Instant now) {
        SignedJwt signedJwt = sign(clientId, issuer, authorizationParameters, now);
        if (requestObject.encryptionAlgorithm().isEmpty()) {
            return signedJwt.tokenContent();
        }
        return encrypt(signedJwt);
    }

    private SignedJwt sign(String clientId, String issuer, Parameters authorizationParameters, Instant now) {
        /*
         * Spec: RFC 9101, 4 Request Object
         * https://www.rfc-editor.org/rfc/rfc9101.html#section-4
         * Quote: "It MUST contain all the parameters (including extension parameters) used to process the OAuth 2.0
         * authorization request except the `request` and `request_uri` parameters".
         * Quote: "The parameters are represented as the JWT Claims of the object."
         * Quote: "The JWT Claims Set is then signed or signed and encrypted."
         * Quote: "The `request` and `request_uri` parameters MUST NOT be included in Request Objects."
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

        return SignedJwt.sign(jwt.build(), signingJwk);
    }

    private String encrypt(SignedJwt signedJwt) {
        /*
         * Spec: RFC 9101, 4 Request Object
         * https://www.rfc-editor.org/rfc/rfc9101.html#section-4
         * Quote: "When both signature and encryption are being applied, the JWT MUST be signed, then encrypted".
         * Quote: "The result is a Nested JWT".
         */
        String algorithm = requestObject.encryptionAlgorithm().orElseThrow();
        String contentEncryption = requestObject.contentEncryptionAlgorithm()
                .orElse(OidcRequestObjectConfigBlueprint.DEFAULT_CONTENT_ENCRYPTION_ALGORITHM);
        JwkKeys keys = jwkSetManager.jwkKeys(requestObject.encryptionKeyId());
        Jwk encryptionJwk = selectEncryptionJwk(keys, requestObject.encryptionKeyId(), algorithm);
        EncryptedJwt.Builder builder = EncryptedJwt.builder(signedJwt)
                .algorithm(supportedAlgorithm(algorithm))
                .encryption(supportedEncryption(contentEncryption));
        if (encryptionJwk.keyId() == null) {
            builder.jwk(encryptionJwk);
        } else {
            builder.jwks(keys, encryptionJwk.keyId());
        }
        return builder.build().token();
    }

    static Jwk selectEncryptionJwk(JwkKeys keys, Optional<String> configuredKeyId, String algorithm) {
        List<Jwk> availableKeys = keys.keys();
        if (configuredKeyId.isPresent()) {
            Jwk selected = keys.forKeyId(configuredKeyId.orElseThrow())
                    .orElseThrow(() -> new IllegalStateException(
                            "Authorization Server JWK Set does not contain the configured Request Object encryption key"));
            if (!isEligibleEncryptionJwk(selected, algorithm, availableKeys.size())) {
                throw new IllegalStateException(
                        "Configured Request Object encryption key is not eligible for the selected algorithm");
            }
            return selected;
        }
        for (Jwk candidate : availableKeys) {
            if (isEligibleEncryptionJwk(candidate, algorithm, availableKeys.size())) {
                return candidate;
            }
        }
        throw new IllegalStateException(
                "Authorization Server JWK Set does not contain an eligible Request Object encryption key");
    }

    static boolean isEligibleEncryptionJwk(Jwk jwk, String algorithm, int keyCount) {
        if (!(jwk instanceof JwkRSA rsa)
                || !(rsa.publicKey() instanceof RSAPublicKey publicKey)
                || publicKey.getModulus().bitLength() < MINIMUM_RSA_KEY_BITS) {
            return false;
        }
        if (keyCount > 1 && jwk.keyId() == null) {
            return false;
        }
        if (jwk.usage().filter(usage -> !Jwk.USE_ENCRYPTION.equals(usage)).isPresent()) {
            return false;
        }
        if (jwk.operations()
                .filter(operations -> !operations.contains(Jwk.OPERATION_WRAP_KEY)
                        && !operations.contains(Jwk.OPERATION_ENCRYPT))
                .isPresent()) {
            return false;
        }
        return jwk.declaredAlgorithm().filter(declared -> !algorithm.equals(declared)).isEmpty();
    }

    private static EncryptedJwt.SupportedAlgorithm supportedAlgorithm(String algorithm) {
        return switch (algorithm) {
        case "RSA-OAEP-256" -> EncryptedJwt.SupportedAlgorithm.RSA_OAEP_256;
        case "RSA-OAEP" -> EncryptedJwt.SupportedAlgorithm.RSA_OAEP;
        default -> throw new IllegalArgumentException("Unsupported Request Object encryption algorithm");
        };
    }

    private static EncryptedJwt.SupportedEncryption supportedEncryption(String encryption) {
        return switch (encryption) {
        case "A128GCM" -> EncryptedJwt.SupportedEncryption.A128GCM;
        case "A192GCM" -> EncryptedJwt.SupportedEncryption.A192GCM;
        case "A256GCM" -> EncryptedJwt.SupportedEncryption.A256GCM;
        case "A128CBC-HS256" -> EncryptedJwt.SupportedEncryption.A128CBC_HS256;
        case "A192CBC-HS384" -> EncryptedJwt.SupportedEncryption.A192CBC_HS384;
        case "A256CBC-HS512" -> EncryptedJwt.SupportedEncryption.A256CBC_HS512;
        default -> throw new IllegalArgumentException("Unsupported Request Object content encryption algorithm");
        };
    }

    private static Jwk signingJwk(OidcRequestObjectConfig requestObject) {
        ResourceConfig jwkConfig = requestObject.signingJwk().orElseThrow(() -> new IllegalArgumentException(
                "authorization-code.request-object.signing-jwk must be configured for signed Request Objects"));
        if (jwkConfig.uri().isPresent()) {
            throw new IllegalArgumentException(
                    "authorization-code.request-object.signing-jwk must be local private key material, not a URI");
        }
        Resource resource = jwkConfig.build();
        resource.cacheBytes();
        JwkKeys keys = JwkKeys.builder()
                .resource(resource)
                .build();
        Optional<String> keyId = requestObject.signingKeyId();
        if (keyId.isPresent()) {
            String id = keyId.orElseThrow();
            return validateSigningJwk(requestObject,
                                      keys.forKeyId(id)
                                              .orElseThrow(() -> new IllegalArgumentException(
                                                      "authorization-code.request-object.signing-key-id does not match a "
                                                              + "configured JWK")));
        }
        List<Jwk> jwks = keys.keys();
        if (jwks.size() == 1) {
            return validateSigningJwk(requestObject, jwks.getFirst());
        }
        throw new IllegalArgumentException(
                "authorization-code.request-object.signing-key-id must be configured when "
                        + "authorization-code.request-object.signing-jwk contains multiple keys");
    }

    private static Jwk validateSigningJwk(OidcRequestObjectConfig requestObject, Jwk jwk) {
        if (!Jwk.KEY_TYPE_RSA.equals(jwk.keyType()) && !Jwk.KEY_TYPE_EC.equals(jwk.keyType())) {
            throw new IllegalArgumentException(
                    "authorization-code.request-object.signing-jwk must select an RSA or EC private JWK");
        }
        if ((jwk instanceof JwkRSA rsa && rsa.privateKey().isEmpty())
                || (jwk instanceof JwkEC ec && ec.privateKey().isEmpty())) {
            throw new IllegalArgumentException(
                    "authorization-code.request-object.signing-jwk must select an RSA or EC private JWK");
        }
        String algorithm = jwk.algorithm();
        if (!OidcClientAuthenticationSupport.isPrivateKeyJwtAlgorithm(algorithm)) {
            throw new IllegalArgumentException(
                    "authorization-code.request-object.signing-jwk selected key algorithm must be one of "
                            + OidcClientAuthenticationSupport.privateKeyJwtAlgorithms());
        }
        requestObject.signingAlgorithm()
                .filter(configuredAlgorithm -> !configuredAlgorithm.equals(algorithm))
                .ifPresent(configuredAlgorithm -> {
                    throw new IllegalArgumentException(
                            "authorization-code.request-object.signing-algorithm must match the selected JWK algorithm");
                });
        return jwk;
    }
}
