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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;

import io.helidon.common.configurable.Resource;
import io.helidon.common.configurable.ResourceConfig;
import io.helidon.http.Status;
import io.helidon.json.JsonArray;
import io.helidon.json.JsonObject;
import io.helidon.json.JsonParser;
import io.helidon.security.AuthenticationResponse;
import io.helidon.security.Grant;
import io.helidon.security.SecurityEnvironment;
import io.helidon.security.SecurityResponse;
import io.helidon.security.Subject;
import io.helidon.security.jwt.Jwt;
import io.helidon.security.jwt.SignedJwt;
import io.helidon.security.jwt.jwk.Jwk;
import io.helidon.security.jwt.jwk.JwkKeys;
import io.helidon.security.jwt.jwk.JwkRSA;
import io.helidon.security.providers.common.TokenCredential;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

/* RFC 9068, JWT Access Token Profile: https://www.rfc-editor.org/rfc/rfc9068.html#section-4
 * RFC 7519, Nested JWT and replicated claims: https://www.rfc-editor.org/rfc/rfc7519.html#section-5
 * Per-tenant key selection and fail-closed algorithm restrictions are Helidon security policy.
 */
class OidcEncryptedJwtAccessTokenTest {
    private static final String ISSUER = "https://issuer.example";
    private static final String AUDIENCE = "api://default";
    private static final String SUBJECT = "user1-id";

    private static JwkKeys signKeys;
    private static JwkKeys encryptKeys;
    private static URI jwksUri;

    @BeforeAll
    static void initKeys() throws Exception {
        signKeys = JwkKeys.builder().resource(Resource.create("oidc-next-sign-jwk.json")).build();
        encryptKeys = JwkKeys.builder().resource(Resource.create("oidc-next-encrypt-jwk.json")).build();
        jwksUri = OidcEncryptedJwtAccessTokenTest.class.getClassLoader()
                .getResource("oidc-next-verify-public-jwk.json").toURI();
    }

    // RFC 9068, 4: "If the JWT access token is encrypted, decrypt it using the keys and algorithms" negotiated.
    @Test
    void encryptedJwtAccessTokenAuthenticatesAndRetainsItsPresentedValue() throws JOSEException {
        String signed = signedToken(jwt -> jwt.addScope("resource.read"));
        String encrypted = encryptedToken(signed);
        try (OidcProvider provider = encryptedProvider(_ -> { })) {
            AuthenticationResponse response = authenticate(provider, encrypted);

            assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
            Subject subject = response.user().orElseThrow();
            assertThat(subject.principal().id(), is(OidcTestIdentities.issuerSubject(ISSUER, SUBJECT)));
            assertThat(subject.grantsByType("scope").stream().map(Grant::getName).toList(), is(List.of("resource.read")));
            TokenCredential credential = subject.publicCredential(TokenCredential.class).orElseThrow();
            assertThat(credential.token(), is(encrypted));
            assertThat(credential.getTokenInstance(SignedJwt.class).orElseThrow().tokenContent(), is(signed));
        }
    }

    // RFC 7519, 5.3: the recipient "SHOULD verify that their values are identical" for replicated claims.
    @Test
    void encryptedJwtAccessTokenAcceptsMatchingReplicatedClaims() throws JOSEException {
        String signed = signedToken(_ -> { });
        String encrypted = OidcTestJwe.encrypt(signed, encryptKeys, true,
                                               JsonObject.builder().set("iss", ISSUER)
                                                       .set("sub", SUBJECT)
                                                       .setStrings("aud", List.of(AUDIENCE))
                                                       .build());
        try (OidcProvider provider = encryptedProvider(_ -> { })) {
            assertThat(authenticate(provider, encrypted).status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        }
    }

    // RFC 9068, 4: decrypt with "the keys and algorithms that the resource server specified during registration".
    @Test
    void encryptedJwtAccessTokenUsesOnlyNegotiatedJweAlgorithms() throws JOSEException {
        String signed = signedToken(_ -> { });
        String token = encryptedTokenWithAlgorithms(signed, JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128CBC_HS256, true);
        try (OidcProvider provider = encryptedProvider(validation -> validation
                .allowedEncryptionAlgorithms(List.of("RSA-OAEP"))
                .allowedContentEncryptionAlgorithms(List.of("A128CBC-HS256")))) {
            assertThat(authenticate(provider, token).status(), is(SecurityResponse.SecurityStatus.SUCCESS));
            assertInvalidToken(authenticate(provider, encryptedToken(signed)));
        }
    }

    // Requiring a per-key JWK algorithm when multiple key-management algorithms are enabled is Helidon policy.
    @Test
    void multipleKeyManagementAlgorithmsNeedPerKeyAlgorithmBinding() throws JOSEException {
        OidcTenantConfig ambiguous = tenant(validation -> validation
                .decryptionJwk(privateKeyResource())
                .allowedEncryptionAlgorithms(List.of("RSA-OAEP-256", "RSA-OAEP"))
                .allowedContentEncryptionAlgorithms(List.of("A256GCM")));
        try (OidcProvider provider = OidcProvider.create(OidcProviderConfig.builder()
                .putTenant("default", ambiguous).buildPrototype())) {
            OidcTenantContext context = provider.tenantRuntimeRegistry().tenantContext("default").orElseThrow();
            assertThat(context.ready(), is(false));
            assertThat(context.failureCause().orElseThrow().getMessage(), containsString("decryption JWK alg"));
        }

        JsonObject original = JsonParser.create(Resource.create("oidc-next-encrypt-jwk.json").string()).readJsonObject();
        JsonObject key = original.arrayValue("keys").orElseThrow().values().getFirst().asObject();
        String boundKeys = JsonObject.builder()
                .set("keys", JsonArray.create(List.of(JsonObject.builder().from(key)
                                                              .set("alg", "RSA-OAEP-256").build())))
                .build().toString();
        String signed = signedToken(_ -> { });
        try (OidcProvider provider = encryptedProvider(validation -> validation
                .decryptionJwk(ResourceConfig.builder().contentPlain(boundKeys).buildPrototype())
                .allowedEncryptionAlgorithms(List.of("RSA-OAEP-256", "RSA-OAEP")))) {
            assertThat(authenticate(provider, encryptedToken(signed)).status(), is(SecurityResponse.SecurityStatus.SUCCESS));
            assertInvalidToken(authenticate(provider,
                                            encryptedTokenWithAlgorithms(signed, JWEAlgorithm.RSA_OAEP,
                                                                         EncryptionMethod.A256GCM, true)));
        }
    }

    // RFC 9068, 4: when encryption was negotiated, the resource server "SHOULD reject" a plain token;
    // Helidon makes this strict by default, but permits an explicit compatibility opt-out.
    @Test
    void accessTokenEncryptionIsRequiredByDefaultWhenKeysAreConfigured() throws JOSEException {
        String signed = signedToken(_ -> { });
        String encrypted = encryptedToken(signed);
        try (OidcProvider provider = encryptedProvider(_ -> { })) {
            assertInvalidToken(authenticate(provider, signed));
            assertThat(authenticate(provider, encrypted).status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        }
        try (OidcProvider provider = encryptedProvider(validation -> validation.encryptionRequired(false))) {
            assertThat(authenticate(provider, signed).status(), is(SecurityResponse.SecurityStatus.SUCCESS));
            assertThat(authenticate(provider, encrypted).status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        }
    }

    // RFC 9068, 4: encrypted access tokens require the registered decryption keys and algorithms.
    @Test
    void encryptedJwtAccessTokenWithoutPrivateKeysIsRejectedWithoutAffectingSignedTokens() throws JOSEException {
        try (OidcProvider provider = provider(_ -> { })) {
            assertInvalidToken(authenticate(provider, encryptedToken(signedToken(_ -> { }))));
            assertThat(authenticate(provider, signedToken(_ -> { })).status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        }
    }

    // RFC 9068, 4: "The resource server MUST validate the signature of all incoming JWT access tokens".
    @Test
    void encryptedJwtAccessTokenStillRequiresValidInnerSignatureTypeAndClaims() throws JOSEException {
        String signed = signedToken(_ -> { });
        int signatureStart = signed.lastIndexOf('.') + 1;
        String tamperedSignature = signed.substring(0, signatureStart)
                + (signed.charAt(signatureStart) == 'A' ? 'B' : 'A')
                + signed.substring(signatureStart + 1);
        try (OidcProvider provider = encryptedProvider(_ -> { })) {
            for (String inner : List.of(
                    "{\"sub\":\"user1\"}",
                    unsignedToken(_ -> { }),
                    signedToken(jwt -> jwt.type("id+jwt")),
                    signedToken(jwt -> jwt.issuer("https://other-issuer.example")),
                    signedToken(jwt -> jwt.audience(List.of("api://another-resource"))),
                    signedToken(jwt -> jwt.expirationTime(Instant.now().minusSeconds(300))),
                    tamperedSignature)) {
                assertInvalidToken(authenticate(provider, encryptedToken(inner)));
            }
        }
    }

    // RFC 7519, 5.2 requires cty="JWT" for nested tokens; RFC 7519, 5.3 recommends replicated-claim equality.
    // Refusing `zip`, ambiguous keys, and disabled algorithms is deliberate Helidon policy, not a universal JWE prohibition.
    @Test
    void malformedEncryptedAccessTokensAreRejected() throws JOSEException {
        String signed = signedToken(_ -> { });
        String encrypted = encryptedToken(signed);
        int tagStart = encrypted.lastIndexOf('.') + 1;
        String badTag = encrypted.substring(0, tagStart)
                + (encrypted.charAt(tagStart) == 'A' ? 'B' : 'A')
                + encrypted.substring(tagStart + 1);
        try (OidcProvider provider = encryptedProvider(_ -> { })) {
            for (String token : List.of(
                    OidcTestJwe.encrypt(signed, encryptKeys, false, JsonObject.builder().build()),
                    OidcTestJwe.encrypt(signed, encryptKeys, true,
                                        JsonObject.builder().set("kid", "unknown-key").build()),
                    OidcTestJwe.encrypt(signed, encryptKeys, true,
                                        JsonObject.builder().set("alg", "RSA1_5").build()),
                    OidcTestJwe.encrypt(signed, encryptKeys, true,
                                        JsonObject.builder().set("enc", "A128GCM").build()),
                    OidcTestJwe.encrypt(signed, encryptKeys, true,
                                        JsonObject.builder().setStrings("crit", List.of("unknown")).build()),
                    OidcTestJwe.encrypt(signed, encryptKeys, true,
                                        JsonObject.builder().set("zip", "DEF").build()),
                    OidcTestJwe.encrypt(signed, encryptKeys, true,
                                        JsonObject.builder().set("iss", "https://other-issuer.example").build()),
                    OidcTestJwe.encrypt(signed, encryptKeys, true,
                                        JsonObject.builder().set("sub", "other-subject").build()),
                    OidcTestJwe.encrypt(signed, encryptKeys, true,
                                        JsonObject.builder().setStrings("aud", List.of("api://other")).build()),
                    badTag)) {
                assertInvalidToken(authenticate(provider, token));
            }
        }
    }

    @Test
    void encryptedJwtAccessTokenRejectsMalformedUtf8Plaintext() throws JOSEException {
        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                .contentType("JWT")
                .keyID("encrypt-rsa")
                .build();
        JWEObject token = new JWEObject(header, new Payload(new byte[] {(byte) 0xc3, (byte) 0x28}));
        JwkRSA key = (JwkRSA) encryptKeys.forKeyId("encrypt-rsa").orElseThrow();
        token.encrypt(new RSAEncrypter((RSAPublicKey) key.publicKey()));
        try (OidcProvider provider = encryptedProvider(_ -> { })) {
            assertInvalidToken(authenticate(provider, token.serialize()));
        }
    }

    // RFC 7516, 4.1.6 treats kid as a key-selection hint, not a universal requirement;
    // requiring it when several local private keys exist is Helidon fail-closed policy.
    @Test
    void encryptedAccessTokenWithoutKidNeedsExactlyOnePrivateKey() throws JOSEException {
        String signed = signedToken(_ -> { });
        String encrypted = encryptedTokenWithAlgorithms(signed,
                                                       JWEAlgorithm.RSA_OAEP_256,
                                                       EncryptionMethod.A256GCM,
                                                       false);
        try (OidcProvider provider = encryptedProvider(_ -> { })) {
            assertThat(authenticate(provider, encrypted).status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        }

        JsonObject original = JsonParser.create(Resource.create("oidc-next-encrypt-jwk.json").string()).readJsonObject();
        JsonObject firstKey = original.arrayValue("keys").orElseThrow().values().getFirst().asObject();
        JsonObject secondKey = JsonObject.builder().from(firstKey).set("kid", "another-key").build();
        String multipleKeys = JsonObject.builder()
                .set("keys", JsonArray.create(List.of(firstKey, secondKey)))
                .build().toString();
        try (OidcProvider provider = encryptedProvider(validation -> validation
                .decryptionJwk(ResourceConfig.builder().contentPlain(multipleKeys).buildPrototype()))) {
            assertInvalidToken(authenticate(provider, encrypted));
            assertThat(authenticate(provider, encryptedToken(signed)).status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        }
    }

    @Test
    void accessTokenDecryptionKeysAreIsolatedByTenant() throws Exception {
        String encrypted = encryptedToken(signedToken(_ -> { }));
        // The signing and encryption test fixtures contain the same RSA key; generate a distinct key with the same
        // kid so this test fails if the validator ever reuses a different tenant's decryption key.
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(OidcJoseKeyPolicy.MINIMUM_RSA_KEY_BITS);
        KeyPair keyPair = generator.generateKeyPair();
        RSAKey otherKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey((RSAPrivateKey) keyPair.getPrivate())
                .keyUse(KeyUse.ENCRYPTION)
                .keyID("encrypt-rsa")
                .build();
        String otherKeys = JsonObject.builder()
                .set("keys", JsonArray.create(List.of(JsonParser.create(otherKey.toJSONString()).readJsonObject())))
                .build().toString();
        try (OidcProvider provider = OidcProvider.create(OidcProviderConfig.builder()
                .putTenant("first", tenant(validation -> validation
                        .decryptionJwk(privateKeyResource())
                        .allowedEncryptionAlgorithms(List.of("RSA-OAEP-256"))
                        .allowedContentEncryptionAlgorithms(List.of("A256GCM"))))
                .putTenant("second", tenant(validation -> validation
                        .decryptionJwk(ResourceConfig.builder().contentPlain(otherKeys).buildPrototype())
                        .allowedEncryptionAlgorithms(List.of("RSA-OAEP-256"))
                        .allowedContentEncryptionAlgorithms(List.of("A256GCM"))))
                .buildPrototype())) {
            OidcJwtAccessTokenValidator validator = new OidcJwtAccessTokenValidator();
            OidcTenantContext first = provider.tenantRuntimeRegistry().tenantContext("first").orElseThrow();
            OidcTenantContext second = provider.tenantRuntimeRegistry().tenantContext("second").orElseThrow();
            assertThat(validator.validate(new OidcAccessTokenValidationRequest(encrypted, first,
                                                                               Optional.empty(), Instant.now()))
                               .succeeded(), is(true));
            assertThat(validator.validate(new OidcAccessTokenValidationRequest(encrypted, second,
                                                                               Optional.empty(), Instant.now()))
                               .succeeded(), is(false));
        }
    }

    private static OidcProvider encryptedProvider(Consumer<OidcTokenValidationConfig.Builder> customizer) {
        return provider(validation -> {
            validation.decryptionJwk(privateKeyResource())
                    .allowedEncryptionAlgorithms(List.of("RSA-OAEP-256"))
                    .allowedContentEncryptionAlgorithms(List.of("A256GCM"));
            customizer.accept(validation);
        });
    }

    private static OidcProvider provider(Consumer<OidcTokenValidationConfig.Builder> customizer) {
        return OidcProvider.create(OidcProviderConfig.builder()
                                           .putTenant("default", tenant(customizer))
                                           .buildPrototype());
    }

    private static OidcTenantConfig tenant(Consumer<OidcTokenValidationConfig.Builder> customizer) {
        return OidcTenantConfig.builder()
                .issuer(ISSUER)
                .endpoints(endpoints -> endpoints.jwksUri(jwksUri).tlsRequired(false))
                .protectedResource(resource -> resource.tokenValidation(validation -> {
                    validation.method(OidcTokenValidationMethod.JWT).audience(AUDIENCE);
                    customizer.accept(validation);
                }))
                .buildPrototype();
    }

    private static ResourceConfig privateKeyResource() {
        return ResourceConfig.builder().resourcePath("oidc-next-encrypt-jwk.json").buildPrototype();
    }

    private static AuthenticationResponse authenticate(OidcProvider provider, String token) {
        return provider.authenticate(OidcProviderTest.request(null,
                                                              SecurityEnvironment.builder()
                                                                      .targetUri(URI.create("https://rp.example/resource"))
                                                                      .header("Authorization", "Bearer " + token)
                                                                      .build()));
    }

    private static void assertInvalidToken(AuthenticationResponse response) {
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.FAILURE));
        assertThat(response.statusCode().orElse(-1), is(Status.UNAUTHORIZED_401.code()));
        assertThat(response.responseHeaders().get("WWW-Authenticate").getFirst(),
                   is("Bearer realm=\"helidon\", error=\"invalid_token\", "
                              + "error_description=\"Bearer Token is invalid\""));
    }

    private static String encryptedToken(String signedJwt) throws JOSEException {
        return OidcTestJwe.encrypt(signedJwt, encryptKeys, true, JsonObject.builder().build());
    }

    private static String encryptedTokenWithAlgorithms(String signedJwt,
                                                       JWEAlgorithm algorithm,
                                                       EncryptionMethod encryption,
                                                       boolean includeKid) throws JOSEException {
        JWEHeader.Builder headerBuilder = new JWEHeader.Builder(algorithm, encryption).contentType("JWT");
        if (includeKid) {
            headerBuilder.keyID("encrypt-rsa");
        }
        JWEObject jwe = new JWEObject(headerBuilder.build(), new Payload(signedJwt));
        JwkRSA key = (JwkRSA) encryptKeys.forKeyId("encrypt-rsa").orElseThrow();
        jwe.encrypt(new RSAEncrypter((RSAPublicKey) key.publicKey()));
        return jwe.serialize();
    }

    private static Jwt.Builder accessToken() {
        Instant now = Instant.now();
        return Jwt.builder()
                .type("at+jwt")
                .subject(SUBJECT)
                .preferredUsername("user1")
                .issuer(ISSUER)
                .algorithm(JwkRSA.ALG_RS256)
                .keyId("verify-rsa")
                .issueTime(now)
                .expirationTime(now.plus(1, ChronoUnit.HOURS))
                .jwtId("jwt-id")
                .addPayloadClaim("client_id", "calling-client")
                .addAudience(AUDIENCE);
    }

    private static String signedToken(Consumer<Jwt.Builder> customizer) {
        Jwt.Builder builder = accessToken();
        customizer.accept(builder);
        Jwk signingKey = OidcJoseKeyPolicy.signingKey(signKeys.forKeyId("sign-rsa").orElseThrow(),
                                                      Optional.of(JwkRSA.ALG_RS256),
                                                      "test signing JWK");
        return SignedJwt.sign(builder.build(), signingKey).tokenContent();
    }

    private static String unsignedToken(Consumer<Jwt.Builder> customizer) {
        Jwt.Builder builder = accessToken().algorithm(Jwk.ALG_NONE);
        customizer.accept(builder);
        return SignedJwt.sign(builder.build(), Jwk.NONE_JWK).tokenContent();
    }
}
