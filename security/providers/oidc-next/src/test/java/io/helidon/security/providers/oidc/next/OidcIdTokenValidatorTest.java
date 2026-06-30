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
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.UnaryOperator;

import io.helidon.common.configurable.Resource;
import io.helidon.security.jwt.EncryptedJwt;
import io.helidon.security.jwt.Jwt;
import io.helidon.security.jwt.SignedJwt;
import io.helidon.security.jwt.jwk.Jwk;
import io.helidon.security.jwt.jwk.JwkKeys;
import io.helidon.security.jwt.jwk.JwkOctet;
import io.helidon.security.jwt.jwk.JwkRSA;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

class OidcIdTokenValidatorTest {
    private static final URI ISSUER = URI.create("https://issuer.example");
    private static final URI AUTHORIZATION_ENDPOINT_URI = URI.create("https://issuer.example/authorize");
    private static final URI TOKEN_ENDPOINT_URI = URI.create("https://issuer.example/token");
    private static final URI REDIRECTION_ENDPOINT_URI = URI.create("https://rp.example/oidc/callback");
    private static final URI ORIGINAL_URI = URI.create("https://rp.example/resource");
    private static final String CLIENT_ID = "client-id";
    private static final String SUBJECT = "user1-id";
    private static final String NONCE = "nonce-value";
    private static final String COOKIE_SECRET = "test-cookie-secret";

    private static JwkKeys signKeys;
    private static JwkKeys encryptKeys;
    private static URI jwksUri;

    private final OidcIdTokenValidator validator = new OidcIdTokenValidator();

    @BeforeAll
    static void initClass() throws Exception {
        signKeys = JwkKeys.builder()
                .resource(Resource.create("oidc-next-sign-jwk.json"))
                .build();
        encryptKeys = JwkKeys.builder()
                .resource(Resource.create("oidc-next-encrypt-jwk.json"))
                .build();
        jwksUri = OidcIdTokenValidatorTest.class.getClassLoader()
                .getResource("oidc-next-verify-jwk.json")
                .toURI();
    }

    @Test
    void validIdTokenIsAccepted() {
        String idToken = signedIdToken(it -> it.email("user1@example.org"));

        var result = validate(idToken);

        assertThat(result.succeeded(), is(true));
        OidcValidatedIdToken validated = result.validatedToken().orElseThrow();
        assertThat(validated.rawToken(), is(idToken));
        assertThat(validated.jwt().subject().orElse(""), is(SUBJECT));
    }

    @Test
    void encryptedIdTokenIsDecryptedAndValidated() {
        String signedIdToken = signedIdToken(it -> it.email("user1@example.org"));
        String encryptedIdToken = encryptedIdToken(signedIdToken);

        var result = validate(encryptedIdToken, tenantConfig(it -> it.idToken(idToken -> idToken
                .decryptionJwk(Resource.create("oidc-next-encrypt-jwk.json")))));

        assertThat(result.succeeded(), is(true));
        OidcValidatedIdToken validated = result.validatedToken().orElseThrow();
        assertThat(validated.rawToken(), is(encryptedIdToken));
        assertThat(validated.encrypted(), is(true));
        assertThat(validated.signedJwt().tokenContent(), is(signedIdToken));
        assertThat(validated.jwt().subject().orElse(""), is(SUBJECT));
    }

    @Test
    void signedIdTokenIsAcceptedWhenDecryptionKeyIsConfigured() {
        String idToken = signedIdToken(it -> it.email("user1@example.org"));

        var result = validate(idToken, tenantConfig(it -> it.idToken(config -> config
                .decryptionJwk(Resource.create("oidc-next-encrypt-jwk.json")))));

        assertThat(result.succeeded(), is(true));
        OidcValidatedIdToken validated = result.validatedToken().orElseThrow();
        assertThat(validated.rawToken(), is(idToken));
        assertThat(validated.encrypted(), is(false));
    }

    @Test
    void encryptedIdTokenWithoutDecryptionKeyIsRejected() {
        String encryptedIdToken = encryptedIdToken(signedIdToken(_ -> { }));

        var result = validate(encryptedIdToken);

        assertFailure(result, "ID Token decryption keys are not configured");
    }

    @Test
    void encryptedIdTokenWithoutNestedJwtContentTypeIsRejected() {
        String encryptedIdToken = withoutJweHeaderClaim(encryptedIdToken(signedIdToken(_ -> { })), "cty", "JWT");

        var result = validate(encryptedIdToken, tenantConfig(it -> it.idToken(config -> config
                .decryptionJwk(Resource.create("oidc-next-encrypt-jwk.json")))));

        assertFailure(result, "Encrypted ID Token must be a Nested JWT with cty=JWT");
    }

    @Test
    void encryptedIdTokenWithDisallowedEncryptionAlgorithmIsRejected() {
        String encryptedIdToken = encryptedIdToken(signedIdToken(_ -> { }));

        var result = validate(encryptedIdToken, tenantConfig(it -> it.idToken(config -> config
                .decryptionJwk(Resource.create("oidc-next-encrypt-jwk.json"))
                .allowedEncryptionAlgorithms(List.of("RSA-OAEP-256")))));

        assertFailure(result, "Encrypted ID Token JWE alg header is not allowed: RSA-OAEP");
    }

    @Test
    void encryptedIdTokenWithDisallowedContentEncryptionAlgorithmIsRejected() {
        String encryptedIdToken = encryptedIdToken(signedIdToken(_ -> { }));

        var result = validate(encryptedIdToken, tenantConfig(it -> it.idToken(config -> config
                .decryptionJwk(Resource.create("oidc-next-encrypt-jwk.json"))
                .allowedContentEncryptionAlgorithms(List.of("A128CBC-HS256")))));

        assertFailure(result, "Encrypted ID Token JWE enc header is not allowed: A256GCM");
    }

    @Test
    void encryptedIdTokenRequiresKidWhenMultipleDecryptionKeysExist() {
        String encryptedIdToken = withoutJweHeaderClaim(encryptedIdToken(signedIdToken(_ -> { })),
                                                        "kid",
                                                        "encrypt-rsa");

        var result = validate(encryptedIdToken, tenantConfig(it -> it.idToken(config -> config
                .decryptionJwk(Resource.create("oidc-next-sign-jwk.json")))));

        assertFailure(result, "Encrypted ID Token JWE kid is required when multiple decryption keys exist");
    }

    @Test
    void encryptedIdTokenRejectsUnknownDecryptionKid() {
        String encryptedIdToken = replaceJweHeaderClaim(encryptedIdToken(signedIdToken(_ -> { })),
                                                        "kid",
                                                        "encrypt-rsa",
                                                        "unknown-rsa");

        var result = validate(encryptedIdToken, tenantConfig(it -> it.idToken(config -> config
                .decryptionJwk(Resource.create("oidc-next-encrypt-jwk.json")))));

        assertFailure(result, "ID Token decryption key is not configured for kid: unknown-rsa");
    }

    @Test
    void encryptedIdTokenRejectsDecryptionKeyWithSigningUse() {
        String encryptedIdToken = replaceJweHeaderClaim(encryptedIdToken(signedIdToken(_ -> { })),
                                                        "kid",
                                                        "encrypt-rsa",
                                                        "sign-rsa");

        var result = validate(encryptedIdToken, tenantConfig(it -> it.idToken(config -> config
                .decryptionJwk(Resource.create("oidc-next-sign-jwk.json")))));

        assertFailure(result, "ID Token decryption JWK use must be enc");
    }

    @Test
    void encryptedIdTokenRejectsDecryptionKeyWithoutDecryptOperation() {
        String encryptedIdToken = replaceJweHeaderClaim(encryptedIdToken(signedIdToken(_ -> { })),
                                                        "kid",
                                                        "encrypt-rsa",
                                                        "sign-oct");

        var result = validate(encryptedIdToken, tenantConfig(it -> it.idToken(config -> config
                .decryptionJwk(Resource.create("oidc-next-sign-jwk.json")))));

        assertFailure(result, "ID Token decryption JWK key_ops must allow unwrapKey or decrypt");
    }

    @Test
    void signedIdTokenIsRejectedWhenEncryptionIsRequired() {
        String idToken = signedIdToken(it -> it.email("user1@example.org"));

        var result = validate(idToken, tenantConfig(it -> it.idToken(config -> config.encryptionRequired(true))));

        assertFailure(result, "ID Token encryption is required");
    }

    @Test
    void wrongIssuerIsRejected() {
        String idToken = signedIdToken(it -> it.issuer("https://other.example"));

        var result = validate(idToken);

        assertFailure(result, "ID Token claims are invalid");
    }

    @Test
    void wrongAudienceIsRejected() {
        String idToken = signedIdToken(it -> it.audience(List.of("other-client")));

        var result = validate(idToken);

        assertFailure(result, "ID Token claims are invalid");
    }

    @Test
    void missingAudienceIsRejected() {
        String idToken = signedIdToken(false, _ -> { });

        var result = validate(idToken);

        assertFailure(result, "ID Token claims are invalid");
    }

    @Test
    void wrongNonceIsRejected() {
        String idToken = signedIdToken(it -> it.nonce("other-nonce"));

        var result = validate(idToken);

        assertFailure(result, "ID Token claims are invalid");
    }

    @Test
    void missingNonceIsRejected() {
        String idToken = signedIdToken(it -> it.nonce(null));

        var result = validate(idToken);

        assertFailure(result, "ID Token claims are invalid");
    }

    @Test
    void multipleAudiencesRequireAuthorizedParty() {
        String idToken = signedIdToken(it -> it.addAudience("other-audience"));

        var result = validate(idToken);

        assertFailure(result, "ID Token claims are invalid");
    }

    @Test
    void multipleAudiencesWithClientAuthorizedPartyAndUntrustedAudienceAreRejected() {
        String idToken = signedIdToken(it -> it.addAudience("other-audience")
                .addPayloadClaim("azp", CLIENT_ID));

        var result = validate(idToken);

        assertFailure(result, "ID Token claims are invalid");
    }

    @Test
    void multipleAudiencesWithClientAuthorizedPartyAndTrustedAudienceAreAccepted() {
        String idToken = signedIdToken(it -> it.addAudience("other-audience")
                .addPayloadClaim("azp", CLIENT_ID));

        var result = validate(idToken, tenantConfig(it -> it.idToken(idTokenConfig -> idTokenConfig
                .addTrustedAdditionalAudience("other-audience"))));

        assertThat(result.succeeded(), is(true));
    }

    @Test
    void wrongAuthorizedPartyIsRejected() {
        String idToken = signedIdToken(it -> it.addPayloadClaim("azp", "other-client"));

        var result = validate(idToken);

        assertFailure(result, "ID Token claims are invalid");
    }

    @Test
    void expiredIdTokenIsRejected() {
        Instant now = Instant.now();
        String idToken = signedIdToken(it -> it.issueTime(now.minus(2, ChronoUnit.HOURS))
                .expirationTime(now.minus(5, ChronoUnit.MINUTES)));

        var result = validate(idToken);

        assertFailure(result, "ID Token claims are invalid");
    }

    @Test
    void missingExpirationIsRejected() {
        String idToken = signedIdToken(it -> it.expirationTime(null));

        var result = validate(idToken);

        assertFailure(result, "ID Token claims are invalid");
    }

    @Test
    void missingIssueTimeIsRejected() {
        String idToken = signedIdToken(it -> it.issueTime(null));

        var result = validate(idToken);

        assertFailure(result, "ID Token claims are invalid");
    }

    @Test
    void unsupportedAlgorithmIsRejectedBeforeSignatureVerification() {
        String idToken = signedIdToken(JwkOctet.ALG_HS256, "verify-oct", "sign-oct", _ -> { });

        var result = validate(idToken);

        assertFailure(result, "ID Token JWS header is invalid");
    }

    @Test
    void noneAlgorithmIsRejectedBeforeSignatureVerification() {
        String idToken = unsignedIdToken(_ -> { });

        var result = validate(idToken);

        assertFailure(result, "ID Token JWS header is invalid");
    }

    @Test
    void invalidSignatureIsRejected() {
        String idToken = signedIdToken(_ -> { });
        int signatureStart = idToken.lastIndexOf('.') + 1;
        char replacement = idToken.charAt(signatureStart) == 'A' ? 'B' : 'A';
        String tampered = idToken.substring(0, signatureStart)
                + replacement
                + idToken.substring(signatureStart + 1);

        var result = validate(tampered);

        assertFailure(result, "ID Token signature is invalid");
    }

    @Test
    void missingSubjectIsRejected() {
        String idToken = signedIdToken(it -> it.subject(null));

        var result = validate(idToken);

        assertFailure(result, "ID Token claims are invalid");
    }

    @Test
    void blankSubjectIsRejected() {
        String idToken = signedIdToken(it -> it.subject(" "));

        var result = validate(idToken);

        assertFailure(result, "ID Token claims are invalid");
    }

    @Test
    void subjectWithMaximumAsciiLengthIsAccepted() {
        String idToken = signedIdToken(it -> it.subject("a".repeat(255)));

        var result = validate(idToken);

        assertThat(result.succeeded(), is(true));
    }

    @Test
    void tooLongSubjectIsRejected() {
        String idToken = signedIdToken(it -> it.subject("a".repeat(256)));

        var result = validate(idToken);

        assertFailure(result, "ID Token claims are invalid");
    }

    @Test
    void nonAsciiSubjectIsRejected() {
        String idToken = signedIdToken(it -> it.subject("uzivatel-\u011b"));

        var result = validate(idToken);

        assertFailure(result, "ID Token claims are invalid");
    }

    @Test
    void malformedIdTokenIsRejected() {
        var result = validate("not-a-jwt");

        assertFailure(result, "ID Token is not a valid signed or encrypted JWT");
    }

    private OidcValidationResult<OidcValidatedIdToken> validate(String idToken) {
        return validator.validate(idToken, tenantContext(), authenticationRequestState());
    }

    private OidcValidationResult<OidcValidatedIdToken> validate(String idToken, OidcTenantConfig tenantConfig) {
        return validator.validate(idToken, OidcTenantContext.ready("default", tenantConfig), authenticationRequestState());
    }

    private static OidcTenantContext tenantContext() {
        return OidcTenantContext.ready("default", tenantConfig());
    }

    private static OidcTenantConfig tenantConfig() {
        return tenantConfig(_ -> { });
    }

    private static OidcTenantConfig tenantConfig(Consumer<OidcTenantConfig.Builder> customizer) {
        OidcTenantConfig.Builder builder = OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId(CLIENT_ID)
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI)
                        .jwksUri(jwksUri)
                        .tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret(COOKIE_SECRET));
        customizer.accept(builder);
        return builder.buildPrototype();
    }

    private static String encryptedIdToken(String signedIdToken) {
        return EncryptedJwt.builder(SignedJwt.parseToken(signedIdToken))
                .jwks(encryptKeys, "encrypt-rsa")
                .build()
                .token();
    }

    private static String withoutJweHeaderClaim(String token, String name, String value) {
        String claim = "\"" + name + "\":\"" + value + "\"";
        return withJweHeader(token, json -> json
                .replace("," + claim, "")
                .replace(claim + ",", "")
                .replace(claim, ""));
    }

    private static String replaceJweHeaderClaim(String token, String name, String from, String to) {
        String claim = "\"" + name + "\":\"" + from + "\"";
        String replacement = "\"" + name + "\":\"" + to + "\"";
        return withJweHeader(token, json -> {
            if (!json.contains(claim)) {
                throw new AssertionError("JWE header did not contain expected claim: " + claim);
            }
            return json.replace(claim, replacement);
        });
    }

    private static String withJweHeader(String token, UnaryOperator<String> customizer) {
        String[] parts = token.split("\\.", -1);
        if (parts.length != 5) {
            throw new AssertionError("Expected JWE compact serialization");
        }
        String json = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
        parts[0] = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(customizer.apply(json).getBytes(StandardCharsets.UTF_8));
        return String.join(".", parts);
    }

    private static OidcAuthenticationRequestState authenticationRequestState() {
        Instant now = Instant.now();
        return new OidcAuthenticationRequestState("default",
                                                     "state-value",
                                                     NONCE,
                                                     "pkce-verifier",
                                                     ISSUER.toString(),
                                                     ORIGINAL_URI,
                                                     REDIRECTION_ENDPOINT_URI,
                                                     now.minusSeconds(1),
                                                     now.plusSeconds(300));
    }

    private static String signedIdToken(Consumer<Jwt.Builder> customizer) {
        return signedIdToken(true, customizer);
    }

    private static String signedIdToken(boolean audience, Consumer<Jwt.Builder> customizer) {
        return signedIdToken(audience, JwkRSA.ALG_RS256, "verify-rsa", "sign-rsa", customizer);
    }

    private static String signedIdToken(String algorithm,
                                        String keyId,
                                        String signingKeyId,
                                        Consumer<Jwt.Builder> customizer) {
        return signedIdToken(true, algorithm, keyId, signingKeyId, customizer);
    }

    private static String signedIdToken(boolean audience,
                                        String algorithm,
                                        String keyId,
                                        String signingKeyId,
                                        Consumer<Jwt.Builder> customizer) {
        Instant now = Instant.now();
        Jwt.Builder builder = Jwt.builder()
                .type("JWT")
                .subject(SUBJECT)
                .issuer(ISSUER.toString())
                .algorithm(algorithm)
                .keyId(keyId)
                .issueTime(now)
                .expirationTime(now.plus(1, ChronoUnit.HOURS))
                .nonce(NONCE);
        if (audience) {
            builder.addAudience(CLIENT_ID);
        }
        customizer.accept(builder);
        return SignedJwt.sign(builder.build(), signKeys.forKeyId(signingKeyId).orElseThrow())
                .tokenContent();
    }

    private static String unsignedIdToken(Consumer<Jwt.Builder> customizer) {
        Instant now = Instant.now();
        Jwt.Builder builder = Jwt.builder()
                .type("JWT")
                .subject(SUBJECT)
                .issuer(ISSUER.toString())
                .algorithm(Jwk.ALG_NONE)
                .issueTime(now)
                .expirationTime(now.plus(1, ChronoUnit.HOURS))
                .nonce(NONCE)
                .addAudience(CLIENT_ID);
        customizer.accept(builder);
        return SignedJwt.sign(builder.build(), Jwk.NONE_JWK)
                .tokenContent();
    }

    private static void assertFailure(OidcValidationResult<OidcValidatedIdToken> result, String description) {
        assertThat(result.succeeded(), is(false));
        assertThat(result.errorDescription().orElse(""), is(description));
    }
}
