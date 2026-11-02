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

import java.math.BigDecimal;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.function.UnaryOperator;

import io.helidon.common.configurable.Resource;
import io.helidon.common.configurable.ResourceConfig;
import io.helidon.json.JsonObject;
import io.helidon.security.jwt.EncryptedJwt;
import io.helidon.security.jwt.Jwt;
import io.helidon.security.jwt.SignedJwt;
import io.helidon.security.jwt.jwk.Jwk;
import io.helidon.security.jwt.jwk.JwkKeys;
import io.helidon.security.jwt.jwk.JwkOctet;
import io.helidon.security.jwt.jwk.JwkRSA;
import io.helidon.security.providers.oidc.next.spi.OidcTenantAdapter;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

/*
 * Specification excerpts below use OpenID Connect Core 1.0 incorporating errata set 2:
 * https://openid.net/specs/openid-connect-core-1_0.html
 * RFC 7519 excerpts use https://www.rfc-editor.org/rfc/rfc7519.
 * Configuration choices that go beyond a specification requirement are marked as Helidon policy.
 */
class OidcIdTokenValidatorTest {
    private static final URI ISSUER = URI.create("https://issuer.example");
    private static final URI AUTHORIZATION_ENDPOINT_URI = URI.create("https://issuer.example/authorize");
    private static final URI TOKEN_ENDPOINT_URI = URI.create("https://issuer.example/token");
    private static final URI REDIRECTION_ENDPOINT_URI = URI.create("https://rp.example/oidc/callback");
    private static final URI ORIGINAL_URI = URI.create("https://rp.example/resource");
    private static final String CLIENT_ID = "client-id";
    private static final String SUBJECT = "user1-id";
    private static final String NONCE = "nonce-value";
    private static final String COOKIE_PASSWORD = "test-cookie-password";
    private static final Instant VALIDATION_TIME = Instant.parse("2026-06-30T12:00:00Z");

    private static JwkKeys signKeys;
    private static JwkKeys encryptKeys;
    private static URI jwksUri;
    private static URI singleJwksUri;

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
                .getResource("oidc-next-verify-multiple-public-jwk.json")
                .toURI();
        singleJwksUri = OidcIdTokenValidatorTest.class.getClassLoader()
                .getResource("oidc-next-verify-public-jwk.json")
                .toURI();
    }

    // Core 3.1.3.7: "Clients MUST validate the ID Token in the Token Response".
    @Test
    void validIdTokenIsAccepted() {
        String idToken = signedIdToken(it -> it.email("user1@example.org"));

        var result = validate(idToken);

        assertThat(result.succeeded(), is(true));
        OidcValidatedIdToken validated = result.validatedToken().orElseThrow();
        assertThat(validated.rawToken(), is(idToken));
        assertThat(validated.jwt().subject().orElse(""), is(SUBJECT));
    }

    // OIDC Core 1.0 §12.2 (https://openid.net/specs/openid-connect-core-1_0.html):
    // refreshed `sub` "MUST be the same as in the ID Token issued when the original authentication occurred".
    // Vendor hooks run only *after* ordinary signature and continuity checks; the hook and its
    // vendor_status claim are Helidon extension policy, not a replacement for Core validation.
    @Test
    void tenantAdapterAddsIdTokenValidationAfterCoreAndRefreshContinuityChecks() {
        AtomicInteger checks = new AtomicInteger();
        AtomicInteger refreshChecks = new AtomicInteger();
        OidcTenantAdapter adapter = new OidcTenantAdapter() {
            @Override
            public String name() {
                return "id-token-test";
            }

            @Override
            public String type() {
                return "id-token-test";
            }

            @Override
            public void validateIdToken(OidcTenantConfig tenant, Jwt jwt, Optional<Jwt> previousIdToken) {
                checks.incrementAndGet();
                if (previousIdToken.isPresent()) {
                    assertThat(previousIdToken.orElseThrow().subject(), is(Optional.of(SUBJECT)));
                    refreshChecks.incrementAndGet();
                }
                if (!"approved".equals(jwt.payloadClaimValue("vendor_status")
                                               .map(value -> value.asString().value()).orElse(null))) {
                    throw new IllegalArgumentException("Unexpected vendor status");
                }
            }
        };
        OidcTenantConfig tenant = tenantConfig(it -> it.adapter(adapter));
        String accepted = signedIdToken(it -> it.addPayloadClaim("vendor_status", "approved"));
        OidcValidatedIdToken current = validate(accepted, tenant).validatedToken().orElseThrow();
        assertThat(checks.get(), is(1));

        assertFailure(validate(signedIdToken(_ -> { }), tenant), "ID Token is rejected by OIDC adapter");
        assertThat(checks.get(), is(2));

        int signatureStart = accepted.lastIndexOf('.') + 1;
        String tampered = accepted.substring(0, signatureStart)
                + (accepted.charAt(signatureStart) == 'A' ? 'B' : 'A')
                + accepted.substring(signatureStart + 1);
        assertFailure(validate(tampered, tenant), "ID Token signature is invalid");
        assertThat(checks.get(), is(2));

        String wrongSubject = signedIdToken(it -> it.subject("other-subject")
                .addPayloadClaim("vendor_status", "approved"));
        assertFailure(validator.validateRefresh(wrongSubject,
                                                OidcTenantContext.ready("default", tenant), current, VALIDATION_TIME),
                      "Refreshed ID Token subject does not match the existing local authentication result");
        assertThat(checks.get(), is(2));

        String refreshed = signedIdToken(it -> it.nonce(null).addPayloadClaim("vendor_status", "approved"));
        assertThat(validator.validateRefresh(refreshed,
                                             OidcTenantContext.ready("default", tenant), current, VALIDATION_TIME)
                           .succeeded(), is(true));
        assertThat(checks.get(), is(3));
        assertThat(refreshChecks.get(), is(1));
    }

    // Core 3.1.2.1: the nonce request parameter is "OPTIONAL." No nonce was requested or returned here.
    @Test
    void omittedAuthenticationRequestNonceIsValidForCodeFlow() {
        OidcAuthenticationRequestState withNoNonce = new OidcAuthenticationRequestState(
                "default", "state-value", null, "pkce-verifier", null, ISSUER.toString(),
                ORIGINAL_URI, REDIRECTION_ENDPOINT_URI, List.of("openid"), VALIDATION_TIME.minusSeconds(1),
                VALIDATION_TIME.plusSeconds(300), Optional.empty());
        OidcValidationResult<OidcValidatedIdToken> result = validator.validate(
                signedIdToken(it -> it.nonce(null)), tenantContext(), withNoNonce, VALIDATION_TIME);

        assertThat(result.succeeded(), is(true));
    }

    // Core 3.1.3.7(1): "If the ID Token is encrypted, decrypt it using the keys and algorithms".
    @Test
    void encryptedIdTokenIsDecryptedAndValidated() {
        String signedIdToken = signedIdToken(it -> it.email("user1@example.org"));
        String encryptedIdToken = encryptedIdToken(signedIdToken);

        var result = validate(encryptedIdToken, tenantConfig(it -> it.idToken(idToken -> idToken
                .decryptionJwk(ResourceConfig.builder()
                        .resourcePath("oidc-next-encrypt-jwk.json")
                        .buildPrototype()))));

        assertThat(result.succeeded(), is(true));
        OidcValidatedIdToken validated = result.validatedToken().orElseThrow();
        assertThat(validated.rawToken(), is(encryptedIdToken));
        assertThat(validated.encrypted(), is(true));
        assertThat(validated.signedJwt().tokenContent(), is(signedIdToken));
        assertThat(validated.jwt().subject().orElse(""), is(SUBJECT));
    }

    // Core 3.1.3.7(1): the RP "SHOULD reject" a signed-only token if encryption was negotiated.
    // Supplying a decryption key alone does not negotiate or require encrypted ID Tokens.
    @Test
    void signedIdTokenIsAcceptedWhenDecryptionKeyIsConfigured() {
        String idToken = signedIdToken(it -> it.email("user1@example.org"));

        var result = validate(idToken, tenantConfig(it -> it.idToken(config -> config
                .decryptionJwk(ResourceConfig.builder()
                        .resourcePath("oidc-next-encrypt-jwk.json")
                        .buildPrototype()))));

        assertThat(result.succeeded(), is(true));
        OidcValidatedIdToken validated = result.validatedToken().orElseThrow();
        assertThat(validated.rawToken(), is(idToken));
        assertThat(validated.encrypted(), is(false));
    }

    // Core 3.1.3.7(1): "If the ID Token is encrypted, decrypt it"; no decryption key was configured.
    @Test
    void encryptedIdTokenWithoutDecryptionKeyIsRejected() {
        String encryptedIdToken = encryptedIdToken(signedIdToken(_ -> { }));

        var result = validate(encryptedIdToken);

        assertFailure(result, "ID Token decryption keys are not configured");
    }

    // RFC 7519, 5.2: for a Nested JWT, "this Header Parameter MUST be present" and "the value MUST be \"JWT\"".
    @Test
    void encryptedIdTokenWithoutNestedJwtContentTypeIsRejected() {
        String encryptedIdToken = withoutJweHeaderClaim(encryptedIdToken(signedIdToken(_ -> { })), "cty", "JWT");

        var result = validate(encryptedIdToken, tenantConfig(it -> it.idToken(config -> config
                .decryptionJwk(ResourceConfig.builder()
                        .resourcePath("oidc-next-encrypt-jwk.json")
                        .buildPrototype()))));

        assertFailure(result, "Encrypted ID Token must be a Nested JWT with cty=JWT");
    }

    // Core 3.1.3.7(1): decrypt using "the keys and algorithms that the Client specified during Registration".
    @Test
    void encryptedIdTokenWithDisallowedEncryptionAlgorithmIsRejected() {
        String encryptedIdToken = encryptedIdToken(signedIdToken(_ -> { }));

        var result = validate(encryptedIdToken, tenantConfig(it -> it.idToken(config -> config
                .decryptionJwk(ResourceConfig.builder()
                        .resourcePath("oidc-next-encrypt-jwk.json")
                        .buildPrototype())
                .allowedEncryptionAlgorithms(List.of("RSA-OAEP-256")))));

        assertFailure(result, "Encrypted ID Token JWE alg header is not allowed: RSA-OAEP");
    }

    // Core 3.1.3.7(1): decrypt using "the keys and algorithms that the Client specified during Registration".
    @Test
    void encryptedIdTokenWithDisallowedContentEncryptionAlgorithmIsRejected() {
        String encryptedIdToken = encryptedIdToken(signedIdToken(_ -> { }));

        var result = validate(encryptedIdToken, tenantConfig(it -> it.idToken(config -> config
                .decryptionJwk(ResourceConfig.builder()
                        .resourcePath("oidc-next-encrypt-jwk.json")
                        .buildPrototype())
                .allowedContentEncryptionAlgorithms(List.of("A128CBC-HS256")))));

        assertFailure(result, "Encrypted ID Token JWE enc header is not allowed: A256GCM");
    }

    // Core 10.2: with multiple encryption keys, "a `kid` value MUST be provided in the JOSE Header."
    @Test
    void encryptedIdTokenRequiresKidWhenMultipleDecryptionKeysExist() {
        String encryptedIdToken = withoutJweHeaderClaim(encryptedIdToken(signedIdToken(_ -> { })),
                                                        "kid",
                                                        "encrypt-rsa");

        var result = validate(encryptedIdToken, tenantConfig(it -> it.idToken(config -> config
                .decryptionJwk(ResourceConfig.builder()
                        .resourcePath("oidc-next-sign-jwk.json")
                        .buildPrototype()))));

        assertFailure(result, "Encrypted ID Token JWE kid is required when multiple decryption keys exist");
    }

    // Core 3.1.3.7(1): decrypt using "the keys and algorithms that the Client specified during Registration";
    // an unknown kid cannot select one of the configured decryption keys.
    @Test
    void encryptedIdTokenRejectsUnknownDecryptionKid() {
        String encryptedIdToken = replaceJweHeaderClaim(encryptedIdToken(signedIdToken(_ -> { })),
                                                        "kid",
                                                        "encrypt-rsa",
                                                        "unknown-rsa");

        var result = validate(encryptedIdToken, tenantConfig(it -> it.idToken(config -> config
                .decryptionJwk(ResourceConfig.builder()
                        .resourcePath("oidc-next-encrypt-jwk.json")
                        .buildPrototype()))));

        assertFailure(result, "ID Token decryption key is not configured for kid: unknown-rsa");
    }

    // Core 10.2: "The key usage of the respective keys MUST include encryption."
    @Test
    void encryptedIdTokenRejectsDecryptionKeyWithSigningUse() {
        String encryptedIdToken = replaceJweHeaderClaim(encryptedIdToken(signedIdToken(_ -> { })),
                                                        "kid",
                                                        "encrypt-rsa",
                                                        "sign-rsa");

        var result = validate(encryptedIdToken, tenantConfig(it -> it.idToken(config -> config
                .decryptionJwk(ResourceConfig.builder()
                        .resourcePath("oidc-next-sign-jwk.json")
                        .buildPrototype()))));

        assertFailure(result, "ID Token decryption JWK use must be enc");
    }

    // RFC 7517 section 4.3: key_ops identifies "the operation(s) for which the key is intended to be used";
    // an explicitly sign-only key cannot be selected for unwrapKey/decrypt.
    @Test
    void encryptedIdTokenRejectsDecryptionKeyWithoutDecryptOperation() {
        String encryptedIdToken = replaceJweHeaderClaim(encryptedIdToken(signedIdToken(_ -> { })),
                                                        "kid",
                                                        "encrypt-rsa",
                                                        "sign-oct");

        var result = validate(encryptedIdToken, tenantConfig(it -> it.idToken(config -> config
                .decryptionJwk(ResourceConfig.builder()
                        .resourcePath("oidc-next-sign-jwk.json")
                        .buildPrototype()))));

        assertFailure(result, "ID Token decryption JWK key_ops must allow unwrapKey or decrypt");
    }

    // Core 3.1.3.7(1): an unencrypted token after negotiating encryption is a SHOULD-reject;
    // requiring encryption explicitly here makes rejection Helidon policy, not an unconditional Core MUST.
    @Test
    void signedIdTokenIsRejectedWhenEncryptionIsRequired() {
        String idToken = signedIdToken(it -> it.email("user1@example.org"));

        var result = validate(idToken, tenantConfig(it -> it.idToken(config -> config.encryptionRequired(true)
                .decryptionJwk(ResourceConfig.builder()
                        .resourcePath("oidc-next-encrypt-jwk.json")
                        .buildPrototype()))));

        assertFailure(result, "ID Token encryption is required");
    }

    // Core 3.1.3.7(2): the Issuer Identifier "MUST exactly match the value of the `iss` (issuer) Claim."
    @Test
    void wrongIssuerIsRejected() {
        String idToken = signedIdToken(it -> it.issuer("https://other.example"));

        var result = validate(idToken);

        assertFailure(result, "ID Token claims are invalid");
    }

    // Core 3.1.3.7(2): the OP issuer "MUST exactly match the value of the `iss` (issuer) Claim";
    // configuring a different issuer for an API's access tokens must not change ID Token trust.
    @Test
    void separateApiIssuerNeverChangesIdTokenIssuerTrust() {
        String apiIssuer = "https://api-issuer.example";
        OidcTenantConfig tenant = tenantConfig(builder -> builder.protectedResource(resource -> resource
                .tokenValidation(validation -> validation.method(OidcTokenValidationMethod.JWT)
                        .audience("api://orders")
                        .issuer(apiIssuer)
                        .jwksUri(URI.create(apiIssuer + "/jwks")))));

        assertThat(validate(signedIdToken(_ -> { }), tenant).succeeded(), is(true));
        assertFailure(validate(signedIdToken(jwt -> jwt.issuer(apiIssuer)), tenant), "ID Token claims are invalid");
    }

    // Core 3.1.3.7(3): the ID Token "MUST be rejected if the ID Token does not list the Client as a valid audience".
    @Test
    void wrongAudienceIsRejected() {
        String idToken = signedIdToken(it -> it.audience(List.of("other-client")));

        var result = validate(idToken);

        assertFailure(result, "ID Token claims are invalid");
    }

    // Core 2: the `aud` claim is "REQUIRED. Audience(s) that this ID Token is intended for."
    @Test
    void missingAudienceIsRejected() {
        String idToken = signedIdToken(false, _ -> { });

        var result = validate(idToken);

        assertFailure(result, "ID Token claims are invalid");
    }

    // Core 3.1.3.7(11): a requested nonce's "value checked to verify that it is the same value".
    @Test
    void wrongNonceIsRejected() {
        String idToken = signedIdToken(it -> it.nonce("other-nonce"));

        var result = validate(idToken);

        assertFailure(result, "ID Token claims are invalid");
    }

    // Core 3.1.3.7(11): "a `nonce` Claim MUST be present" if sent in the Authentication Request.
    @Test
    void missingNonceIsRejected() {
        String idToken = signedIdToken(it -> it.nonce(null));

        var result = validate(idToken);

        assertFailure(result, "ID Token claims are invalid");
    }

    // Core section 2 (`azp`): "OPTIONAL. Authorized party - the party to which the ID Token was issued."
    // Requiring it for multiple trusted audiences is stricter Helidon policy, not an unconditional OIDC requirement.
    @Test
    void multipleAudiencesRequireAuthorizedParty() {
        String idToken = signedIdToken(it -> it.addAudience("other-audience"));
        OidcTenantConfig tenant = tenantConfig(it -> it.idToken(idTokenConfig -> idTokenConfig
                .addTrustedAdditionalAudience("other-audience")));

        var result = validate(idToken, tenant);

        assertFailure(result, "ID Token claims are invalid");
    }

    /*
     * Spec: OpenID Connect Core 1.0, 3.1.3.7(3), ID Token Validation.
     * https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
     * Quote: "or if it contains additional audiences not trusted by the Client."
     */
    @Test
    void multipleAudiencesWithClientAuthorizedPartyAndUntrustedAudienceAreRejected() {
        String idToken = signedIdToken(it -> it.addAudience("other-audience")
                .addPayloadClaim("azp", CLIENT_ID));

        var result = validate(idToken);

        assertFailure(result, "ID Token claims are invalid");
    }

    // Core 3.1.3.7(3): "The `aud` (audience) Claim MAY contain an array with more than one element."
    // Each additional audience here is trusted explicitly; an untrusted third audience must still fail.
    @Test
    void multipleAudiencesWithClientAuthorizedPartyAndTrustedAudienceAreAccepted() {
        String idToken = signedIdToken(it -> it.addAudience("other-audience")
                .addPayloadClaim("azp", CLIENT_ID));

        OidcTenantConfig tenant = tenantConfig(it -> it.idToken(idTokenConfig -> idTokenConfig
                .addTrustedAdditionalAudience("other-audience")));
        var result = validate(idToken, tenant);

        assertThat(result.succeeded(), is(true));

        String untrusted = signedIdToken(it -> it.addAudience("other-audience")
                .addAudience("third-audience")
                .addPayloadClaim("azp", CLIENT_ID));
        assertFailure(validate(untrusted, tenant), "ID Token claims are invalid");
    }

    /*
     * Spec: OpenID Connect Core 1.0, 12.2, Successful Refresh Response.
     * https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse
     * Quote: "its `aud` Claim Value MUST be the same as in the ID Token issued when the original authentication occurred,"
     */
    @Test
    void refreshedAudienceMustMatchEvenWhenAdditionalAudienceIsTrusted() {
        OidcTenantConfig tenant = tenantConfig(it -> it.idToken(idTokenConfig -> idTokenConfig
                .addTrustedAdditionalAudience("other-audience")));
        OidcValidatedIdToken current = validate(signedIdToken(_ -> { }), tenant).validatedToken().orElseThrow();
        String refreshed = signedIdToken(it -> it.nonce(null)
                .addAudience("other-audience")
                .addPayloadClaim("azp", CLIENT_ID));

        assertFailure(validator.validateRefresh(refreshed,
                                               OidcTenantContext.ready("default", tenant), current, VALIDATION_TIME),
                      "Refreshed ID Token audience does not match the existing local authentication result");
    }

    // Core 3.1.3.7(5): for a present `azp`, "the Client SHOULD verify that its `client_id` is the Claim Value."
    @Test
    void wrongAuthorizedPartyIsRejected() {
        String idToken = signedIdToken(it -> it.addPayloadClaim("azp", "other-client"));

        var result = validate(idToken);

        assertFailure(result, "ID Token claims are invalid");
    }

    // Core 2: "The `azp` value is a case-sensitive string containing a StringOrURI value."
    // Requiring the present value to be nonblank and identify this client is Helidon's stricter policy.
    @Test
    void presentAuthorizedPartyMustBeANonblankString() {
        for (Object value : List.of(42, true, List.of(CLIENT_ID), Map.of("client_id", CLIENT_ID), "", " \t")) {
            String idToken = signedIdToken(it -> it.addPayloadClaim("azp", value));

            assertThat("azp=" + value, validate(idToken).errorDescription().orElse(""),
                       is("ID Token claims are invalid"));
        }

        OidcTenantConfig multiAudienceTenant = tenantConfig(it -> it.idToken(idToken -> idToken
                .addTrustedAdditionalAudience("other-audience")));
        String multiAudience = signedIdToken(it -> it.addAudience("other-audience")
                .addPayloadClaim("azp", List.of(CLIENT_ID)));

        assertFailure(validate(multiAudience, multiAudienceTenant), "ID Token claims are invalid");
    }

    // Core 3.1.3.7(10): for `iat`, "The acceptable range is Client specific." Here it is the configured skew.
    @Test
    void issueTimeRespectsConfiguredClockSkew() {
        OidcTenantConfig tenant = tenantConfig(it -> it.idToken(idToken -> idToken.clockSkew(Duration.ofSeconds(30))));

        assertThat(validate(signedIdToken(it -> it.issueTime(VALIDATION_TIME.plusSeconds(30))), tenant).succeeded(),
                   is(true));
        assertFailure(validate(signedIdToken(it -> it.issueTime(VALIDATION_TIME.plusSeconds(31))), tenant),
                      "ID Token claims are invalid");
    }

    // RFC 7519, 4.1.5: for `nbf`, "Implementers MAY provide for some small leeway" for clock skew.
    @Test
    void notBeforeRespectsConfiguredClockSkew() {
        OidcTenantConfig tenant = tenantConfig(it -> it.idToken(idToken -> idToken.clockSkew(Duration.ofSeconds(30))));

        assertThat(validate(signedIdToken(it -> it.notBefore(VALIDATION_TIME.plusSeconds(30))), tenant).succeeded(),
                   is(true));
        assertFailure(validate(signedIdToken(it -> it.notBefore(VALIDATION_TIME.plusSeconds(31))), tenant),
                      "ID Token claims are invalid");
    }

    // Core 2: for `exp`, "Implementers MAY provide for some small leeway" to account for clock skew.
    @Test
    void expirationRespectsConfiguredClockSkew() {
        OidcTenantConfig tenant = tenantConfig(it -> it.idToken(idToken -> idToken.clockSkew(Duration.ofSeconds(30))));

        assertThat(validate(signedIdToken(it -> it.issueTime(VALIDATION_TIME.minusSeconds(60))
                           .expirationTime(VALIDATION_TIME.minusSeconds(29))), tenant).succeeded(),
                   is(true));
        assertFailure(validate(signedIdToken(it -> it.issueTime(VALIDATION_TIME.minusSeconds(60))
                               .expirationTime(VALIDATION_TIME.minusSeconds(30))), tenant),
                      "ID Token claims are invalid");
        assertFailure(validate(signedIdToken(it -> it.issueTime(VALIDATION_TIME.minusSeconds(60))
                               .expirationTime(VALIDATION_TIME.minusSeconds(31))), tenant),
                      "ID Token claims are invalid");
    }

    // Core 3.1.3.7(9): "The current time MUST be before the time represented by the `exp` Claim."
    @Test
    void expirationAtValidationTimeIsRejectedWithZeroClockSkew() {
        OidcTenantConfig tenant = tenantConfig(it -> it.idToken(idToken -> idToken.clockSkew(Duration.ZERO)));
        String idToken = signedIdToken(it -> it.issueTime(VALIDATION_TIME.minusSeconds(60))
                .expirationTime(VALIDATION_TIME));

        assertFailure(validate(idToken, tenant), "ID Token claims are invalid");
    }

    // RFC 7519, 2 and 4.1.5: "non-integer values can be represented" and `nbf` is a not-before boundary.
    @Test
    void fractionalNotBeforeDoesNotAllowEarlyIdTokenAuthentication() {
        OidcTenantContext context = OidcTenantContext.ready("default", tenantConfig(
                tenant -> tenant.idToken(idToken -> idToken.clockSkew(Duration.ZERO))));
        String token = signedIdTokenWithFractionalClaim("nbf");
        Instant boundary = VALIDATION_TIME.plusMillis(750);

        assertFailure(validator.validate(token, context, authenticationRequestState(), VALIDATION_TIME.plusMillis(500)),
                      "ID Token claims are invalid");
        OidcValidationResult<OidcValidatedIdToken> accepted =
                validator.validate(token, context, authenticationRequestState(), boundary);
        assertThat(accepted.succeeded(), is(true));
        assertThat(accepted.validatedToken().orElseThrow().jwt().notBefore().orElseThrow(), is(boundary));
    }

    // RFC 7519, 2: NumericDate permits that "non-integer values can be represented"; `iat` range is RP policy.
    @Test
    void fractionalIssueTimeDoesNotAllowEarlyIdTokenAuthentication() {
        OidcTenantContext context = OidcTenantContext.ready("default", tenantConfig(
                tenant -> tenant.idToken(idToken -> idToken.clockSkew(Duration.ZERO))));
        String token = signedIdTokenWithFractionalClaim("iat");
        Instant boundary = VALIDATION_TIME.plusMillis(750);

        assertFailure(validator.validate(token, context, authenticationRequestState(), VALIDATION_TIME.plusMillis(500)),
                      "ID Token claims are invalid");
        OidcValidationResult<OidcValidatedIdToken> accepted =
                validator.validate(token, context, authenticationRequestState(), boundary);
        assertThat(accepted.succeeded(), is(true));
        assertThat(accepted.validatedToken().orElseThrow().jwt().issueTime().orElseThrow(), is(boundary));
    }

    // RFC 7519, 2: "non-integer values can be represented"; Core 3.1.3.7(9) requires time before `exp`.
    @Test
    void fractionalExpirationAllowsAuthenticationUntilTheExactTime() {
        OidcTenantContext context = OidcTenantContext.ready("default", tenantConfig(
                tenant -> tenant.idToken(idToken -> idToken.clockSkew(Duration.ZERO))));
        String token = signedIdTokenWithFractionalClaim("exp");
        Instant boundary = VALIDATION_TIME.plusMillis(750);

        OidcValidationResult<OidcValidatedIdToken> accepted =
                validator.validate(token, context, authenticationRequestState(), VALIDATION_TIME.plusMillis(500));
        assertThat(accepted.succeeded(), is(true));
        assertThat(accepted.validatedToken().orElseThrow().jwt().expirationTime().orElseThrow(), is(boundary));
        assertFailure(validator.validate(token, context, authenticationRequestState(), boundary),
                      "ID Token claims are invalid");
    }

    // Core 2: an expired ID Token "MUST NOT be accepted by the RP when performing authentication".
    @Test
    void expiredIdTokenIsRejected() {
        String idToken = signedIdToken(it -> it.issueTime(VALIDATION_TIME.minus(2, ChronoUnit.HOURS))
                .expirationTime(VALIDATION_TIME.minus(5, ChronoUnit.MINUTES)));

        var result = validate(idToken);

        assertFailure(result, "ID Token claims are invalid");
    }

    // Core 3.1.3.7(9): "The current time MUST be before the time represented by the `exp` Claim."
    @Test
    void suppliedValidationTimeDeterminesTokenExpiration() {
        String idToken = signedIdToken(_ -> { });

        var result = validator.validate(idToken,
                                        tenantContext(),
                                        authenticationRequestState(),
                                        VALIDATION_TIME.plus(2, ChronoUnit.HOURS));

        assertFailure(result, "ID Token claims are invalid");
    }

    // Core 2: the `exp` Claim is "REQUIRED. Expiration time".
    @Test
    void missingExpirationIsRejected() {
        String idToken = signedIdToken(it -> it.expirationTime(null));

        var result = validate(idToken);

        assertFailure(result, "ID Token claims are invalid");
    }

    // Core 2: the `iat` Claim is "REQUIRED. Time at which the JWT was issued."
    @Test
    void missingIssueTimeIsRejected() {
        String idToken = signedIdToken(it -> it.issueTime(null));

        var result = validate(idToken);

        assertFailure(result, "ID Token claims are invalid");
    }

    // Helidon policy: use only registered/allowed ID Token algorithms (Core 3.1.3.7(7): "SHOULD" use RS256
    // or the algorithm selected during registration), before trying keys or verifying a signature.
    @Test
    void unsupportedAlgorithmIsRejectedBeforeSignatureVerification() {
        String idToken = signedIdToken(JwkOctet.ALG_HS256, "verify-oct", "sign-oct", _ -> { });

        var result = validate(idToken);

        assertFailure(result, "ID Token JWS header is invalid");
    }

    // RFC 7517, 4.4 (https://www.rfc-editor.org/rfc/rfc7517#section-4.4), JWK `alg`:
    // "Use of this member is OPTIONAL."
    @Test
    void rsaJwkWithoutDeclaredAlgorithmUsesRegisteredIdTokenAlgorithm() {
        for (String algorithm : List.of("RS384", "RS512")) {
            String idToken = signedIdToken(algorithm, null, "sign-rsa", _ -> { });
            OidcTenantConfig tenantConfig = tenantConfig(singleJwksUri,
                                                         tenant -> tenant.idToken(idTokenConfig -> idTokenConfig
                                                                 .allowedAlgorithms(List.of(algorithm))));

            OidcValidationResult<OidcValidatedIdToken> result = validate(idToken, tenantConfig);

            assertThat(result.succeeded(), is(true));
            // An additional encryption-use JWK cannot verify the signature and does not make key selection ambiguous.
            assertThat(validate(idToken,
                                tenantConfig(jwksUri,
                                             tenant -> tenant.idToken(idTokenConfig -> idTokenConfig
                                                     .allowedAlgorithms(List.of(algorithm))))).succeeded(),
                       is(true));
        }
    }

    // Helidon policy: reject unsigned ID Tokens by default. Core 3.1.3.7(6) allows TLS server validation
    // in lieu of an ID Token signature for direct code-flow token responses; this is not a general Core MUST-reject.
    @Test
    void noneAlgorithmIsRejectedBeforeSignatureVerification() {
        String idToken = unsignedIdToken(_ -> { });

        var result = validate(idToken);

        assertFailure(result, "ID Token JWS header is invalid");
    }

    // Helidon policy: also verify code-flow ID Token signatures when Core 3.1.3.7(6) permits TLS validation instead.
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

    // Core 2: `sub` is a "REQUIRED. Subject Identifier."
    @Test
    void missingSubjectIsRejected() {
        String idToken = signedIdToken(it -> it.subject(null));

        var result = validate(idToken);

        assertFailure(result, "ID Token claims are invalid");
    }

    // Core 2: `sub` is a "REQUIRED. Subject Identifier." A blank identifier cannot identify this end-user.
    @Test
    void blankSubjectIsRejected() {
        String idToken = signedIdToken(it -> it.subject(" "));

        var result = validate(idToken);

        assertFailure(result, "ID Token claims are invalid");
    }

    // Core 2: `sub` "MUST NOT exceed 255 ASCII characters in length."
    @Test
    void subjectWithMaximumAsciiLengthIsAccepted() {
        String idToken = signedIdToken(it -> it.subject("a".repeat(255)));

        var result = validate(idToken);

        assertThat(result.succeeded(), is(true));
    }

    // Core 2: `sub` "MUST NOT exceed 255 ASCII characters in length."
    @Test
    void tooLongSubjectIsRejected() {
        String idToken = signedIdToken(it -> it.subject("a".repeat(256)));

        var result = validate(idToken);

        assertFailure(result, "ID Token claims are invalid");
    }

    // Core 2: `sub` is bounded by "255 ASCII characters in length"; Helidon applies an ASCII-only policy.
    @Test
    void nonAsciiSubjectIsRejected() {
        String idToken = signedIdToken(it -> it.subject("uzivatel-\u011b"));

        var result = validate(idToken);

        assertFailure(result, "ID Token claims are invalid");
    }

    // Core 2: "The ID Token is represented as a JSON Web Token (JWT)".
    @Test
    void malformedIdTokenIsRejected() {
        var result = validate("not-a-jwt");

        assertFailure(result, "ID Token is not a valid signed or encrypted JWT");
    }

    private static OidcTenantContext tenantContext() {
        return OidcTenantContext.ready("default", tenantConfig());
    }

    private static OidcTenantConfig tenantConfig() {
        return tenantConfig(_ -> { });
    }

    private static OidcTenantConfig tenantConfig(Consumer<OidcTenantConfig.Builder> customizer) {
        return tenantConfig(jwksUri, customizer);
    }

    private static OidcTenantConfig tenantConfig(URI verificationJwksUri,
                                                  Consumer<OidcTenantConfig.Builder> customizer) {
        OidcTenantConfig.Builder builder = OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId(CLIENT_ID)
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI)
                        .jwksUri(verificationJwksUri)
                        .tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.password(COOKIE_PASSWORD));
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
        return new OidcAuthenticationRequestState("default",
                                                     "state-value",
                                                     NONCE,
                                                     "pkce-verifier",
                                                     null,
                                                     ISSUER.toString(),
                                                     ORIGINAL_URI,
                                                     REDIRECTION_ENDPOINT_URI,
                                                     List.of("openid"),
                                                     VALIDATION_TIME.minusSeconds(1),
                                                     VALIDATION_TIME.plusSeconds(300), Optional.empty());
    }

    private static String signedIdToken(Consumer<Jwt.Builder> customizer) {
        return signedIdToken(true, customizer);
    }

    private static String signedIdTokenWithFractionalClaim(String claim) {
        Jwt jwt = SignedJwt.parseToken(signedIdToken(it -> it.issueTime(VALIDATION_TIME.minusSeconds(60)))).getJwt();
        // The JWT builder serializes Instants as whole seconds; sign an explicit fractional JSON number from an OP.
        JsonObject payload = JsonObject.builder().from(jwt.payloadJsonObject())
                .set(claim, new BigDecimal(VALIDATION_TIME.getEpochSecond() + ".75"))
                .build();
        return SignedJwt.sign(jwt.headers(), payload, signKeys.forKeyId("sign-rsa").orElseThrow()).tokenContent();
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
        Jwt.Builder builder = Jwt.builder()
                .type("JWT")
                .subject(SUBJECT)
                .issuer(ISSUER.toString())
                .algorithm(algorithm)
                .issueTime(VALIDATION_TIME)
                .expirationTime(VALIDATION_TIME.plus(1, ChronoUnit.HOURS))
                .nonce(NONCE);
        if (keyId != null) {
            builder.keyId(keyId);
        }
        if (audience) {
            builder.addAudience(CLIENT_ID);
        }
        customizer.accept(builder);
        Jwk signingKey = OidcJoseKeyPolicy.signingKey(signKeys.forKeyId(signingKeyId).orElseThrow(),
                                                      Optional.of(algorithm),
                                                      "test signing JWK");
        return SignedJwt.sign(builder.build(), signingKey)
                .tokenContent();
    }

    private static String unsignedIdToken(Consumer<Jwt.Builder> customizer) {
        Jwt.Builder builder = Jwt.builder()
                .type("JWT")
                .subject(SUBJECT)
                .issuer(ISSUER.toString())
                .algorithm(Jwk.ALG_NONE)
                .issueTime(VALIDATION_TIME)
                .expirationTime(VALIDATION_TIME.plus(1, ChronoUnit.HOURS))
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

    private OidcValidationResult<OidcValidatedIdToken> validate(String idToken) {
        return validator.validate(idToken, tenantContext(), authenticationRequestState(), VALIDATION_TIME);
    }

    private OidcValidationResult<OidcValidatedIdToken> validate(String idToken, OidcTenantConfig tenantConfig) {
        return validator.validate(idToken,
                                  OidcTenantContext.ready("default", tenantConfig),
                                  authenticationRequestState(),
                                  VALIDATION_TIME);
    }
}
