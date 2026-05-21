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
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.function.Consumer;

import io.helidon.common.configurable.Resource;
import io.helidon.security.jwt.Jwt;
import io.helidon.security.jwt.SignedJwt;
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
    private static URI jwksUri;

    private final OidcIdTokenValidator validator = OidcIdTokenValidator.create();

    @BeforeAll
    static void initClass() throws Exception {
        signKeys = JwkKeys.builder()
                .resource(Resource.create("oidc-next-sign-jwk.json"))
                .build();
        jwksUri = OidcIdTokenValidatorTest.class.getClassLoader()
                .getResource("oidc-next-verify-jwk.json")
                .toURI();
    }

    @Test
    void validIdTokenIsAccepted() {
        String idToken = signedIdToken(it -> it.email("user1@example.org"));

        OidcIdTokenValidationResult result = validate(idToken);

        assertThat(result.succeeded(), is(true));
        OidcValidatedIdToken validated = result.validatedToken().orElseThrow();
        assertThat(validated.rawToken(), is(idToken));
        assertThat(validated.jwt().subject().orElse(""), is(SUBJECT));
    }

    @Test
    void wrongIssuerIsRejected() {
        String idToken = signedIdToken(it -> it.issuer("https://other.example"));

        OidcIdTokenValidationResult result = validate(idToken);

        assertFailure(result, "ID Token claims are invalid");
    }

    @Test
    void wrongAudienceIsRejected() {
        String idToken = signedIdToken(it -> it.audience(List.of("other-client")));

        OidcIdTokenValidationResult result = validate(idToken);

        assertFailure(result, "ID Token claims are invalid");
    }

    @Test
    void missingAudienceIsRejected() {
        String idToken = signedIdToken(false, it -> { });

        OidcIdTokenValidationResult result = validate(idToken);

        assertFailure(result, "ID Token claims are invalid");
    }

    @Test
    void wrongNonceIsRejected() {
        String idToken = signedIdToken(it -> it.nonce("other-nonce"));

        OidcIdTokenValidationResult result = validate(idToken);

        assertFailure(result, "ID Token claims are invalid");
    }

    @Test
    void missingNonceIsRejected() {
        String idToken = signedIdToken(it -> it.nonce(null));

        OidcIdTokenValidationResult result = validate(idToken);

        assertFailure(result, "ID Token claims are invalid");
    }

    @Test
    void multipleAudiencesRequireAuthorizedParty() {
        String idToken = signedIdToken(it -> it.addAudience("other-audience"));

        OidcIdTokenValidationResult result = validate(idToken);

        assertFailure(result, "ID Token claims are invalid");
    }

    @Test
    void multipleAudiencesWithClientAuthorizedPartyAreAccepted() {
        String idToken = signedIdToken(it -> it.addAudience("other-audience")
                .addPayloadClaim("azp", CLIENT_ID));

        OidcIdTokenValidationResult result = validate(idToken);

        assertThat(result.succeeded(), is(true));
    }

    @Test
    void wrongAuthorizedPartyIsRejected() {
        String idToken = signedIdToken(it -> it.addPayloadClaim("azp", "other-client"));

        OidcIdTokenValidationResult result = validate(idToken);

        assertFailure(result, "ID Token claims are invalid");
    }

    @Test
    void expiredIdTokenIsRejected() {
        Instant now = Instant.now();
        String idToken = signedIdToken(it -> it.issueTime(now.minus(2, ChronoUnit.HOURS))
                .expirationTime(now.minus(5, ChronoUnit.MINUTES)));

        OidcIdTokenValidationResult result = validate(idToken);

        assertFailure(result, "ID Token claims are invalid");
    }

    @Test
    void missingExpirationIsRejected() {
        String idToken = signedIdToken(it -> it.expirationTime(null));

        OidcIdTokenValidationResult result = validate(idToken);

        assertFailure(result, "ID Token claims are invalid");
    }

    @Test
    void unsupportedAlgorithmIsRejectedBeforeSignatureVerification() {
        String idToken = signedIdToken(JwkOctet.ALG_HS256, "verify-oct", "sign-oct", it -> { });

        OidcIdTokenValidationResult result = validate(idToken);

        assertFailure(result, "ID Token JWS header is invalid");
    }

    @Test
    void invalidSignatureIsRejected() {
        String idToken = signedIdToken(it -> { });
        int signatureStart = idToken.lastIndexOf('.') + 1;
        char replacement = idToken.charAt(signatureStart) == 'A' ? 'B' : 'A';
        String tampered = idToken.substring(0, signatureStart)
                + replacement
                + idToken.substring(signatureStart + 1);

        OidcIdTokenValidationResult result = validate(tampered);

        assertFailure(result, "ID Token signature is invalid");
    }

    @Test
    void missingSubjectIsRejected() {
        String idToken = signedIdToken(it -> it.subject(null));

        OidcIdTokenValidationResult result = validate(idToken);

        assertFailure(result, "ID Token claims are invalid");
    }

    @Test
    void blankSubjectIsRejected() {
        String idToken = signedIdToken(it -> it.subject(" "));

        OidcIdTokenValidationResult result = validate(idToken);

        assertFailure(result, "ID Token claims are invalid");
    }

    @Test
    void malformedIdTokenIsRejected() {
        OidcIdTokenValidationResult result = validate("not-a-jwt");

        assertFailure(result, "ID Token is not a valid signed JWT");
    }

    private OidcIdTokenValidationResult validate(String idToken) {
        return validator.validate(idToken, tenantContext(), authenticationRequestState());
    }

    private static OidcTenantContext tenantContext() {
        return OidcTenantContext.ready("default", tenantConfig());
    }

    private static OidcTenantConfig tenantConfig() {
        return OidcTenantConfig.builder()
                .issuer(ISSUER)
                .clientId(CLIENT_ID)
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI)
                        .jwksUri(jwksUri)
                        .tlsRequired(false))
                .authorizationCode(it -> it.enabled(true)
                        .redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret(COOKIE_SECRET))
                .buildPrototype();
    }

    private static OidcAuthenticationRequestState authenticationRequestState() {
        Instant now = Instant.now();
        return OidcAuthenticationRequestState.create("default",
                                                     "state-value",
                                                     NONCE,
                                                     "pkce-verifier",
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

    private static void assertFailure(OidcIdTokenValidationResult result, String description) {
        assertThat(result.succeeded(), is(false));
        assertThat(result.errorDescription().orElse(""), is(description));
    }
}
