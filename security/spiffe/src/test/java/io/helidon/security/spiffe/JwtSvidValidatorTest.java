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

package io.helidon.security.spiffe;

import java.io.StringReader;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import io.helidon.json.JsonObject;
import io.helidon.json.JsonParser;
import io.helidon.security.jwt.Jwt;
import io.helidon.security.jwt.SignedJwt;
import io.helidon.security.jwt.jwk.JwkEC;
import io.helidon.security.jwt.jwk.JwkKeys;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

class JwtSvidValidatorTest {
    private static final SpiffeTrustDomain TRUST_DOMAIN = SpiffeTrustDomain.create("example.org");
    private static final String AUDIENCE = "https://issuer.example/token";
    private static final Instant NOW = Instant.parse("2026-06-10T10:15:30Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

    @Test
    void shouldValidateJwtSvid() {
        JwtSvidValidator validator = validator(AUDIENCE);
        String token = token("spiffe://example.org/ns/backend/sa/orders", AUDIENCE, NOW.plusSeconds(300));

        SpiffeValidationResult<JwtSvid> result = validator.validate(token);

        assertThat(result.isValid(), is(true));
        assertThat(result.svid().orElseThrow().spiffeId(),
                   is(SpiffeId.parse("spiffe://example.org/ns/backend/sa/orders")));
    }

    @Test
    void shouldRejectUnexpectedAudience() {
        JwtSvidValidator validator = validator(AUDIENCE);
        String token = token("spiffe://example.org/ns/backend/sa/orders", "https://other.example/token", NOW.plusSeconds(300));

        SpiffeValidationResult<JwtSvid> result = validator.validate(token);

        assertThat(result.isValid(), is(false));
        assertThat(result.failureMessage().orElseThrow(), containsString("expected audience"));
    }

    @Test
    void shouldRejectExpiredToken() {
        JwtSvidValidator validator = validator(AUDIENCE);
        String token = token("spiffe://example.org/ns/backend/sa/orders", AUDIENCE, NOW.minusSeconds(1));

        SpiffeValidationResult<JwtSvid> result = validator.validate(token);

        assertThat(result.isValid(), is(false));
        assertThat(result.failureMessage().orElseThrow(), is("JWT-SVID is expired"));
    }

    @Test
    void shouldRejectSubjectOutsideMatcher() {
        JwtSvidValidator validator = validator(AUDIENCE);
        String token = token("spiffe://example.org/ns/frontend/sa/web", AUDIENCE, NOW.plusSeconds(300));

        SpiffeValidationResult<JwtSvid> result = validator.validate(token);

        assertThat(result.isValid(), is(false));
        assertThat(result.failureMessage().orElseThrow(), containsString("subject is not accepted"));
    }

    private static JwtSvidValidator validator(String audience) {
        SpiffeBundle bundle = SpiffeBundleLoader.load(TRUST_DOMAIN, json(TestKeys.PUBLIC_SPIFFE_BUNDLE));
        return JwtSvidValidator.builder()
                .bundleSource(SpiffeBundleSource.fixed(bundle))
                .addAudience(audience)
                .addSubjectMatcher(SpiffeIdMatcher.startsWith(SpiffeId.parse("spiffe://example.org/ns/backend")))
                .clock(CLOCK)
                .build();
    }

    private static String token(String subject, String audience, Instant expiresAt) {
        Jwt jwt = Jwt.builder()
                .algorithm(JwkEC.ALG_ES256)
                .keyId(TestKeys.KEY_ID)
                .subject(subject)
                .addAudience(audience)
                .expirationTime(expiresAt)
                .issueTime(NOW)
                .build();
        return SignedJwt.sign(jwt, JwkKeys.create(json(TestKeys.PRIVATE_SIGNING_JWK))).tokenContent();
    }

    private static JsonObject json(String content) {
        return JsonParser.create(new StringReader(content)).readJsonObject();
    }
}
