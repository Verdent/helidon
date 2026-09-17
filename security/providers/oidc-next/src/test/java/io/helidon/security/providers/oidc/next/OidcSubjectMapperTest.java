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

import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;

import io.helidon.json.JsonObject;
import io.helidon.security.jwt.Jwt;
import io.helidon.security.jwt.SignedJwt;
import io.helidon.security.jwt.jwk.Jwk;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;

class OidcSubjectMapperTest {
    private static final String ISSUER = "https://issuer.example";
    private static final OidcSubjectMappingConfig DEFAULT_MAPPING = OidcSubjectMappingConfig.create();

    @Test
    void browserAndBearerUseTheSameIssuerSubjectIdentity() {
        Jwt jwt = claims(ISSUER, "123");

        String browserId = OidcSubjectMapper.localPrincipalId(jwt).orElseThrow();
        String bearerId = OidcSubjectMapper.principalId(jwt, DEFAULT_MAPPING).orElseThrow();

        assertThat(browserId, is(OidcTestIdentities.issuerSubject(ISSUER, "123")));
        assertThat(bearerId, is(browserId));
        assertThat(jwt.issuer().orElseThrow(), is(ISSUER));
        assertThat(jwt.subject().orElseThrow(), is("123"));
    }

    @Test
    void equalSubjectsFromDifferentIssuersRemainDifferentIdentities() {
        String first = principalId(claims("https://first.example", "123"));
        String second = principalId(claims("https://second.example", "123"));

        assertThat(second, not(first));
    }

    @Test
    void issuerSpellingIsNotNormalized() {
        List<String> issuers = List.of(ISSUER,
                                       ISSUER + "/",
                                       "https://ISSUER.example",
                                       ISSUER + ":443",
                                       ISSUER + "/a",
                                       ISSUER + "/%61");

        List<String> ids = issuers.stream().map(issuer -> principalId(claims(issuer, "123"))).toList();

        assertThat(ids.stream().distinct().count(), is((long) issuers.size()));
    }

    @Test
    void subjectSpellingAndUnicodeAreNotNormalized() {
        // These are JWT access-token subjects, not OIDC ID Tokens (which require ASCII subjects).
        List<String> subjects = List.of("alice", "Alice", "alice ", "á", "a\u0301", "a.b", "a:b", "a/b", "😀", "?");

        List<String> ids = subjects.stream().map(subject -> principalId(claims(ISSUER, subject))).toList();

        assertThat(ids.stream().distinct().count(), is((long) subjects.size()));
        for (int i = 0; i < subjects.size(); i++) {
            assertThat(ids.get(i), is(OidcTestIdentities.issuerSubject(ISSUER, subjects.get(i))));
        }
    }

    @Test
    void encodingSeparatesValuesContainingDelimiters() {
        String first = principalId(claims(ISSUER + "/a", "b.c"));
        String second = principalId(claims(ISSUER + "/a.b", "c"));

        assertThat(second, not(first));
    }

    @Test
    void subjectAndExplicitClientClaimHaveDistinctNamespaces() {
        Jwt jwt = claims(Jwt.builder().issuer(ISSUER).subject("123").addPayloadClaim("client_id", "123"));
        OidcSubjectMappingConfig clientMapping = OidcSubjectMappingConfig.builder()
                .principalIdClaimPaths(List.of("client_id"))
                .buildPrototype();

        String subjectId = principalId(jwt);
        String clientId = OidcSubjectMapper.principalId(jwt, clientMapping).orElseThrow();

        assertThat(subjectId, not(clientId));
        assertThat(clientId, is(OidcTestIdentities.issuerClaim(ISSUER, "client_id", "123")));
    }

    @Test
    void customClaimPathsHaveDistinctNamespaces() {
        Jwt jwt = claims(Jwt.builder()
                .issuer(ISSUER)
                .subject("123")
                .addPayloadClaim("external_id", "123")
                .addPayloadClaim("external", JsonObject.builder().set("id", "123").build()));
        OidcSubjectMappingConfig firstMapping = OidcSubjectMappingConfig.builder()
                .principalIdClaimPaths(List.of("external_id"))
                .buildPrototype();
        OidcSubjectMappingConfig secondMapping = OidcSubjectMappingConfig.builder()
                .principalIdClaimPaths(List.of("external.id"))
                .buildPrototype();

        String firstId = OidcSubjectMapper.principalId(jwt, firstMapping).orElseThrow();
        String secondId = OidcSubjectMapper.principalId(jwt, secondMapping).orElseThrow();

        assertThat(secondId, not(firstId));
        assertThat(secondId, is(OidcTestIdentities.issuerClaim(ISSUER, "external.id", "123")));
    }

    @Test
    void noDefaultFallbackToUsernameOrClientId() {
        Jwt jwt = claims(Jwt.builder()
                .issuer(ISSUER)
                .addPayloadClaim("username", "123")
                .addPayloadClaim("client_id", "123"));

        assertThat(OidcSubjectMapper.principalId(jwt, DEFAULT_MAPPING).isEmpty(), is(true));
        assertThat(OidcSubjectMapper.localPrincipalId(jwt).isEmpty(), is(true));
    }

    @Test
    void malformedUnicodeIsNotReplacedIntoAnIdentity() {
        for (String malformed : List.of("\uD800", "\uDC00", "a\uD800b", "\uD800\uD800")) {
            assertThat(OidcSubjectMapper.principalId(claims(ISSUER, malformed), DEFAULT_MAPPING).isEmpty(), is(true));
            assertThat(OidcSubjectMapper.principalId(claims(ISSUER + malformed, "123"), DEFAULT_MAPPING).isEmpty(),
                       is(true));
        }
        assertThat(principalId(claims(ISSUER, "?")), is(OidcTestIdentities.issuerSubject(ISSUER, "?")));
    }

    @Test
    void qualifiedIdentityRequiresBothIssuerAndSelectedValue() {
        assertThat(OidcSubjectMapper.localPrincipalId(Jwt.builder().subject("123").build()).isEmpty(), is(true));
        assertThat(OidcSubjectMapper.localPrincipalId(Jwt.builder().issuer(ISSUER).build()).isEmpty(), is(true));
        assertThat(OidcSubjectMapper.principalId(claims(" ", "123"), DEFAULT_MAPPING).isEmpty(), is(true));
        assertThat(OidcSubjectMapper.principalId(claims(ISSUER, " "), DEFAULT_MAPPING).isEmpty(), is(true));
    }

    @Test
    void concurrentVirtualThreadsDoNotShareEncodingState() throws Exception {
        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<String>> results = IntStream.range(0, 256)
                    .mapToObj(index -> executor.submit(() -> {
                        assertThat(Thread.currentThread().isVirtual(), is(true));
                        return principalId(claims(ISSUER, "subject-" + index));
                    }))
                    .toList();
            for (int i = 0; i < results.size(); i++) {
                assertThat(results.get(i).get(10, TimeUnit.SECONDS),
                           is(OidcTestIdentities.issuerSubject(ISSUER, "subject-" + i)));
            }
        }
    }

    private static Jwt claims(String issuer, String subject) {
        return claims(Jwt.builder().issuer(issuer).subject(subject));
    }

    private static Jwt claims(Jwt.Builder builder) {
        // Materialize standard claims just as parsing does; these tests exercise mapping, not signature validation.
        return SignedJwt.sign(builder.build(), Jwk.NONE_JWK).getJwt();
    }

    private static String principalId(Jwt jwt) {
        return OidcSubjectMapper.principalId(jwt, DEFAULT_MAPPING).orElseThrow();
    }
}
