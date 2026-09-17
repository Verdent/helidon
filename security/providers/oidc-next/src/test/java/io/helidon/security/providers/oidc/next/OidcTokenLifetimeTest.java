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

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Stream;

import io.helidon.json.JsonObject;
import io.helidon.json.JsonParser;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;

class OidcTokenLifetimeTest {
    private static final Instant NOW = Instant.parse("2026-09-17T12:00:00.123456789Z");
    private static final List<ResponseParser> PARSERS = List.of(
            new ResponseParser("authorization code", json -> OidcTokenResponse.fromAuthorizationCodeJson(json).expiresIn()),
            new ResponseParser("refresh", json -> OidcTokenResponse.fromRefreshJson(json).expiresIn()),
            new ResponseParser("client credentials", json -> OidcTokenResponse.fromClientCredentialsJson(json).expiresIn()),
            new ResponseParser("token exchange", json -> OidcTokenExchangeResponse.fromJson(json).expiresIn()));

    @TestFactory
    Stream<DynamicTest> unusableLifetimesAreRejectedByEveryGrantParser() {
        return PARSERS.stream().flatMap(parser -> Stream.of("0", "-1", "1.5", "-9223372036854775809",
                                                          "9223372036854775808", "1e100", "\"60\"", "null", "true", "{}", "[]")
                .map(lifetime -> dynamicTest(parser.name() + ": expires_in=" + lifetime, () -> {
                    JsonObject json = JsonObject.builder()
                            .from(tokenResponse())
                            .from(JsonParser.create("{\"expires_in\":" + lifetime + "}").readJsonObject())
                            .build();

                    assertThrows(RuntimeException.class, () -> parser.parse().apply(json));
                })));
    }

    @TestFactory
    Stream<DynamicTest> positiveLifetimesArePreservedByEveryGrantParser() {
        return PARSERS.stream().flatMap(parser -> Stream.of(1L, 60L, 61L, Instant.MAX.getEpochSecond(), Long.MAX_VALUE)
                .map(lifetime -> dynamicTest(parser.name() + ": expires_in=" + lifetime, () -> {
                    JsonObject json = JsonObject.builder().from(tokenResponse()).set("expires_in", lifetime).build();

                    assertThat(parser.parse().apply(json), is(Optional.of(lifetime)));
                })));
    }

    @TestFactory
    Stream<DynamicTest> omittedLifetimeIsNotAnExpiredLifetime() {
        return PARSERS.stream().map(parser -> dynamicTest(parser.name(), () ->
                assertThat(parser.parse().apply(tokenResponse()), is(Optional.empty()))));
    }

    @Test
    void representableExpiryPreservesSecondsAndNanoseconds() {
        assertAll(
                () -> assertThat(OidcTokenLifetime.expiresAt(NOW, 1), is(NOW.plusSeconds(1))),
                () -> assertThat(OidcTokenLifetime.expiresAt(NOW, 60), is(NOW.plusSeconds(60))),
                () -> assertThat(OidcTokenLifetime.expiresAt(Instant.MIN, 1), is(Instant.MIN.plusSeconds(1))));
    }

    @Test
    void saturatesOnlyBeyondRepresentableExpiry() {
        long maximumSeconds = Instant.MAX.getEpochSecond() - NOW.getEpochSecond();

        assertAll(
                () -> assertThat(OidcTokenLifetime.expiresAt(NOW, maximumSeconds),
                                 is(Instant.ofEpochSecond(Instant.MAX.getEpochSecond(), NOW.getNano()))),
                () -> assertThat(OidcTokenLifetime.expiresAt(NOW, maximumSeconds + 1), is(Instant.MAX)),
                () -> assertThat(OidcTokenLifetime.expiresAt(NOW, Long.MAX_VALUE), is(Instant.MAX)),
                () -> assertThat(OidcTokenLifetime.expiresAt(Instant.MIN, Long.MAX_VALUE), is(Instant.MAX)),
                () -> assertThat(OidcTokenLifetime.expiresAt(Instant.MAX.minusSeconds(1), 1), is(Instant.MAX)),
                () -> assertThat(OidcTokenLifetime.expiresAt(Instant.MAX, 1), is(Instant.MAX)));
    }

    @Test
    void cacheSkewBoundaryIsExclusiveAndNanosecondPrecise() {
        Instant expiresAt = NOW.plusSeconds(60);
        Duration skew = Duration.ofSeconds(60);

        assertAll(
                () -> assertThat(OidcTokenLifetime.activeAt(expiresAt, NOW.minusNanos(1), skew), is(true)),
                () -> assertThat(OidcTokenLifetime.activeAt(expiresAt, NOW, skew), is(false)),
                () -> assertThat(OidcTokenLifetime.activeAt(expiresAt, NOW.plusNanos(1), skew), is(false)),
                () -> assertThat(OidcTokenLifetime.activeAt(expiresAt, expiresAt, Duration.ZERO), is(false)),
                () -> assertThat(OidcTokenLifetime.activeAt(expiresAt, expiresAt.plusNanos(1), Duration.ZERO), is(false)),
                () -> assertThat(OidcTokenLifetime.activeAt(expiresAt, expiresAt.minusNanos(1), Duration.ZERO), is(true)));
    }

    @Test
    void skewComparisonDoesNotOverflowAtInstantOrDurationBoundaries() {
        Duration maximumSkew = Duration.ofSeconds(Long.MAX_VALUE, 999_999_999);

        assertAll(
                () -> assertThat(OidcTokenLifetime.activeAt(Instant.MAX, NOW, Duration.ofSeconds(60)), is(true)),
                () -> assertThat(OidcTokenLifetime.activeAt(Instant.MAX, NOW, maximumSkew), is(false)),
                () -> assertThat(OidcTokenLifetime.activeAt(Instant.MAX, Instant.MIN, maximumSkew), is(false)),
                () -> assertThat(OidcTokenLifetime.activeAt(Instant.MIN, Instant.MAX, Duration.ZERO), is(false)));
    }

    private static JsonObject tokenResponse() {
        return JsonObject.builder()
                .set("access_token", "access-token")
                .set("token_type", "Bearer")
                .set("issued_token_type", OidcTokenExchangeResponse.ACCESS_TOKEN_TYPE)
                .set("id_token", "id-token")
                .build();
    }

    private record ResponseParser(String name, Function<JsonObject, Optional<Long>> parse) {
    }
}
