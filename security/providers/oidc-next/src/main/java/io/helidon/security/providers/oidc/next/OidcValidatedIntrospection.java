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
import java.time.DateTimeException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import io.helidon.json.JsonObject;
import io.helidon.json.JsonString;
import io.helidon.json.JsonValue;
import io.helidon.json.JsonValueType;
import io.helidon.security.jwt.Jwt;

final class OidcValidatedIntrospection implements OidcValidatedAccessToken {
    private final String rawToken;
    private final JsonObject claims;
    private final Jwt jwt;

    OidcValidatedIntrospection(String rawToken, JsonObject claims) {
        this.rawToken = rawToken;
        this.claims = claims;
        this.jwt = toJwt(claims);
    }

    @Override
    public String rawToken() {
        return rawToken;
    }

    JsonObject claims() {
        return claims;
    }

    Jwt jwt() {
        return jwt;
    }

    Optional<String> issuer() {
        return stringClaim("iss");
    }

    Optional<String> tokenType() {
        return stringClaim("token_type");
    }

    Optional<Instant> expirationTime() {
        return instantClaim("exp");
    }

    Optional<Instant> issueTime() {
        return instantClaim("iat");
    }

    Optional<Instant> notBefore() {
        return instantClaim("nbf");
    }

    List<String> audience() {
        return stringListClaim("aud");
    }

    private Optional<String> stringClaim(String claimName) {
        return stringClaim(claims, claimName);
    }

    private static Optional<String> stringClaim(JsonObject claims, String claimName) {
        /*
         * Spec: RFC 6749, 2.2 Client Identifier
         * https://www.rfc-editor.org/rfc/rfc6749.html#section-2.2
         * Quote: "The client identifier is a case-sensitive string."
         *
         * Spec: RFC 7662, 2.2 Introspection Response
         * https://www.rfc-editor.org/rfc/rfc7662.html#section-2.2
         * Quote: "`iss` OPTIONAL. String representing the issuer of this token, as defined in JWT."
         */
        return claims.value(claimName)
                .map(jsonValue -> {
                    if (jsonValue.type() == JsonValueType.STRING) {
                        return jsonValue.asString().value();
                    }
                    throw new IllegalArgumentException("Claim " + claimName + " must be a string");
                });
    }

    private Optional<Instant> instantClaim(String claimName) {
        return instantClaim(claims, claimName);
    }

    private static Optional<Instant> instantClaim(JsonObject claims, String claimName) {
        return claims.value(claimName)
                .map(value -> {
                    if (value.type() != JsonValueType.NUMBER) {
                        throw new IllegalArgumentException("Claim " + claimName + " must be a number");
                    }
                    return instantClaim(claimName, value.asNumber().bigDecimalValue());
                });
    }

    private static Instant instantClaim(String claimName, BigDecimal value) {
        /*
         * Spec: RFC 7662, 2.2 Introspection Response
         * https://www.rfc-editor.org/rfc/rfc7662.html#section-2.2
         * Quote: "`exp` OPTIONAL. Integer timestamp, measured in the number of seconds since January 1 1970 UTC,
         * indicating when this token will expire, as defined in JWT."
         * Quote: "`iat` OPTIONAL. Integer timestamp, measured in the number of seconds since January 1 1970 UTC,
         * indicating when this token was originally issued, as defined in JWT."
         * Quote: "`nbf` OPTIONAL. Integer timestamp, measured in the number of seconds since January 1 1970 UTC,
         * indicating when this token is not to be used before, as defined in JWT."
         */
        try {
            return Instant.ofEpochSecond(value.toBigIntegerExact().longValueExact());
        } catch (ArithmeticException | DateTimeException e) {
            throw new IllegalArgumentException("Claim " + claimName + " must be an integer NumericDate", e);
        }
    }

    private List<String> stringListClaim(String claimName) {
        return stringListClaim(claims, claimName);
    }

    private static List<String> stringListClaim(JsonObject claims, String claimName) {
        /*
         * Spec: RFC 7662, 2.2 Introspection Response
         * https://www.rfc-editor.org/rfc/rfc7662.html#section-2.2
         * Quote: "`aud` OPTIONAL. Service-specific string identifier or list of string identifiers representing the
         * intended audience for this token, as defined in JWT."
         */
        return claims.value(claimName)
                .map(jsonValue -> {
                    if (jsonValue.type() == JsonValueType.STRING) {
                        return List.of(jsonValue.asString().value());
                    }
                    if (jsonValue.type() == JsonValueType.ARRAY) {
                        return jsonValue.asArray()
                                .values()
                                .stream()
                                .map(JsonValue::asString)
                                .map(JsonString::value)
                                .toList();
                    }
                    throw new IllegalArgumentException("Claim " + claimName + " must be a string or string array");
                })
                .orElseGet(List::of);
    }

    private static Jwt toJwt(JsonObject claims) {
        Jwt.Builder builder = Jwt.builder();
        stringClaim(claims, "iss").ifPresent(builder::issuer);
        instantClaim(claims, "exp").ifPresent(builder::expirationTime);
        instantClaim(claims, "iat").ifPresent(builder::issueTime);
        instantClaim(claims, "nbf").ifPresent(builder::notBefore);
        stringClaim(claims, "sub").ifPresent(builder::subject);
        stringListClaim(claims, "aud").forEach(builder::addAudience);
        stringListClaim(claims, "groups").forEach(builder::addUserGroup);
        return builder.build();
    }
}
