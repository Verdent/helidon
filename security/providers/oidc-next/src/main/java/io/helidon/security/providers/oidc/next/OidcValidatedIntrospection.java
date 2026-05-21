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
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import io.helidon.json.JsonObject;
import io.helidon.json.JsonString;
import io.helidon.json.JsonValue;
import io.helidon.json.JsonValueType;
import io.helidon.security.jwt.Jwt;

final class OidcValidatedIntrospection {
    private final String rawToken;
    private final JsonObject claims;
    private final Jwt jwt;

    private OidcValidatedIntrospection(String rawToken, JsonObject claims) {
        this.rawToken = rawToken;
        this.claims = claims;
        this.jwt = toJwt(claims);
    }

    static OidcValidatedIntrospection create(String rawToken, JsonObject claims) {
        return new OidcValidatedIntrospection(rawToken, claims);
    }

    String rawToken() {
        return rawToken;
    }

    JsonObject claims() {
        return claims;
    }

    Jwt jwt() {
        return jwt;
    }

    Optional<String> principalId() {
        return stringClaim("sub")
                .filter(it -> !it.isBlank())
                .or(() -> stringClaim("username").filter(it -> !it.isBlank()))
                .or(() -> clientId().filter(it -> !it.isBlank()));
    }

    Optional<String> principalName() {
        return stringClaim("preferred_username")
                .filter(it -> !it.isBlank())
                .or(() -> stringClaim("username").filter(it -> !it.isBlank()))
                .or(this::principalId);
    }

    Optional<String> issuer() {
        return stringClaim("iss");
    }

    Optional<String> clientId() {
        return stringClaim("client_id");
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

    List<String> scopes() {
        return scopes(claims);
    }

    List<String> groups() {
        return stringListClaim("groups")
                .stream()
                .filter(group -> !group.isBlank())
                .toList();
    }

    private Optional<String> stringClaim(String claimName) {
        return stringClaim(claims, claimName);
    }

    private static Optional<String> stringClaim(JsonObject claims, String claimName) {
        Optional<JsonValue> value = claims.value(claimName);
        if (value.isEmpty()) {
            return Optional.empty();
        }
        JsonValue jsonValue = value.get();
        if (jsonValue.type() == JsonValueType.STRING) {
            return Optional.of(jsonValue.asString().value());
        }
        throw new IllegalArgumentException("Claim " + claimName + " must be a string");
    }

    private Optional<Instant> instantClaim(String claimName) {
        return instantClaim(claims, claimName);
    }

    private static Optional<Instant> instantClaim(JsonObject claims, String claimName) {
        return claims.numberValue(claimName)
                .map(BigDecimal::longValue)
                .map(Instant::ofEpochSecond);
    }

    private List<String> stringListClaim(String claimName) {
        return stringListClaim(claims, claimName);
    }

    private static List<String> stringListClaim(JsonObject claims, String claimName) {
        Optional<JsonValue> value = claims.value(claimName);
        if (value.isEmpty()) {
            return List.of();
        }
        JsonValue jsonValue = value.get();
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
    }

    private static List<String> scopes(JsonObject claims) {
        return stringListClaim(claims, "scope")
                .stream()
                .flatMap(scope -> Arrays.stream(scope.split(" ")))
                .filter(scope -> !scope.isBlank())
                .toList();
    }

    private static Jwt toJwt(JsonObject claims) {
        Jwt.Builder builder = Jwt.builder();
        stringClaim(claims, "iss").ifPresent(builder::issuer);
        instantClaim(claims, "exp").ifPresent(builder::expirationTime);
        instantClaim(claims, "iat").ifPresent(builder::issueTime);
        instantClaim(claims, "nbf").ifPresent(builder::notBefore);
        stringClaim(claims, "sub").ifPresent(builder::subject);
        stringListClaim(claims, "aud").forEach(builder::addAudience);
        scopes(claims).forEach(builder::addScope);
        stringListClaim(claims, "groups").forEach(builder::addUserGroup);
        return builder.build();
    }
}
