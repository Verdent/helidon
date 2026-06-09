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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import io.helidon.json.JsonObject;
import io.helidon.json.JsonValue;
import io.helidon.json.JsonValueType;

final class OidcScopeSupport {
    private static final String STANDARD_SCOPE_CLAIM = "scope";

    private OidcScopeSupport() {
    }

    static void validateConfiguredScopes(List<String> scopes, String configKey) {
        Set<String> uniqueScopes = new LinkedHashSet<>();
        scopes.forEach(scope -> {
            if (scope == null || scope.isBlank() || !scope.equals(scope.strip())) {
                throw new IllegalArgumentException(configKey + " contains blank or padded scope");
            }
            if (!uniqueScopes.add(scope)) {
                throw new IllegalArgumentException(configKey + " contains duplicate scope: " + scope);
            }
            validateScopeToken(scope, configKey);
        });
    }

    static String serializeScopes(List<String> scopes) {
        return String.join(" ", scopes);
    }

    static String validateScopeString(String scope, String source) {
        return serializeScopes(parseScopeString(scope, source));
    }

    static List<String> parseScopeString(String scope, String source) {
        /*
         * Spec: RFC 6749, 3.3 Access Token Scope and Appendix A.4 "scope" Syntax
         * https://www.rfc-editor.org/rfc/rfc6749.html#section-3.3
         * https://www.rfc-editor.org/rfc/rfc6749.html#appendix-A.4
         * Quote: "The value of the scope parameter is expressed as a list of space-delimited, case-sensitive strings."
         * Quote: "scope = scope-token *( SP scope-token )"
         * Quote: "scope-token = 1*NQCHAR"
         */
        if (scope == null || scope.isEmpty()) {
            throw invalidScopeString(source);
        }
        List<String> scopes = Arrays.asList(scope.split(" ", -1));
        scopes.forEach(token -> validateScopeToken(token, source));
        return scopes;
    }

    static void validateScopeClaims(JsonObject claims, OidcSubjectMappingConfig subjectMapping, String source) {
        validateScopeClaims(claims::value, subjectMapping, source);
    }

    static void validateScopeClaims(Map<String, JsonValue> claims, OidcSubjectMappingConfig subjectMapping, String source) {
        validateScopeClaims(name -> Optional.ofNullable(claims.get(name)), subjectMapping, source);
    }

    private static void validateScopeClaims(ClaimSource claims, OidcSubjectMappingConfig subjectMapping, String source) {
        claims.value(STANDARD_SCOPE_CLAIM)
                .ifPresent(value -> scopeClaimValues(value, source + " scope claim", true));
        if (!subjectMapping.scopeGrantsEnabled()) {
            return;
        }
        for (String claimPath : subjectMapping.scopeClaimPaths()) {
            if (!STANDARD_SCOPE_CLAIM.equals(claimPath)) {
                claimValue(claims, claimPath)
                        .ifPresent(value -> scopeClaimValues(value, source + " scope claim " + claimPath, false));
            }
        }
    }

    static List<String> scopeClaimValues(JsonValue value, String source, boolean standardScope) {
        if (value.type() == JsonValueType.STRING) {
            return parseScopeString(value.asString().value(), source);
        }
        if (standardScope) {
            throw new IllegalArgumentException(source + " must be a string");
        }
        if (value.type() == JsonValueType.ARRAY) {
            List<String> result = new ArrayList<>();
            value.asArray()
                    .values()
                    .forEach(item -> {
                        if (item.type() != JsonValueType.STRING) {
                            throw new IllegalArgumentException(source + " array values must be strings");
                        }
                        String scope = item.asString().value();
                        validateScopeToken(scope, source);
                        result.add(scope);
                    });
            return result;
        }
        throw new IllegalArgumentException(source + " must be a string or string array");
    }

    static Optional<JsonValue> claimValue(JsonObject claims, String claimPath) {
        return claimValue(claims::value, claimPath);
    }

    private static Optional<JsonValue> claimValue(ClaimSource claims, String claimPath) {
        String[] segments = claimPath.split("\\.");
        if (segments.length == 0 || segments[0].isBlank()) {
            return Optional.empty();
        }
        return claims.value(segments[0])
                .flatMap(value -> claimValue(value, segments));
    }

    private static Optional<JsonValue> claimValue(JsonValue firstSegmentValue, String[] segments) {
        JsonValue current = firstSegmentValue;
        for (int i = 1; i < segments.length; i++) {
            if (current == null || current.type() != JsonValueType.OBJECT || segments[i].isBlank()) {
                return Optional.empty();
            }
            current = current.asObject()
                    .value(segments[i])
                    .orElse(null);
        }
        return Optional.ofNullable(current);
    }

    private static void validateScopeToken(String scope, String source) {
        if (scope == null || scope.isEmpty()) {
            throw invalidScopeString(source);
        }
        scope.codePoints()
                .filter(codePoint -> !validScopeTokenCodePoint(codePoint))
                .findFirst()
                .ifPresent(ignored -> {
                    throw new IllegalArgumentException(source + " contains invalid scope: " + scope);
                });
    }

    private static boolean validScopeTokenCodePoint(int codePoint) {
        /*
         * Spec: RFC 6749, Appendix A.4 "scope" Syntax
         * https://www.rfc-editor.org/rfc/rfc6749.html#appendix-A.4
         * Quote: "scope-token = 1*NQCHAR".
         */
        return codePoint == 0x21
                || (codePoint >= 0x23 && codePoint <= 0x5B)
                || (codePoint >= 0x5D && codePoint <= 0x7E);
    }

    private static IllegalArgumentException invalidScopeString(String source) {
        return new IllegalArgumentException(source + " must be an RFC 6749 scope string");
    }

    @FunctionalInterface
    private interface ClaimSource {
        Optional<JsonValue> value(String name);
    }
}
