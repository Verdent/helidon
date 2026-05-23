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
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import io.helidon.common.uri.UriEncoding;
import io.helidon.common.uri.UriQuery;
import io.helidon.http.HeaderNames;
import io.helidon.security.SecurityEnvironment;

final class OidcBearerTokenExtractor {
    private static final String ACCESS_TOKEN = "access_token";
    private static final String BEARER_SCHEME = "Bearer";

    private OidcBearerTokenExtractor() {
    }

    static OidcBearerTokenExtractionResult extract(SecurityEnvironment environment,
                                                   OidcTokenTransportConfig tokenTransport) {
        List<String> bearerTokens = new ArrayList<>();
        if (tokenTransport.authorizationHeaderEnabled()) {
            OidcBearerTokenExtractionResult headerToken = authorizationHeaderBearerToken(environment);
            if (headerToken.invalidRequest()) {
                return headerToken;
            }
            headerToken.bearerToken().ifPresent(bearerTokens::add);
        }
        if (tokenTransport.queryParameterEnabled()) {
            OidcBearerTokenExtractionResult queryToken = accessTokenQueryParameterBearerToken(environment.queryParams(),
                                                                                             rawQuery(environment));
            if (queryToken.invalidRequest()) {
                return queryToken;
            }
            queryToken.bearerToken().ifPresent(bearerTokens::add);
        }

        if (bearerTokens.size() > 1) {
            return OidcBearerTokenExtractionResult.invalidRequest("Multiple Bearer Token credential sources found");
        }
        return bearerTokens.stream()
                .findFirst()
                .map(OidcBearerTokenExtractionResult::bearerToken)
                .orElseGet(OidcBearerTokenExtractionResult::empty);
    }

    private static OidcBearerTokenExtractionResult authorizationHeaderBearerToken(SecurityEnvironment environment) {
        List<String> tokens = new ArrayList<>();
        List<String> values = environment.headers().getOrDefault(HeaderNames.AUTHORIZATION.defaultCase(), List.of());
        for (String value : values) {
            Optional<String> token = authorizationHeaderBearerToken(value);
            if (token.isEmpty()) {
                continue;
            }
            String bearerToken = token.orElseThrow();
            if (malformedToken(bearerToken)) {
                return OidcBearerTokenExtractionResult.invalidRequest("Malformed Bearer Token in Authorization header");
            }
            tokens.add(bearerToken);
        }
        if (tokens.size() > 1) {
            return OidcBearerTokenExtractionResult.invalidRequest(
                    "Multiple Bearer Tokens found in Authorization header");
        }
        return tokens.stream()
                .findFirst()
                .map(OidcBearerTokenExtractionResult::bearerToken)
                .orElseGet(OidcBearerTokenExtractionResult::empty);
    }

    private static Optional<String> authorizationHeaderBearerToken(String value) {
        String trimmed = value.stripLeading();
        if (!trimmed.regionMatches(true, 0, BEARER_SCHEME, 0, BEARER_SCHEME.length())) {
            return Optional.empty();
        }
        if (trimmed.length() == BEARER_SCHEME.length()) {
            return Optional.of("");
        }
        int tokenStart = BEARER_SCHEME.length();
        char separator = trimmed.charAt(tokenStart);
        if (separator != ' ') {
            return Character.isWhitespace(separator) ? Optional.of("") : Optional.empty();
        }
        while (tokenStart < trimmed.length() && trimmed.charAt(tokenStart) == ' ') {
            tokenStart++;
        }
        return Optional.of(trimmed.substring(tokenStart));
    }

    private static OidcBearerTokenExtractionResult accessTokenQueryParameterBearerToken(UriQuery queryParams,
                                                                                       Optional<String> rawQuery) {
        if (!queryParams.contains(ACCESS_TOKEN)) {
            return OidcBearerTokenExtractionResult.empty();
        }
        List<String> tokens = queryParams.all(ACCESS_TOKEN);
        int accessTokenOccurrences = queryParameterOccurrenceCount(rawQuery.orElseGet(queryParams::rawValue),
                                                                   ACCESS_TOKEN);
        if (tokens.size() > 1 || accessTokenOccurrences > 1) {
            return OidcBearerTokenExtractionResult.invalidRequest("Multiple Bearer Tokens found in query parameter");
        }
        if (tokens.isEmpty()) {
            return OidcBearerTokenExtractionResult.invalidRequest("Malformed Bearer Token in query parameter");
        }
        String token = tokens.get(0);
        if (malformedToken(token)) {
            return OidcBearerTokenExtractionResult.invalidRequest("Malformed Bearer Token in query parameter");
        }
        return OidcBearerTokenExtractionResult.bearerToken(token);
    }

    private static Optional<String> rawQuery(SecurityEnvironment environment) {
        URI targetUri = environment.targetUri();
        if (targetUri == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(targetUri.getRawQuery());
    }

    private static int queryParameterOccurrenceCount(String rawQuery, String parameterName) {
        if (rawQuery.isEmpty()) {
            return 1;
        }

        int count = 0;
        int segmentStart = 0;
        while (segmentStart <= rawQuery.length()) {
            int segmentEnd = rawQuery.indexOf('&', segmentStart);
            if (segmentEnd == -1) {
                segmentEnd = rawQuery.length();
            }

            String segment = rawQuery.substring(segmentStart, segmentEnd);
            int nameEnd = segment.indexOf('=');
            String rawName = nameEnd == -1 ? segment : segment.substring(0, nameEnd);
            if (parameterName.equals(UriEncoding.decodeQuery(rawName))) {
                count++;
            }

            if (segmentEnd == rawQuery.length()) {
                break;
            }
            segmentStart = segmentEnd + 1;
        }
        return count;
    }

    private static boolean malformedToken(String token) {
        return token.isEmpty() || token.chars().anyMatch(Character::isWhitespace);
    }
}
