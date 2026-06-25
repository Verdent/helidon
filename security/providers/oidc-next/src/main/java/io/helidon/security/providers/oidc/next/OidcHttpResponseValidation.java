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

import java.util.Arrays;
import java.util.Locale;

import io.helidon.http.HeaderName;
import io.helidon.http.HeaderNames;
import io.helidon.http.HttpMediaTypes;
import io.helidon.webclient.api.HttpClientResponse;

final class OidcHttpResponseValidation {
    private static final String APPLICATION = "application";
    private static final String JWT = "jwt";

    private OidcHttpResponseValidation() {
    }

    static boolean hasJsonContentType(HttpClientResponse response) {
        return response.headers()
                .contentType()
                .filter(HttpMediaTypes.JSON_PREDICATE::test)
                .isPresent();
    }

    static boolean hasJwtContentType(HttpClientResponse response) {
        return response.headers()
                .contentType()
                .filter(contentType -> APPLICATION.equalsIgnoreCase(contentType.type())
                        && JWT.equalsIgnoreCase(contentType.subtype()))
                .isPresent();
    }

    static boolean hasNoStoreCacheControl(HttpClientResponse response) {
        return hasHeaderValue(response, HeaderNames.CACHE_CONTROL, "no-store");
    }

    static boolean hasNoCachePragma(HttpClientResponse response) {
        return hasHeaderValue(response, HeaderNames.PRAGMA, "no-cache");
    }

    private static boolean hasHeaderValue(HttpClientResponse response, HeaderName headerName, String expectedValue) {
        return response.headers()
                .get(headerName)
                .allValues()
                .stream()
                .map(value -> value.toLowerCase(Locale.ROOT))
                .flatMap(value -> Arrays.stream(value.split(",")))
                .map(String::strip)
                .anyMatch(expectedValue::equals);
    }
}
