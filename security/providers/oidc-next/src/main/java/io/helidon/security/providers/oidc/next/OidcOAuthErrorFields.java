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

final class OidcOAuthErrorFields {
    private OidcOAuthErrorFields() {
    }

    static boolean validError(String value) {
        return value != null && !value.isBlank() && value.codePoints().allMatch(OidcOAuthErrorFields::validErrorChar);
    }

    static boolean validErrorDescription(String value) {
        return value != null && value.codePoints().allMatch(OidcOAuthErrorFields::validErrorChar);
    }

    static boolean validErrorUri(String value) {
        if (value == null || value.isBlank() || !value.codePoints().allMatch(OidcOAuthErrorFields::validErrorUriChar)) {
            return false;
        }
        try {
            URI.create(value);
            return true;
        } catch (RuntimeException e) {
            return false;
        }
    }

    private static boolean validErrorChar(int codePoint) {
        return codePoint >= 0x20 && codePoint <= 0x21
                || codePoint >= 0x23 && codePoint <= 0x5B
                || codePoint >= 0x5D && codePoint <= 0x7E;
    }

    private static boolean validErrorUriChar(int codePoint) {
        return codePoint == 0x21
                || codePoint >= 0x23 && codePoint <= 0x5B
                || codePoint >= 0x5D && codePoint <= 0x7E;
    }
}
