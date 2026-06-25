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
import java.net.URISyntaxException;

final class OidcDiagnostics {
    private static final int MAX_LOG_VALUE_LENGTH = 512;

    private OidcDiagnostics() {
    }

    static String safeUri(URI uri) {
        if (uri == null) {
            return "<unknown>";
        }
        String scheme = uri.getScheme();
        if (scheme == null || scheme.isBlank()) {
            return "<no-scheme>";
        }
        if (uri.isOpaque()) {
            return sanitizeLogValue(scheme + ":<opaque>");
        }
        if (uri.getHost() == null) {
            return sanitizeLogValue(scheme + ":" + uri.getRawPath());
        }
        try {
            return new URI(scheme, null, uri.getHost(), uri.getPort(), uri.getRawPath(), null, null)
                    .toASCIIString();
        } catch (URISyntaxException e) {
            return sanitizeLogValue(scheme + "://<invalid>");
        }
    }

    static String safeExceptionType(Throwable throwable) {
        if (throwable == null) {
            return "<none>";
        }
        return throwable.getClass().getName();
    }

    static String sanitizeLogValue(String value) {
        if (value == null) {
            return "<null>";
        }
        StringBuilder result = new StringBuilder(Math.min(value.length(), MAX_LOG_VALUE_LENGTH));
        int appended = 0;
        for (int i = 0; i < value.length() && appended < MAX_LOG_VALUE_LENGTH; i++) {
            char current = value.charAt(i);
            if (Character.isISOControl(current)) {
                result.append('?');
            } else {
                result.append(current);
            }
            appended++;
        }
        if (value.length() > MAX_LOG_VALUE_LENGTH) {
            result.append("...");
        }
        return result.toString();
    }
}
