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

final class OidcUri {
    private OidcUri() {
    }

    static URI localReference(URI uri) {
        return localReference(uri.getRawPath(), uri.getRawQuery());
    }

    static URI localReference(String rawPath, String rawQuery) {
        String path = rawPath;
        if (path == null || path.isEmpty()) {
            path = "/";
        }
        if (!path.startsWith("/")) {
            path = "/" + path;
        }
        while (path.startsWith("//")) {
            path = path.substring(1);
        }

        return URI.create(rawQuery == null ? path : path + "?" + rawQuery);
    }

    static String path(URI uri) {
        String path = uri.getPath();
        if (path == null || path.isEmpty()) {
            return "/";
        }
        return path;
    }

    static boolean sameOrigin(URI first, URI second) {
        String firstScheme = first.getScheme();
        String secondScheme = second.getScheme();
        String firstHost = first.getHost();
        String secondHost = second.getHost();
        return firstScheme != null
                && secondScheme != null
                && firstHost != null
                && secondHost != null
                && firstScheme.equalsIgnoreCase(secondScheme)
                && firstHost.equalsIgnoreCase(secondHost)
                && effectivePort(first) == effectivePort(second);
    }

    static int effectivePort(URI uri) {
        int port = uri.getPort();
        if (port != -1) {
            return port;
        }
        String scheme = uri.getScheme();
        if ("https".equalsIgnoreCase(scheme)) {
            return 443;
        }
        if ("http".equalsIgnoreCase(scheme)) {
            return 80;
        }
        return -1;
    }
}
