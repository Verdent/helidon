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
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import io.helidon.common.uri.UriValidator;

final class OidcResourceIndicators {
    private OidcResourceIndicators() {
    }

    static void validate(List<String> resources, String configKey) {
        /*
         * Spec: RFC 8707, 2 Resource Parameter
         * https://www.rfc-editor.org/rfc/rfc8707.html#section-2
         * Quote: "The `resource` parameter URI value is an identifier representing the identity of the resource".
         * Quote: "MUST be an absolute URI".
         * Quote: "MUST NOT include a fragment component."
         */
        Set<String> uniqueResources = new LinkedHashSet<>();
        for (String resource : resources) {
            if (resource == null || resource.isBlank() || !resource.equals(resource.strip())) {
                throw new IllegalArgumentException(configKey + " must not contain blank or padded values");
            }
            if (!uniqueResources.add(resource)) {
                throw new IllegalArgumentException(configKey + " contains duplicate resource: " + resource);
            }
            URI uri;
            try {
                uri = URI.create(resource);
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException(configKey + " contains an invalid resource URI: " + resource, e);
            }
            if (!uri.isAbsolute()) {
                throw new IllegalArgumentException(configKey + " must contain absolute resource URIs");
            }
            if (uri.getRawFragment() != null) {
                throw new IllegalArgumentException(configKey + " must not contain URI fragments");
            }
            try {
                // RFC 3986 query syntax covers path pchars too; URI parsing isolates authority and fragment.
                if (uri.isOpaque()) {
                    UriValidator.validateQuery(uri.getRawSchemeSpecificPart());
                } else {
                    String authority = uri.getRawAuthority();
                    if (authority != null) {
                        validateAuthority(authority);
                    }
                    String path = uri.getRawPath();
                    if (path != null) {
                        UriValidator.validateQuery(path);
                    }
                    String query = uri.getRawQuery();
                    if (query != null) {
                        UriValidator.validateQuery(query);
                    }
                }
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException(configKey + " contains an invalid resource URI: " + resource, e);
            }
        }
    }

    private static void validateAuthority(String authority) {
        // RFC 3986 authority = [ userinfo "@" ] host [ ":" port ]; URI parsing already separates '/' and '?'.
        int at = authority.indexOf('@');
        if (at >= 0) {
            UriValidator.validateQuery(authority.substring(0, at));
            authority = authority.substring(at + 1);
        }
        int hostEnd;
        if (authority.startsWith("[")) {
            int closingBracket = authority.indexOf(']');
            if (closingBracket < 0) {
                throw new IllegalArgumentException("Invalid resource URI host literal");
            }
            hostEnd = closingBracket + 1;
        } else {
            int colon = authority.indexOf(':');
            hostEnd = colon < 0 ? authority.length() : colon;
        }
        String host = authority.substring(0, hostEnd);
        if (!host.isEmpty()) {
            UriValidator.validateHost(host);
        }
        if (hostEnd < authority.length()) {
            if (authority.charAt(hostEnd) != ':') {
                throw new IllegalArgumentException("Invalid resource URI authority port");
            }
            for (int i = hostEnd + 1; i < authority.length(); i++) {
                char c = authority.charAt(i);
                if (c < '0' || c > '9') {
                    throw new IllegalArgumentException("Invalid resource URI authority port");
                }
            }
        }
    }
}
