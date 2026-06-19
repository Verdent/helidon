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
        }
    }
}
