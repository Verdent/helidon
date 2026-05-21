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
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import io.helidon.common.uri.UriQuery;

record OidcAuthorizationResponseContext(UriQuery parameters,
                                        Map<String, List<String>> cookies,
                                        URI redirectionEndpointUri,
                                        Instant now) {
    OidcAuthorizationResponseContext {
        parameters = Objects.requireNonNull(parameters);
        cookies = Map.copyOf(Objects.requireNonNull(cookies));
        redirectionEndpointUri = Objects.requireNonNull(redirectionEndpointUri);
        now = Objects.requireNonNull(now);
    }

    static OidcAuthorizationResponseContext create(UriQuery parameters,
                                                   Map<String, List<String>> cookies,
                                                   URI redirectionEndpointUri,
                                                   Instant now) {
        return new OidcAuthorizationResponseContext(parameters, cookies, redirectionEndpointUri, now);
    }
}
