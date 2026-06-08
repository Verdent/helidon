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

import io.helidon.builder.api.Option;
import io.helidon.builder.api.Prototype;

/**
 * Bearer Token transport configuration.
 */
@Prototype.Blueprint
@Prototype.Configured
interface OidcTokenTransportConfigBlueprint {
    /**
     * Whether the Authorization request header is accepted for Bearer Token transport.
     *
     * @return whether Authorization header transport is enabled
     */
    @Option.Configured
    @Option.DefaultBoolean(true)
    boolean authorizationHeaderEnabled();

    /**
     * Whether URI query parameter transport is accepted for Bearer Token transport.
     *
     * @return whether query parameter transport is enabled
     */
    @Option.Configured
    @Option.DefaultBoolean(false)
    boolean queryParameterEnabled();

    /**
     * Whether Bearer Token requests must use secure transport.
     * <p>
     * Spec: RFC 6750, 1 Introduction and 5.2 Threat Mitigation,
     * <a href="https://www.rfc-editor.org/rfc/rfc6750.html#section-1">section 1</a> and
     * <a href="https://www.rfc-editor.org/rfc/rfc6750.html#section-5.2">section 5.2</a>.
     * Quote: "TLS is mandatory to implement and use with this specification; other specifications may extend this
     * specification for use with other protocols."
     * Quote: "This requires that the communication interaction between the client and the authorization server, as well
     * as the interaction between the client and the resource server, utilize confidentiality and integrity protection."
     *
     * @return whether Bearer Token requests must use secure transport
     */
    @Option.Configured
    @Option.DefaultBoolean(true)
    boolean secureTransportRequired();
}
