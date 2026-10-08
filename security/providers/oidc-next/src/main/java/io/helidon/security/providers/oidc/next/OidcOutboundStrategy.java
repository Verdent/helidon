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

/**
 * Strategy for securing one outbound request with an OIDC access token.
 */
public enum OidcOutboundStrategy {
    /**
     * No strategy at this policy level. An endpoint policy with this value does not override a matching target policy.
     */
    NONE,

    /**
     * Propagate the current subject's access token, subject to the configured audience check.
     */
    TOKEN_PROPAGATION,

    /**
     * Acquire an access token using the Client Credentials Grant; mutual TLS client authentication requires enabled
     * tenant {@code webclient.tls} and an HTTPS Token Endpoint or HTTPS well-known metadata.
     */
    CLIENT_CREDENTIALS,

    /**
     * Exchange the current subject's access token for a downstream access token.
     */
    TOKEN_EXCHANGE
}
