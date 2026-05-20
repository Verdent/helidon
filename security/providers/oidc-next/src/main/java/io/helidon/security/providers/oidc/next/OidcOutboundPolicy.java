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

final class OidcOutboundPolicy {
    private final boolean tokenPropagation;
    private final boolean clientCredentialsGrant;

    private OidcOutboundPolicy(boolean tokenPropagation, boolean clientCredentialsGrant) {
        this.tokenPropagation = tokenPropagation;
        this.clientCredentialsGrant = clientCredentialsGrant;
    }

    static OidcOutboundPolicy tokenPropagation() {
        return new OidcOutboundPolicy(true, false);
    }

    static OidcOutboundPolicy clientCredentialsGrant() {
        return new OidcOutboundPolicy(false, true);
    }

    static OidcOutboundPolicy tokenPropagationAndClientCredentialsGrant() {
        return new OidcOutboundPolicy(true, true);
    }

    boolean tokenPropagationEnabled() {
        return tokenPropagation;
    }

    boolean clientCredentialsGrantEnabled() {
        return clientCredentialsGrant;
    }
}
