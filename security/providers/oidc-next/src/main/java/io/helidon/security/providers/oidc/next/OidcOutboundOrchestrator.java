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

import io.helidon.security.EndpointConfig;
import io.helidon.security.OutboundSecurityResponse;
import io.helidon.security.ProviderRequest;
import io.helidon.security.SecurityEnvironment;

final class OidcOutboundOrchestrator {
    private OidcOutboundOrchestrator() {
    }

    static OidcOutboundOrchestrator create(OidcProviderConfig config) {
        return new OidcOutboundOrchestrator();
    }

    boolean isSupported(ProviderRequest providerRequest,
                        SecurityEnvironment outboundEnv,
                        EndpointConfig outboundConfig) {
        return false;
    }

    OutboundSecurityResponse secure(ProviderRequest providerRequest,
                                    SecurityEnvironment outboundEnv,
                                    EndpointConfig outboundConfig) {
        return OutboundSecurityResponse.abstain();
    }
}
