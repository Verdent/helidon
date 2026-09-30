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

import java.time.Duration;

import io.helidon.security.providers.common.OutboundConfig;
import io.helidon.webclient.api.WebClient;
import io.helidon.webclient.api.WebClientConfig;

final class OidcWebClientFactory {
    private static final Duration DEFAULT_READ_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration WEBCLIENT_DEFAULT_SOCKET_READ_TIMEOUT =
            WebClientConfig.create().socketOptions().readTimeout();

    private OidcWebClientFactory() {
    }

    static WebClient create(OidcTenantConfig tenantConfig) {
        WebClientConfig configured = tenantConfig.webClient();
        /*
         * Provider-owned protocol traffic already applies its required endpoint authentication explicitly. Allowing
         * WebClientSecurity to route these requests through OIDC outbound security can re-enter the same tenant
         * initialization or token single-flight operation and make the leader wait on itself.
         */
        WebClientConfig.Builder builder = WebClientConfig.builder()
                .from(configured)
                .putProperty(OutboundConfig.PROPERTY_DISABLE_OUTBOUND, Boolean.TRUE.toString());
        if (configured.readTimeout().isEmpty()
                && WEBCLIENT_DEFAULT_SOCKET_READ_TIMEOUT.equals(configured.socketOptions().readTimeout())) {
            builder.readTimeout(DEFAULT_READ_TIMEOUT);
        }
        return WebClient.create(builder.buildPrototype());
    }
}
