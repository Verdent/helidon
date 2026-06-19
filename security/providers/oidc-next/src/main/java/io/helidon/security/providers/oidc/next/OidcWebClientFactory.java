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
import java.util.Optional;

import io.helidon.webclient.api.Proxy;
import io.helidon.webclient.api.WebClient;
import io.helidon.webclient.api.WebClientConfig;

final class OidcWebClientFactory {
    private static final WebClientConfig DEFAULT_WEBCLIENT = WebClientConfig.create();
    private static final Duration DEFAULT_READ_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration WEBCLIENT_DEFAULT_SOCKET_READ_TIMEOUT =
            WebClientConfig.create().socketOptions().readTimeout();

    private OidcWebClientFactory() {
    }

    static WebClient create(OidcTenantConfig tenantConfig) {
        WebClientConfig configured = tenantConfig.webClient();
        if (configured.readTimeout().isPresent()
                || !WEBCLIENT_DEFAULT_SOCKET_READ_TIMEOUT.equals(configured.socketOptions().readTimeout())) {
            return WebClient.create(configured);
        }
        return WebClient.create(WebClientConfig.builder()
                                        .from(configured)
                                        .readTimeout(DEFAULT_READ_TIMEOUT)
                                        .buildPrototype());
    }

    static boolean optionsChanged(WebClientConfig webClient) {
        return webClient.readTimeout().isPresent()
                || webClient.connectTimeout().isPresent()
                || !WEBCLIENT_DEFAULT_SOCKET_READ_TIMEOUT.equals(webClient.socketOptions().readTimeout())
                || !DEFAULT_WEBCLIENT.socketOptions().connectTimeout().equals(webClient.socketOptions().connectTimeout())
                || webClient.followRedirects() != DEFAULT_WEBCLIENT.followRedirects()
                || webClient.maxRedirects() != DEFAULT_WEBCLIENT.maxRedirects()
                || webClient.keepAlive() != DEFAULT_WEBCLIENT.keepAlive()
                || proxyOptionsChanged(webClient.proxy())
                || !DEFAULT_WEBCLIENT.tls().equals(webClient.tls())
                || webClient.baseUri().isPresent()
                || webClient.baseAddress().isPresent()
                || !webClient.defaultHeadersMap().isEmpty()
                || !webClient.headers().isEmpty()
                || !webClient.properties().isEmpty()
                || !DEFAULT_WEBCLIENT.protocolConfigs().equals(webClient.protocolConfigs())
                || !webClient.protocolPreference().isEmpty();
    }

    private static boolean proxyOptionsChanged(Proxy proxy) {
        Proxy defaultProxy = DEFAULT_WEBCLIENT.proxy();
        return proxy.type() != defaultProxy.type()
                || proxy.port() != defaultProxy.port()
                || !Optional.ofNullable(defaultProxy.host()).equals(Optional.ofNullable(proxy.host()))
                || !defaultProxy.username().equals(proxy.username())
                || defaultProxy.password().isPresent() != proxy.password().isPresent();
    }
}
