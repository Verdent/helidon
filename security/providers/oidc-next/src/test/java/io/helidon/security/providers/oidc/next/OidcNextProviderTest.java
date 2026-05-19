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

import java.util.ServiceLoader;

import io.helidon.config.Config;
import io.helidon.security.SecurityResponse;
import io.helidon.security.spi.SecurityProviderService;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;

class OidcNextProviderTest {
    private static final String CURRENT_PROVIDER_CONFIG_KEY = "oidc";
    private static final String OIDC_NEXT_PACKAGE = "io.helidon.security.providers.oidc.next";

    @Test
    void serviceCreatesProvider() {
        OidcNextProviderService service = new OidcNextProviderService();

        assertThat(service.providerConfigKey(), is("oidc-next"));
        assertThat(service.providerClass() == OidcNextProvider.class, is(true));
        assertThat(service.create(Config.empty()), instanceOf(OidcNextProvider.class));
    }

    @Test
    void serviceIsDiscoverable() {
        boolean found = false;

        for (SecurityProviderService service : ServiceLoader.load(SecurityProviderService.class)) {
            if (OidcNextProviderService.PROVIDER_CONFIG_KEY.equals(service.providerConfigKey())) {
                assertThat(service.providerClass() == OidcNextProvider.class, is(true));
                found = true;
            }
        }

        assertThat(found, is(true));
    }

    @Test
    void stage0KeepsNewProviderIsolatedFromCurrentProvider() {
        assertThat(OidcNextProvider.class.getPackageName(), is(OIDC_NEXT_PACKAGE));
        assertThat(OidcNextProviderService.PROVIDER_CONFIG_KEY, is("oidc-next"));
        assertThat(OidcNextProviderService.PROVIDER_CONFIG_KEY, is(not(CURRENT_PROVIDER_CONFIG_KEY)));
    }

    @Test
    void providerAbstainsUntilFlowsAreImplemented() {
        OidcNextProvider provider = OidcNextProvider.create();

        assertThat(provider.authenticate(null).status(), is(SecurityResponse.SecurityStatus.ABSTAIN));
        assertThat(provider.isOutboundSupported(null, null, null), is(false));
        assertThat(provider.outboundSecurity(null, null, null).status(), is(SecurityResponse.SecurityStatus.ABSTAIN));
    }
}
