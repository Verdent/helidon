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

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class OidcAuthorizationStateTest {
    private static final String REQUEST_ID = Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(new byte[32]);

    @Test
    void createsAndParsesVersionedTenantRoutedState() {
        OidcAuthorizationState state = OidcAuthorizationState.create("tenant-a", REQUEST_ID);

        assertThat(state.value(), is("s1.dGVuYW50LWE." + REQUEST_ID));
        assertThat(state.routedTenantId(), is("tenant-a"));
        assertThat(state.requestId(), is(REQUEST_ID));

        assertThat(OidcAuthorizationState.parse(state.value()).orElseThrow(), is(state));
    }

    @Test
    void preservesUtf8TenantId() {
        String tenantId = "tenant-\u010D";
        OidcAuthorizationState parsed = OidcAuthorizationState.parse(
                OidcAuthorizationState.create(tenantId, REQUEST_ID).value()).orElseThrow();

        assertThat(parsed.routedTenantId(), is(tenantId));
    }

    @Test
    void rejectsMalformedAndNonCanonicalValues() {
        String encodedTenant = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString("default".getBytes(StandardCharsets.UTF_8));
        List<String> invalidValues = List.of("",
                                             "s2." + encodedTenant + "." + REQUEST_ID,
                                             "s1.." + REQUEST_ID,
                                             "s1." + encodedTenant + ".",
                                             "s1." + encodedTenant + ".short",
                                             "s1." + encodedTenant + "." + REQUEST_ID + ".extra",
                                             "s1.***." + REQUEST_ID,
                                             "s1." + encodedTenant + "=." + REQUEST_ID,
                                             "s1." + encodedTenant + "." + REQUEST_ID + "=");

        for (String value : invalidValues) {
            assertThat(value, OidcAuthorizationState.parse(value).isEmpty(), is(true));
        }
    }

    @Test
    void createRequiresTenantAnd256BitRequestId() {
        assertThrows(IllegalArgumentException.class, () -> OidcAuthorizationState.create("", REQUEST_ID));
        assertThrows(IllegalArgumentException.class, () -> OidcAuthorizationState.create("default", "short"));
    }
}
