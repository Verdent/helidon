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

package io.helidon.security.spiffe;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SpiffeIdTest {
    @Test
    void shouldParseWorkloadId() {
        SpiffeId id = SpiffeId.parse("spiffe://example.org/ns/backend/sa/orders");

        assertThat(id.trustDomain(), is(SpiffeTrustDomain.create("example.org")));
        assertThat(id.path(), is(SpiffePath.create("/ns/backend/sa/orders")));
        assertThat(id.isRoot(), is(false));
        assertThat(id.value(), is("spiffe://example.org/ns/backend/sa/orders"));
    }

    @Test
    void shouldParseRootId() {
        SpiffeId id = SpiffeId.parse("spiffe://example.org");

        assertThat(id.isRoot(), is(true));
        assertThat(id.path(), is(SpiffePath.root()));
        assertThat(id.value(), is("spiffe://example.org"));
    }

    @Test
    void shouldRejectInvalidIds() {
        assertThrows(SpiffeException.class, () -> SpiffeId.parse("https://example.org/ns/app"));
        assertThrows(SpiffeException.class, () -> SpiffeId.parse("spiffe://Example.org/ns/app"));
        assertThrows(SpiffeException.class, () -> SpiffeId.parse("spiffe://example_domain/ns/app"));
        assertThrows(SpiffeException.class, () -> SpiffeId.parse("spiffe://-example.org/ns/app"));
        assertThrows(SpiffeException.class, () -> SpiffeId.parse("spiffe://example.org:8443/ns/app"));
        assertThrows(SpiffeException.class, () -> SpiffeId.parse("spiffe://example.org/ns//app"));
        assertThrows(SpiffeException.class, () -> SpiffeId.parse("spiffe://example.org/ns/../app"));
        assertThrows(SpiffeException.class, () -> SpiffeId.parse("spiffe://example.org/ns/app?debug=true"));
    }

    @Test
    void shouldMatchByPrefix() {
        SpiffeIdMatcher matcher = SpiffeIdMatcher.startsWith(SpiffeId.parse("spiffe://example.org/ns/backend"));

        assertThat(matcher.matches(SpiffeId.parse("spiffe://example.org/ns/backend/sa/orders")), is(true));
        assertThat(matcher.matches(SpiffeId.parse("spiffe://example.org/ns/frontend/sa/web")), is(false));
        assertThat(matcher.matches(SpiffeId.parse("spiffe://other.example/ns/backend/sa/orders")), is(false));
    }
}
