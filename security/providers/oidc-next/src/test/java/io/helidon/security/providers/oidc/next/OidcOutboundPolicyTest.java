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

import java.util.List;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class OidcOutboundPolicyTest {
    @Test
    void clientCredentialsGrantValidatesResources() {
        var policy = OidcOutboundPolicy.clientCredentialsGrant(List.of("inventory.read"),
                                                               List.of("https://inventory.example.com"));

        assertThat(policy.clientCredentialsScope().orElseThrow(), is("inventory.read"));
        assertThat(policy.clientCredentialsResources(), is(List.of("https://inventory.example.com")));

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                                                          () -> OidcOutboundPolicy.clientCredentialsGrant(
                                                                  List.of("inventory.read"),
                                                                  List.of("inventory")));
        assertThat(exception.getMessage(), containsString("Client Credentials Grant resources"));
    }

    @Test
    void resourceIndicatorsRejectNonRfc3986Uris() {
        for (String resource : List.of("https://api.example/items?currency=£",
                                       "https://api.example/items?filter[x]=y",
                                       "https://api.example/£",
                                       "https://api.example/items[0]",
                                       "https://api.example:abc/items",
                                       "https://user@other@api.example/items",
                                       "https://münich.example/items",
                                       "urn:example:part[0]",
                                       "urn:example:£")) {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                                                              () -> OidcOutboundPolicy.clientCredentialsGrant(
                                                                      List.of(), List.of(resource)),
                                                              resource);
            assertThat(exception.getMessage(), containsString("Client Credentials Grant resources"));
            assertThat(exception.getMessage(), containsString("invalid resource URI"));
        }
    }

    @Test
    void resourceIndicatorsPreserveValidRfc3986Uris() {
        for (String resource : List.of("https://api.example/items?currency=%C2%A3",
                                       "https://api.example/items?filter%5Bx%5D=y",
                                       "https://api.example/items?query=a/b?c",
                                       "https://%65xample.com/items",
                                       "https://[2001:db8::1]:443/items",
                                       "urn:example:contacts?role=a=b&literal=+",
                                       "urn:example:%C2%A3",
                                       "file:///tmp/oidc-resource")) {
            OidcOutboundPolicy policy = OidcOutboundPolicy.clientCredentialsGrant(List.of(), List.of(resource));
            assertThat(policy.clientCredentialsResources(), is(List.of(resource)));
        }
    }

    @Test
    void tokenExchangeForResourceValidatesResource() {
        var policy = OidcOutboundPolicy.tokenExchangeForResource(List.of("orders.read"),
                                                                 "https://orders.example.com");

        assertThat(policy.tokenExchangeScope().orElseThrow(), is("orders.read"));
        assertThat(policy.tokenExchangeResource().orElseThrow(), is("https://orders.example.com"));

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                                                          () -> OidcOutboundPolicy.tokenExchangeForResource(
                                                                  List.of("orders.read"),
                                                                  "https://orders.example.com#fragment"));
        assertThat(exception.getMessage(), containsString("Token Exchange resource"));
    }

    @Test
    void tokenExchangeForAudienceUsesAudienceOnly() {
        var policy = OidcOutboundPolicy.tokenExchangeForAudience(List.of("orders.read"), "api://orders");

        assertThat(policy.tokenExchangeScope().orElseThrow(), is("orders.read"));
        assertThat(policy.tokenExchangeResource().isEmpty(), is(true));
        assertThat(policy.tokenExchangeAudience().orElseThrow(), is("api://orders"));
    }

    @Test
    void tokenExchangeUsesResourceAndAudience() {
        var policy = OidcOutboundPolicy.tokenExchange(List.of("orders.read"),
                                                      "https://orders.example.com",
                                                      "api://orders");

        assertThat(policy.tokenExchangeScope().orElseThrow(), is("orders.read"));
        assertThat(policy.tokenExchangeResource().orElseThrow(), is("https://orders.example.com"));
        assertThat(policy.tokenExchangeAudience().orElseThrow(), is("api://orders"));
    }
}
