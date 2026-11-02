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

class OidcOutboundPolicyConfigTest {
    // RFC 8707 §2 (https://www.rfc-editor.org/rfc/rfc8707.html#section-2):
    // the resource "value MUST be an absolute URI" and "MUST NOT include a fragment component."
    // An application's scope names and configured resource identifiers are not prescribed by the RFC.
    @Test
    void clientCredentialsGrantValidatesResources() {
        OidcOutboundPolicyConfig policy = OidcOutboundPolicyConfig.builder()
                .strategy(OidcOutboundStrategy.CLIENT_CREDENTIALS)
                .addClientCredentialsScope("inventory.read")
                .addClientCredentialsResource("https://inventory.example.com")
                .buildPrototype();

        assertThat(policy.clientCredentialsScopes(), is(List.of("inventory.read")));
        assertThat(policy.clientCredentialsResources(), is(List.of("https://inventory.example.com")));

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                                                          () -> OidcOutboundPolicyConfig.builder()
                                                                  .strategy(OidcOutboundStrategy.CLIENT_CREDENTIALS)
                                                                  .addClientCredentialsScope("inventory.read")
                                                                  .addClientCredentialsResource("inventory")
                                                                  .buildPrototype());
        assertThat(exception.getMessage(), containsString("client-credentials-resources"));
    }

    // RFC 8707 §2 requires an absolute RFC 3986 URI; these inputs are not RFC 3986 URI syntax.
    // Unicode, when desired, has to be percent-encoded in the URI rather than inserted verbatim.
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
                                                              () -> OidcOutboundPolicyConfig.builder()
                                                                      .strategy(OidcOutboundStrategy.CLIENT_CREDENTIALS)
                                                                      .addClientCredentialsResource(resource)
                                                                      .buildPrototype(),
                                                              resource);
            assertThat(exception.getMessage(), containsString("client-credentials-resources"));
            assertThat(exception.getMessage(), containsString("invalid resource URI"));
        }
    }

    // RFC 8707 §2: the resource "SHOULD NOT include a query component" but explicitly
    // allows one when necessary. These examples test URI syntax, not OP acceptance
    // (nor a promise that an OP will recognize a `file` resource identifier).
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
            OidcOutboundPolicyConfig policy = OidcOutboundPolicyConfig.builder()
                    .strategy(OidcOutboundStrategy.CLIENT_CREDENTIALS)
                    .addClientCredentialsResource(resource)
                    .buildPrototype();
            assertThat(policy.clientCredentialsResources(), is(List.of(resource)));
        }
    }

    // RFC 8693 §2.1 (https://www.rfc-editor.org/rfc/rfc8693.html#section-2.1):
    // resource "MUST be an absolute URI" and "MUST NOT include a fragment component."
    @Test
    void tokenExchangeForResourceValidatesResource() {
        OidcOutboundPolicyConfig policy = OidcOutboundPolicyConfig.builder()
                .strategy(OidcOutboundStrategy.TOKEN_EXCHANGE)
                .addTokenExchangeScope("orders.read")
                .tokenExchangeResource("https://orders.example.com")
                .buildPrototype();

        assertThat(policy.tokenExchangeScopes(), is(List.of("orders.read")));
        assertThat(policy.tokenExchangeResource().orElseThrow(), is("https://orders.example.com"));

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                                                          () -> OidcOutboundPolicyConfig.builder()
                                                                  .strategy(OidcOutboundStrategy.TOKEN_EXCHANGE)
                                                                  .addTokenExchangeScope("orders.read")
                                                                  .tokenExchangeResource("https://orders.example.com#fragment")
                                                                  .buildPrototype());
        assertThat(exception.getMessage(), containsString("token-exchange-resource"));
    }

    // RFC 8693 §2.1: audience is "OPTIONAL. The logical name of the target service";
    // specifying it without the optional resource is a valid token-exchange request.
    @Test
    void tokenExchangeForAudienceUsesAudienceOnly() {
        OidcOutboundPolicyConfig policy = OidcOutboundPolicyConfig.builder()
                .strategy(OidcOutboundStrategy.TOKEN_EXCHANGE)
                .addTokenExchangeScope("orders.read")
                .tokenExchangeAudience("api://orders")
                .buildPrototype();

        assertThat(policy.tokenExchangeScopes(), is(List.of("orders.read")));
        assertThat(policy.tokenExchangeResource().isEmpty(), is(true));
        assertThat(policy.tokenExchangeAudience().orElseThrow(), is("api://orders"));
    }

    // RFC 8693 §2.1: "The `audience` and `resource` parameters may be used together".
    // This validates the configuration's retention of both, not an AS token exchange.
    @Test
    void tokenExchangeUsesResourceAndAudience() {
        OidcOutboundPolicyConfig policy = OidcOutboundPolicyConfig.builder()
                .strategy(OidcOutboundStrategy.TOKEN_EXCHANGE)
                .addTokenExchangeScope("orders.read")
                .tokenExchangeResource("https://orders.example.com")
                .tokenExchangeAudience("api://orders")
                .buildPrototype();

        assertThat(policy.tokenExchangeScopes(), is(List.of("orders.read")));
        assertThat(policy.tokenExchangeResource().orElseThrow(), is("https://orders.example.com"));
        assertThat(policy.tokenExchangeAudience().orElseThrow(), is("api://orders"));
    }

    // Choosing exactly one outbound strategy per target is Helidon configuration,
    // not an OAuth restriction on the number of grant types a client can support.
    @Test
    void oneStrategyIsSelectedPerPolicy() {
        OidcOutboundPolicyConfig none = OidcOutboundPolicyConfig.create();
        assertThat(none.strategy(), is(OidcOutboundStrategy.NONE));
        assertThat(OidcOutboundPolicy.fromConfig(none).isEmpty(), is(true));

        for (OidcOutboundStrategy strategy : List.of(OidcOutboundStrategy.TOKEN_PROPAGATION,
                                                     OidcOutboundStrategy.CLIENT_CREDENTIALS,
                                                     OidcOutboundStrategy.TOKEN_EXCHANGE)) {
            OidcOutboundPolicyConfig.Builder builder = OidcOutboundPolicyConfig.builder().strategy(strategy);
            if (strategy == OidcOutboundStrategy.TOKEN_PROPAGATION) {
                builder.audience("api://orders");
            } else if (strategy == OidcOutboundStrategy.TOKEN_EXCHANGE) {
                builder.tokenExchangeAudience("api://orders");
            }
            OidcOutboundPolicyConfig policy = builder.buildPrototype();
            assertThat(policy.strategy(), is(strategy));
            assertThat(OidcOutboundPolicy.fromConfig(policy).isPresent(), is(true));
        }
    }
}
