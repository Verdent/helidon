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

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import io.helidon.json.JsonArray;
import io.helidon.json.JsonBoolean;
import io.helidon.json.JsonNull;
import io.helidon.json.JsonNumber;
import io.helidon.json.JsonObject;
import io.helidon.json.JsonString;
import io.helidon.json.JsonValue;
import io.helidon.security.SecurityEnvironment;
import io.helidon.security.providers.oidc.next.spi.OidcTenantAdapter;

import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertThrows;

class OidcAuthorizationParametersTest {
    @Test
    void snapshotsCallerMapsAndListsAndProtectsAccessors() {
        List<JsonValue> values = new ArrayList<>(List.of(JsonString.create("first")));
        Map<String, List<JsonValue>> source = new LinkedHashMap<>();
        source.put("custom", values);
        OidcAuthorizationParameters request = OidcAuthorizationParameters.builder().parameters(source).buildPrototype();
        OidcAuthorizationParameters snapshot = OidcAuthorizationParameters.builder(() -> source).buildPrototype();
        values.add(JsonString.create("second"));
        source.clear();

        assertThat(request.parameters(), is(Map.of("custom", List.of(JsonString.create("first")))));
        assertThat(snapshot.parameters(), is(request.parameters()));
        assertThrows(UnsupportedOperationException.class, () -> request.parameters().clear());
        assertThrows(UnsupportedOperationException.class, () -> request.parameters().get("custom").clear());
        OidcAuthorizationParameters appended = OidcAuthorizationParameters.builder(request)
                .addParameter("custom", JsonString.create("third")).buildPrototype();
        assertThat(appended.parameters().get("custom"), is(List.of(JsonString.create("first"), JsonString.create("third"))));
        assertThat(request.parameters().get("custom"), is(List.of(JsonString.create("first"))));
        assertThat(request.toString(), not(containsString("first")));
    }

    @Test
    void distinguishesStructuredArraysFromRepeatedStringsAndPreservesLookalikes() {
        JsonArray details = JsonArray.create(List.of(JsonObject.builder().set("type", "payment").build()));
        JsonObject claims = JsonObject.builder().set("userinfo", JsonObject.builder().set("nickname", JsonNull.instance())
                .set("email", JsonObject.builder().set("essential", true).build()).build()).build();
        OidcAuthorizationParameters request = OidcAuthorizationParameters.builder()
                .addParameter("max_age", JsonNumber.create(0))
                .addParameter("claims", claims).addParameter("authorization_details", details)
                .addParameter("resource", JsonString.create("https://api.example/one"))
                .addParameter("resource", JsonString.create("urn:two"))
                .addParameter("login_hint", JsonString.create("000300"))
                .addParameter("custom", JsonString.create("{\"x\":1}"))
                .addParameter("custom_null", JsonNull.instance()).buildPrototype();
        JsonObject payload = OidcAuthorizationParameterSupport.payload(request);
        var form = OidcAuthorizationParameterSupport.form(request);

        assertThat(payload.numberValue("max_age").orElseThrow(), is(BigDecimal.ZERO));
        assertThat(payload.objectValue("claims"), is(Optional.of(claims)));
        assertThat(payload.arrayValue("authorization_details"), is(Optional.of(details)));
        assertThat(payload.arrayValue("resource").orElseThrow().values(),
                   is(List.of(JsonString.create("https://api.example/one"), JsonString.create("urn:two"))));
        assertThat(form.all("authorization_details"), is(List.of(details.toString())));
        assertThat(form.all("resource"), is(List.of("https://api.example/one", "urn:two")));
        assertThat(form.get("login_hint"), is("000300"));
        assertThat(payload.stringValue("custom").orElseThrow(), is("{\"x\":1}"));
        assertThat(form.get("custom_null"), is("null"));
        assertThat(OidcAuthorizationParameterSupport.requiredString(request, "login_hint"), is("000300"));
        assertThrows(IllegalStateException.class, () -> OidcAuthorizationParameterSupport.requiredString(request, "absent"));
        assertThrows(IllegalStateException.class, () -> OidcAuthorizationParameterSupport.requiredString(request, "max_age"));
    }

    @Test
    void serializesIntegralMaxAgeAsWholeSecondsInBothTransports() {
        for (BigDecimal age : List.of(new BigDecimal("300.0"), new BigDecimal("3E+2"))) {
            OidcAuthorizationParameters request = OidcAuthorizationParameters.builder()
                    .addParameter("max_age", JsonNumber.create(age)).buildPrototype();

            assertThat(OidcAuthorizationParameterSupport.form(request).get("max_age"), is("300"));
            assertThat(OidcAuthorizationParameterSupport.payload(request).numberValue("max_age"),
                       is(Optional.of(BigDecimal.valueOf(300))));
        }
    }

    @Test
    void defaultAdapterPreservesTheRequestAndRejectsNullInputs() {
        OidcTenantAdapter adapter = new OidcTenantAdapter() {
            @Override
            public String name() {
                return "default-typed-test";
            }

            @Override
            public String type() {
                return "default-typed-test";
            }
        };
        OidcTenantConfig tenant = OidcTenantConfig.builder().issuer("https://issuer.example").clientId("client")
                .buildPrototype();
        SecurityEnvironment environment = SecurityEnvironment.builder().build();
        OidcAuthorizationParameters parameters = OidcAuthorizationParameters.create();

        assertThat(adapter.authorizationRequest(tenant, "default", environment, parameters), is(parameters));
        assertThrows(NullPointerException.class, () -> adapter.authorizationRequest(null, "default", environment, parameters));
        assertThrows(NullPointerException.class, () -> adapter.authorizationRequest(tenant, null, environment, parameters));
        assertThrows(NullPointerException.class, () -> adapter.authorizationRequest(tenant, "default", null, parameters));
        assertThrows(NullPointerException.class, () -> adapter.authorizationRequest(tenant, "default", environment, null));
    }

    @Test
    void validatesStandardTypesCardinalityAndReservedNames() {
        for (Map.Entry<String, List<JsonValue>> invalid : List.of(
                Map.entry("", List.<JsonValue>of(JsonString.create("value"))),
                Map.entry("bad name", List.<JsonValue>of(JsonString.create("value"))),
                Map.entry("bad\nname", List.<JsonValue>of(JsonString.create("value"))),
                Map.entry("bad\0name", List.<JsonValue>of(JsonString.create("value"))),
                Map.entry("custom", List.<JsonValue>of()),
                Map.entry("nonce", List.<JsonValue>of(JsonNumber.create(1))),
                Map.entry("state", List.<JsonValue>of(JsonString.create("a"), JsonString.create("b"))),
                Map.entry("max_age", List.<JsonValue>of(JsonString.create("300"))),
                Map.entry("max_age", List.<JsonValue>of(JsonNumber.create(-1))),
                Map.entry("max_age", List.<JsonValue>of(JsonNumber.create(new BigDecimal("1.5")))),
                Map.entry("max_age", List.<JsonValue>of(JsonNumber.create(new BigDecimal("9223372036854775808")))),
                Map.entry("max_age", List.<JsonValue>of(JsonNumber.create(1), JsonNumber.create(2))),
                Map.entry("claims", List.<JsonValue>of(JsonArray.create(List.of()))),
                Map.entry("claims", List.<JsonValue>of(JsonObject.builder().build(), JsonObject.builder().build())),
                Map.entry("authorization_details", List.<JsonValue>of(JsonObject.builder().build())),
                Map.entry("authorization_details", List.<JsonValue>of(JsonArray.create(List.of()), JsonArray.create(List.of()))),
                Map.entry("authorization_details", List.<JsonValue>of(JsonArray.create(List.of(JsonString.create("bad"))))),
                Map.entry("authorization_details", List.<JsonValue>of(JsonArray.create(List.of(JsonObject.builder().build())))),
                Map.entry("authorization_details", List.<JsonValue>of(JsonArray.create(List.of(JsonObject.builder()
                        .set("type", true).build())))),
                Map.entry("authorization_details", List.<JsonValue>of(JsonArray.create(List.of(JsonObject.builder()
                        .set("type", " ").build())))),
                Map.entry("resource", List.<JsonValue>of(JsonBoolean.create(true))),
                Map.entry("resource", List.<JsonValue>of(JsonString.create("relative"))),
                Map.entry("resource", List.<JsonValue>of(JsonString.create("https://api.example/bad path"))),
                Map.entry("resource", List.<JsonValue>of(JsonString.create("https://api.example/#fragment"))),
                Map.entry("registration", List.<JsonValue>of(JsonObject.builder().build())))) {
            assertThrows(IllegalArgumentException.class,
                         () -> OidcAuthorizationParameters.builder().putParameter(invalid.getKey(), invalid.getValue())
                                 .buildPrototype(), invalid.getKey());
        }
        for (String name : List.of("request", "request_uri", "iss", "aud", "iat", "exp", "nbf", "jti")) {
            assertThrows(IllegalArgumentException.class, () -> OidcAuthorizationParameters.builder()
                    .addParameter(name, JsonString.create("value")).buildPrototype());
        }
        assertThat(OidcAuthorizationParameters.builder().addParameter("max_age", JsonNumber.create(Long.MAX_VALUE))
                           .buildPrototype().parameters().get("max_age"), is(List.of(JsonNumber.create(Long.MAX_VALUE))));
    }
}
