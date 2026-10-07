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

package io.helidon.security.jwt;

import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

import io.helidon.common.configurable.Resource;
import io.helidon.json.JsonArray;
import io.helidon.json.JsonNull;
import io.helidon.json.JsonNumber;
import io.helidon.json.JsonObject;
import io.helidon.json.JsonParser;
import io.helidon.json.JsonString;
import io.helidon.security.jwt.jwk.Jwk;
import io.helidon.security.jwt.jwk.JwkKeys;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SignedJwtPayloadTest {
    private static final String KEY_ID = "cc34c0a0-bd5a-4a3c-a50d-a2a7db7643df";

    private static JwkKeys keys;
    private static Jwk key;
    private static JwtHeaders headers;

    @BeforeAll
    static void init() {
        keys = JwkKeys.builder().resource(Resource.create("jwk_data.json")).build();
        key = keys.forKeyId(KEY_ID).orElseThrow();
        headers = JwtHeaders.builder().algorithm("RS256").keyId(KEY_ID).type("JWT").build();
    }

    @Test
    void signsExactJsonValuesWithoutProfileClaimCoercion() {
        JsonObject payload = JsonObject.builder()
                .set("name", "Alice")
                .set("email_verified", true)
                .set("precise", new BigDecimal("9007199254740993.25"))
                .set("claims", JsonObject.builder().set("userinfo", JsonObject.builder()
                        .set("email", JsonObject.builder().set("essential", true).build())
                        .set("nickname", JsonNull.instance()).build()).build())
                .set("array", JsonArray.create(List.of(JsonString.create("000300"), JsonNumber.create(300), JsonNull.instance())))
                .build();

        SignedJwt signed = SignedJwt.sign(headers, payload, key);
        JsonObject encoded = JsonParser.create(Base64.getUrlDecoder().decode(signed.tokenContent().split("\\.")[1]))
                .readJsonObject();

        assertThat(encoded, is(payload));
        assertThat(signed.headerJson(), is(headers.headerJsonObject()));
        assertThat(signed.verifySignature(keys).isValid(), is(true));
        assertThat(SignedJwt.parseToken(signed.tokenContent()).verifySignature(keys).isValid(), is(true));
    }

    @Test
    void existingJwtSigningUsesTheSameCompactRepresentation() {
        Jwt jwt = Jwt.builder().algorithm("RS256").keyId(KEY_ID).issuer("issuer").subject("subject").build();

        assertThat(SignedJwt.sign(jwt, key).tokenContent(),
                   is(SignedJwt.sign(jwt.headers(), jwt.payloadJsonObject(), key).tokenContent()));
    }

    @Test
    void changedJsonPayloadCannotVerifyWithTheOriginalSignature() {
        SignedJwt original = SignedJwt.sign(headers, JsonObject.builder().set("name", "Alice").build(), key);
        String[] parts = original.tokenContent().split("\\.");
        String changed = Base64.getUrlEncoder().withoutPadding().encodeToString(
                JsonObject.builder().set("name", "Bob").build().toString().getBytes(StandardCharsets.UTF_8));

        SignedJwt tampered = SignedJwt.parseToken(parts[0] + "." + changed + "." + parts[2]);
        assertThat(tampered.verifySignature(keys).isValid(), is(false));
    }

    @Test
    void jsonSigningRejectsNullInputs() {
        JsonObject payload = JsonObject.builder().set("value", "value").build();

        assertThrows(NullPointerException.class, () -> SignedJwt.sign(null, payload, key));
        assertThrows(NullPointerException.class, () -> SignedJwt.sign(headers, null, key));
        assertThrows(NullPointerException.class, () -> SignedJwt.sign(headers, payload, null));
    }
}
