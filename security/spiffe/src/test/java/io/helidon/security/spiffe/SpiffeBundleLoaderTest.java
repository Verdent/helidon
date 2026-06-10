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

import java.io.StringReader;
import java.util.Optional;

import io.helidon.common.configurable.Resource;
import io.helidon.json.JsonObject;
import io.helidon.json.JsonParser;
import io.helidon.security.jwt.jwk.Jwk;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SpiffeBundleLoaderTest {
    private static final SpiffeTrustDomain TRUST_DOMAIN = SpiffeTrustDomain.create("example.org");

    @Test
    void shouldNormalizeJwtSvidKeysForSignatureVerification() {
        SpiffeBundle bundle = SpiffeBundleLoader.load(TRUST_DOMAIN, json(TestKeys.PUBLIC_SPIFFE_BUNDLE));

        assertThat(bundle.trustDomain(), is(TRUST_DOMAIN));
        assertThat(bundle.hasJwtSvidKeys(), is(true));
        assertThat(bundle.hasX509Authorities(), is(false));
        assertThat(bundle.jwtSvidKeys().forKeyId(TestKeys.KEY_ID)
                           .flatMap(Jwk::usage), is(Optional.of(Jwk.USE_SIGNATURE)));
    }

    @Test
    void shouldLoadBundleFromResourceContent() {
        SpiffeBundle bundle = SpiffeBundleLoader.load(TRUST_DOMAIN,
                                                      Resource.create("spiffe-bundle", TestKeys.PUBLIC_SPIFFE_BUNDLE));

        assertThat(bundle.hasJwtSvidKeys(), is(true));
    }

    @Test
    void shouldRejectPrivateKeyMaterialInBundle() {
        assertThrows(SpiffeException.class, () -> SpiffeBundleLoader.load(TRUST_DOMAIN, json(TestKeys.PRIVATE_SIGNING_JWK)));
    }

    private static JsonObject json(String content) {
        return JsonParser.create(new StringReader(content)).readJsonObject();
    }
}
