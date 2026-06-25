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

import java.net.URI;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

class OidcDiagnosticsTest {
    @Test
    void safeUriRemovesSensitiveUriParts() {
        URI uri = URI.create("https://user:secret@issuer.example:8443/.well-known/openid-configuration"
                                     + "?access_token=secret#fragment");

        assertThat(OidcDiagnostics.safeUri(uri),
                   is("https://issuer.example:8443/.well-known/openid-configuration"));
    }

    @Test
    void logValuesReplaceControlCharacters() {
        assertThat(OidcDiagnostics.sanitizeLogValue("first\r\nsecond\tthird"),
                   is("first??second?third"));
    }
}
