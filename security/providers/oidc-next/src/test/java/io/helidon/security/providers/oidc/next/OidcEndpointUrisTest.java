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
import java.util.List;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

/*
 * RFC 9110 §§4.2.1-4.2.2, https://www.rfc-editor.org/rfc/rfc9110.html#section-4.2.1:
 * "A recipient that processes such a URI reference MUST reject it as invalid" when the
 * http or https host is empty. Disabling Helidon's TLS requirement does not change URI validity.
 */
class OidcEndpointUrisTest {
    @Test
    void httpEndpointsRejectMissingOrInvalidAuthority() {
        List<OidcEndpointUris.EndpointUriValidator> validators = List.of(
                OidcEndpointUris::validateAuthorizationEndpointUri,
                (uri, _) -> OidcEndpointUris.validatePushedAuthorizationRequestEndpointUri(uri),
                OidcEndpointUris::validateIssuerUri,
                OidcEndpointUris::validateRedirectionEndpointUri,
                OidcEndpointUris::validateJwksUri,
                OidcEndpointUris::validateEndSessionEndpointUri,
                OidcEndpointUris::validateBackChannelLogoutUri,
                OidcEndpointUris::validateUserInfoEndpointUri,
                (uri, tlsRequired) -> OidcEndpointUris.validatePostLogoutRedirectUri(
                        "post-logout-redirect-uri", uri, tlsRequired),
                OidcEndpointUris::validateTokenEndpointUri,
                OidcEndpointUris::validateIntrospectionEndpointUri,
                OidcEndpointUris::validateWellKnownUri);

        for (OidcEndpointUris.EndpointUriValidator validator : validators) {
            for (String value : List.of("https:/token", "https:///token", "https:token", "https://:443/token",
                                        "https://user:password@issuer.example/token",
                                        "https://issuer.example:65536/token")) {
                URI uri = URI.create(value);
                IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
                                                                () -> validator.validate(uri, true), value);
                assertThat(value, failure.getMessage(), containsString("must have a valid HTTP(S) authority"));
            }
        }
    }

    @Test
    void disablingTlsDoesNotPermitHostlessHttpEndpoints() {
        for (String value : List.of("http:/token", "http:///token", "http://:8080/token")) {
            URI uri = URI.create(value);
            IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
                    () -> OidcEndpointUris.validateTokenEndpointUri(uri, false), value);
            assertThat(value, failure.getMessage(), containsString("must have a valid HTTP(S) authority"));
        }
    }

    @Test
    void validAuthoritiesAndNonHttpExceptionsRemainSupported() {
        for (String value : List.of("https://issuer.example/token", "https://api_name/token",
                                    "https://[2001:db8::1]:443/token", "https://issuer.example:/token")) {
            URI uri = URI.create(value);
            assertDoesNotThrow(() -> OidcEndpointUris.validateTokenEndpointUri(uri, true), value);
        }
        assertDoesNotThrow(() -> OidcEndpointUris.validateTokenEndpointUri(URI.create("http://localhost:8080/token"),
                                                                           false));
        assertDoesNotThrow(() -> OidcEndpointUris.validateRedirectionEndpointUri(URI.create("/oidc/callback"), true));
        assertDoesNotThrow(() -> OidcEndpointUris.validateJwksUri(URI.create("file:/tmp/jwks.json"), false));
    }
}
