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

import io.helidon.common.uri.UriQuery;
import io.helidon.security.SecurityEnvironment;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

/* RFC 6750, OAuth 2.0 Bearer Token Usage: https://www.rfc-editor.org/rfc/rfc6750.html */
class OidcBearerTokenExtractorTest {
    // RFC 6750, 2.1: "Resource servers MUST support this method." RFC 9110, 11.1:
    // "It uses a case-insensitive token to identify the authentication scheme".
    @Test
    void extractsAuthorizationHeaderBearerToken() {
        OidcBearerTokenExtractionResult result = OidcBearerTokenExtractor.extract(
                SecurityEnvironment.builder()
                        .targetUri(URI.create("https://rp.example/resource"))
                        .header("Authorization", "bearer   access-token")
                        .build(),
                OidcTokenTransportConfig.create());

        assertThat(result.invalidRequest(), is(false));
        assertThat(result.bearerToken().orElseThrow(), is("access-token"));
    }

    @Test
    void ignoresAuthorizationHeaderWhenTransportIsDisabled() {
        OidcBearerTokenExtractionResult result = OidcBearerTokenExtractor.extract(
                SecurityEnvironment.builder()
                        .header("Authorization", "Bearer access-token")
                        .build(),
                OidcTokenTransportConfig.builder()
                        .authorizationHeaderEnabled(false)
                        .buildPrototype());

        assertThat(result.bearerToken().isEmpty(), is(true));
        assertThat(result.invalidRequest(), is(false));
    }

    // RFC 6750, 2.3: the query transport uses the "access_token" parameter;
    // it is optional in Helidon and RFC 6750 says its use SHOULD NOT occur when a header is possible.
    @Test
    void extractsQueryParameterBearerTokenWhenTransportIsEnabled() {
        OidcBearerTokenExtractionResult result = OidcBearerTokenExtractor.extract(
                SecurityEnvironment.builder()
                        .targetUri(URI.create("https://rp.example/resource"))
                        .queryParam("access_token", "access-token")
                        .build(),
                OidcTokenTransportConfig.builder()
                        .queryParameterEnabled(true)
                        .buildPrototype());

        assertThat(result.invalidRequest(), is(false));
        assertThat(result.bearerToken().orElseThrow(), is("access-token"));
    }

    // RFC 6750, 5.2: "confidentiality protection MUST be applied using TLS".
    @Test
    void rejectsAuthorizationHeaderBearerTokenOverInsecureTransport() {
        OidcBearerTokenExtractionResult result = OidcBearerTokenExtractor.extract(
                SecurityEnvironment.builder()
                        .targetUri(URI.create("http://rp.example/resource"))
                        .transport("http")
                        .header("Authorization", "Bearer access-token")
                        .build(),
                OidcTokenTransportConfig.create());

        assertThat(result.bearerToken().isEmpty(), is(true));
        assertThat(result.invalidRequest(), is(true));
        assertThat(result.errorDescription().orElse(""), is("Bearer Token requires secure transport"));
    }

    // Deliberate development opt-out of the RFC 6750 TLS requirement; not a conformant deployment default.
    @Test
    void acceptsAuthorizationHeaderBearerTokenOverInsecureTransportWhenDisabled() {
        OidcBearerTokenExtractionResult result = OidcBearerTokenExtractor.extract(
                SecurityEnvironment.builder()
                        .targetUri(URI.create("http://rp.example/resource"))
                        .transport("http")
                        .header("Authorization", "Bearer access-token")
                        .build(),
                OidcTokenTransportConfig.builder()
                        .secureTransportRequired(false)
                        .buildPrototype());

        assertThat(result.invalidRequest(), is(false));
        assertThat(result.bearerToken().orElseThrow(), is("access-token"));
    }

    @Test
    void acceptsAuthorizationHeaderBearerTokenWhenTargetUriIsSecure() {
        OidcBearerTokenExtractionResult result = OidcBearerTokenExtractor.extract(
                SecurityEnvironment.builder()
                        .targetUri(URI.create("https://rp.example/resource"))
                        .transport("http")
                        .header("Authorization", "Bearer access-token")
                        .build(),
                OidcTokenTransportConfig.create());

        assertThat(result.invalidRequest(), is(false));
        assertThat(result.bearerToken().orElseThrow(), is("access-token"));
    }

    @Test
    void acceptsAuthorizationHeaderBearerTokenWhenTransportIsSecureAndTargetUriIsMissing() {
        OidcBearerTokenExtractionResult result = OidcBearerTokenExtractor.extract(
                SecurityEnvironment.builder()
                        .transport("https")
                        .header("Authorization", "Bearer access-token")
                        .build(),
                OidcTokenTransportConfig.create());

        assertThat(result.invalidRequest(), is(false));
        assertThat(result.bearerToken().orElseThrow(), is("access-token"));
    }

    @Test
    void rejectsAuthorizationHeaderBearerTokenWhenTargetUriIsInsecure() {
        OidcBearerTokenExtractionResult result = OidcBearerTokenExtractor.extract(
                SecurityEnvironment.builder()
                        .targetUri(URI.create("http://rp.example/resource"))
                        .transport("https")
                        .header("Authorization", "Bearer access-token")
                        .build(),
                OidcTokenTransportConfig.create());

        assertThat(result.bearerToken().isEmpty(), is(true));
        assertThat(result.invalidRequest(), is(true));
        assertThat(result.errorDescription().orElse(""), is("Bearer Token requires secure transport"));
    }

    @Test
    void rejectsAuthorizationHeaderBearerTokenWhenOnlyHostIsPresent() {
        OidcBearerTokenExtractionResult result = OidcBearerTokenExtractor.extract(
                SecurityEnvironment.builder()
                        .header("Host", "rp.example")
                        .header("Authorization", "Bearer access-token")
                        .build(),
                OidcTokenTransportConfig.create());

        assertThat(result.bearerToken().isEmpty(), is(true));
        assertThat(result.invalidRequest(), is(true));
        assertThat(result.errorDescription().orElse(""), is("Bearer Token requires secure transport"));
    }

    @Test
    void rejectsAuthorizationHeaderBearerTokenWhenOnlyForwardedProtoIsSecure() {
        OidcBearerTokenExtractionResult result = OidcBearerTokenExtractor.extract(
                SecurityEnvironment.builder()
                        .header("X-Forwarded-Proto", "https")
                        .header("Authorization", "Bearer access-token")
                        .build(),
                OidcTokenTransportConfig.create());

        assertThat(result.bearerToken().isEmpty(), is(true));
        assertThat(result.invalidRequest(), is(true));
        assertThat(result.errorDescription().orElse(""), is("Bearer Token requires secure transport"));
    }

    @Test
    void rejectsQueryParameterBearerTokenOverInsecureTransport() {
        OidcBearerTokenExtractionResult result = OidcBearerTokenExtractor.extract(
                SecurityEnvironment.builder()
                        .targetUri(URI.create("http://rp.example/resource"))
                        .transport("http")
                        .queryParam("access_token", "access-token")
                        .build(),
                OidcTokenTransportConfig.builder()
                        .queryParameterEnabled(true)
                        .buildPrototype());

        assertThat(result.bearerToken().isEmpty(), is(true));
        assertThat(result.invalidRequest(), is(true));
        assertThat(result.errorDescription().orElse(""), is("Bearer Token requires secure transport"));
    }

    @Test
    void ignoresQueryParameterWhenTransportIsDisabled() {
        OidcBearerTokenExtractionResult result = OidcBearerTokenExtractor.extract(
                SecurityEnvironment.builder()
                        .queryParam("access_token", "access-token")
                        .build(),
                OidcTokenTransportConfig.create());

        assertThat(result.bearerToken().isEmpty(), is(true));
        assertThat(result.invalidRequest(), is(false));
    }

    // RFC 6750, 2: "Clients MUST NOT use more than one method to transmit the token in each request."
    @Test
    void rejectsMultipleCredentialSources() {
        OidcBearerTokenExtractionResult result = OidcBearerTokenExtractor.extract(
                SecurityEnvironment.builder()
                        .header("Authorization", "Bearer header-token")
                        .queryParam("access_token", "query-token")
                        .build(),
                OidcTokenTransportConfig.builder()
                        .queryParameterEnabled(true)
                        .buildPrototype());

        assertThat(result.bearerToken().isEmpty(), is(true));
        assertThat(result.invalidRequest(), is(true));
        assertThat(result.errorDescription().orElse(""), is("Multiple Bearer Token credential sources found"));
    }

    @Test
    void rejectsMultipleAuthorizationHeaderBearerTokens() {
        OidcBearerTokenExtractionResult result = OidcBearerTokenExtractor.extract(
                SecurityEnvironment.builder()
                        .header("Authorization", List.of("Bearer first-token", "Bearer second-token"))
                        .build(),
                OidcTokenTransportConfig.create());

        assertThat(result.bearerToken().isEmpty(), is(true));
        assertThat(result.invalidRequest(), is(true));
        assertThat(result.errorDescription().orElse(""), is("Multiple Bearer Tokens found in Authorization header"));
    }

    @Test
    void rejectsMultipleQueryParameterBearerTokens() {
        OidcBearerTokenExtractionResult result = OidcBearerTokenExtractor.extract(
                SecurityEnvironment.builder()
                        .queryParam("access_token", List.of("first-token", "second-token"))
                        .build(),
                OidcTokenTransportConfig.builder()
                        .queryParameterEnabled(true)
                        .buildPrototype());

        assertThat(result.bearerToken().isEmpty(), is(true));
        assertThat(result.invalidRequest(), is(true));
        assertThat(result.errorDescription().orElse(""), is("Multiple Bearer Tokens found in query parameter"));
    }

    @Test
    void rejectsRepeatedQueryParameterBearerTokensFromTargetUri() {
        OidcBearerTokenExtractionResult result = OidcBearerTokenExtractor.extract(
                SecurityEnvironment.builder()
                        .targetUri(URI.create("https://rp.example/resource?access_token=first-token&access_token=second-token"))
                        .queryParam("access_token", "second-token")
                        .build(),
                OidcTokenTransportConfig.builder()
                        .queryParameterEnabled(true)
                        .buildPrototype());

        assertThat(result.bearerToken().isEmpty(), is(true));
        assertThat(result.invalidRequest(), is(true));
        assertThat(result.errorDescription().orElse(""), is("Multiple Bearer Tokens found in query parameter"));
    }

    @Test
    void rejectsEncodedRepeatedQueryParameterBearerTokensFromTargetUri() {
        OidcBearerTokenExtractionResult result = OidcBearerTokenExtractor.extract(
                SecurityEnvironment.builder()
                        .targetUri(URI.create("https://rp.example/resource?access%5Ftoken=first-token&access_token=second-token"))
                        .queryParam("access_token", "second-token")
                        .build(),
                OidcTokenTransportConfig.builder()
                        .queryParameterEnabled(true)
                        .buildPrototype());

        assertThat(result.bearerToken().isEmpty(), is(true));
        assertThat(result.invalidRequest(), is(true));
        assertThat(result.errorDescription().orElse(""), is("Multiple Bearer Tokens found in query parameter"));
    }

    // RFC 6750, 2.1: "credentials = \"Bearer\" 1*SP b64token"; an empty token is not b64token.
    @Test
    void rejectsMalformedAuthorizationHeaderBearerToken() {
        OidcBearerTokenExtractionResult result = OidcBearerTokenExtractor.extract(
                SecurityEnvironment.builder()
                        .header("Authorization", "Bearer ")
                        .build(),
                OidcTokenTransportConfig.create());

        assertThat(result.bearerToken().isEmpty(), is(true));
        assertThat(result.invalidRequest(), is(true));
        assertThat(result.errorDescription().orElse(""), is("Malformed Bearer Token in Authorization header"));
    }

    // RFC 6750, 2.1: "credentials = \"Bearer\" 1*SP b64token"; trailing whitespace is not padding.
    @Test
    void rejectsTrailingWhitespaceInAuthorizationHeaderBearerToken() {
        OidcBearerTokenExtractionResult result = OidcBearerTokenExtractor.extract(
                SecurityEnvironment.builder()
                        .header("Authorization", "Bearer access-token ")
                        .build(),
                OidcTokenTransportConfig.create());

        assertThat(result.bearerToken().isEmpty(), is(true));
        assertThat(result.invalidRequest(), is(true));
        assertThat(result.errorDescription().orElse(""), is("Malformed Bearer Token in Authorization header"));
    }

    @Test
    void rejectsAuthorizationHeaderBearerTokenWithInvalidCharacters() {
        OidcBearerTokenExtractionResult result = OidcBearerTokenExtractor.extract(
                SecurityEnvironment.builder()
                        .header("Authorization", "Bearer access,token")
                        .build(),
                OidcTokenTransportConfig.create());

        assertThat(result.bearerToken().isEmpty(), is(true));
        assertThat(result.invalidRequest(), is(true));
        assertThat(result.errorDescription().orElse(""), is("Malformed Bearer Token in Authorization header"));
    }

    // RFC 6750, 2.1: "b64token =" permits a trailing sequence of "=" padding, not an embedded "=".
    @Test
    void rejectsAuthorizationHeaderBearerTokenWithMisplacedPadding() {
        OidcBearerTokenExtractionResult result = OidcBearerTokenExtractor.extract(
                SecurityEnvironment.builder()
                        .header("Authorization", "Bearer access=token")
                        .build(),
                OidcTokenTransportConfig.create());

        assertThat(result.bearerToken().isEmpty(), is(true));
        assertThat(result.invalidRequest(), is(true));
        assertThat(result.errorDescription().orElse(""), is("Malformed Bearer Token in Authorization header"));
    }

    // RFC 6750, 2.1: the scheme is followed by "1*SP", not a tab.
    @Test
    void rejectsTabSeparatedAuthorizationHeaderBearerToken() {
        OidcBearerTokenExtractionResult result = OidcBearerTokenExtractor.extract(
                SecurityEnvironment.builder()
                        .header("Authorization", "Bearer\taccess-token")
                        .build(),
                OidcTokenTransportConfig.create());

        assertThat(result.bearerToken().isEmpty(), is(true));
        assertThat(result.invalidRequest(), is(true));
        assertThat(result.errorDescription().orElse(""), is("Malformed Bearer Token in Authorization header"));
    }

    @Test
    void rejectsMalformedQueryParameterBearerToken() {
        OidcBearerTokenExtractionResult result = OidcBearerTokenExtractor.extract(
                SecurityEnvironment.builder()
                        .queryParam("access_token", " ")
                        .build(),
                OidcTokenTransportConfig.builder()
                        .queryParameterEnabled(true)
                        .buildPrototype());

        assertThat(result.bearerToken().isEmpty(), is(true));
        assertThat(result.invalidRequest(), is(true));
        assertThat(result.errorDescription().orElse(""), is("Malformed Bearer Token in query parameter"));
    }

    @Test
    void rejectsQueryParameterBearerTokenWithInvalidCharacters() {
        OidcBearerTokenExtractionResult result = OidcBearerTokenExtractor.extract(
                SecurityEnvironment.builder()
                        .queryParam("access_token", "access,token")
                        .build(),
                OidcTokenTransportConfig.builder()
                        .queryParameterEnabled(true)
                        .buildPrototype());

        assertThat(result.bearerToken().isEmpty(), is(true));
        assertThat(result.invalidRequest(), is(true));
        assertThat(result.errorDescription().orElse(""), is("Malformed Bearer Token in query parameter"));
    }

    @Test
    void rejectsBareQueryParameterBearerToken() {
        OidcBearerTokenExtractionResult result = OidcBearerTokenExtractor.extract(
                SecurityEnvironment.builder()
                        .queryParams(UriQuery.create("access_token"))
                        .build(),
                OidcTokenTransportConfig.builder()
                        .queryParameterEnabled(true)
                        .buildPrototype());

        assertThat(result.bearerToken().isEmpty(), is(true));
        assertThat(result.invalidRequest(), is(true));
        assertThat(result.errorDescription().orElse(""), is("Malformed Bearer Token in query parameter"));
    }

    @Test
    void rejectsBareQueryParameterBearerTokenWithAnotherQueryToken() {
        OidcBearerTokenExtractionResult result = OidcBearerTokenExtractor.extract(
                SecurityEnvironment.builder()
                        .targetUri(URI.create("https://rp.example/resource?access_token&access_token=access-token"))
                        .queryParams(UriQuery.create("access_token&access_token=access-token"))
                        .build(),
                OidcTokenTransportConfig.builder()
                        .queryParameterEnabled(true)
                        .buildPrototype());

        assertThat(result.bearerToken().isEmpty(), is(true));
        assertThat(result.invalidRequest(), is(true));
        assertThat(result.errorDescription().orElse(""), is("Multiple Bearer Tokens found in query parameter"));
    }

    // RFC 6750, 2.3: the parameter carries the token; surrounding whitespace is not token content.
    @Test
    void rejectsSurroundingWhitespaceInQueryParameterBearerToken() {
        OidcBearerTokenExtractionResult result = OidcBearerTokenExtractor.extract(
                SecurityEnvironment.builder()
                        .queryParam("access_token", " access-token ")
                        .build(),
                OidcTokenTransportConfig.builder()
                        .queryParameterEnabled(true)
                        .buildPrototype());

        assertThat(result.bearerToken().isEmpty(), is(true));
        assertThat(result.invalidRequest(), is(true));
        assertThat(result.errorDescription().orElse(""), is("Malformed Bearer Token in query parameter"));
    }

    // RFC 6750, 2.1: "b64token" ends with "*\"=\""; real base64url padding must be accepted.
    @Test
    void acceptsBearerTokenWithTrailingEqualsPadding() {
        SecurityEnvironment environment = SecurityEnvironment.builder()
                .targetUri(URI.create("https://rp.example/resource"))
                .header("Authorization", "Bearer access-token==")
                .queryParam("access_token", "access-token==")
                .build();

        assertThat(OidcBearerTokenExtractor.extract(environment, OidcTokenTransportConfig.create())
                           .bearerToken().orElseThrow(), is("access-token=="));
        assertThat(OidcBearerTokenExtractor.extract(environment, OidcTokenTransportConfig.builder()
                           .authorizationHeaderEnabled(false).queryParameterEnabled(true).buildPrototype())
                           .bearerToken().orElseThrow(), is("access-token=="));
    }
}
