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

class OidcBearerTokenExtractorTest {
    @Test
    void extractsAuthorizationHeaderBearerToken() {
        OidcBearerTokenExtractionResult result = OidcBearerTokenExtractor.extract(
                SecurityEnvironment.builder()
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

    @Test
    void extractsQueryParameterBearerTokenWhenTransportIsEnabled() {
        OidcBearerTokenExtractionResult result = OidcBearerTokenExtractor.extract(
                SecurityEnvironment.builder()
                        .queryParam("access_token", "access-token")
                        .build(),
                OidcTokenTransportConfig.builder()
                        .queryParameterEnabled(true)
                        .buildPrototype());

        assertThat(result.invalidRequest(), is(false));
        assertThat(result.bearerToken().orElseThrow(), is("access-token"));
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

    @Test
    void rejectsPaddedAuthorizationHeaderBearerToken() {
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

    @Test
    void rejectsPaddedQueryParameterBearerToken() {
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
}
