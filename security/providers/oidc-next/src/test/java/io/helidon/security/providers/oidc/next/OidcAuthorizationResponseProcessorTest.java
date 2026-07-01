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
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import io.helidon.common.uri.UriQuery;
import io.helidon.http.SetCookie;
import io.helidon.json.JsonObject;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

class OidcAuthorizationResponseProcessorTest {
    private static final URI ISSUER = URI.create("https://issuer.example");
    private static final URI AUTHORIZATION_ENDPOINT_URI = URI.create("https://issuer.example/authorize");
    private static final URI TOKEN_ENDPOINT_URI = URI.create("https://issuer.example/token");
    private static final URI REDIRECTION_ENDPOINT_URI = URI.create("https://rp.example/oidc/callback");
    private static final URI OTHER_REDIRECTION_ENDPOINT_URI = URI.create("https://rp.example/other/callback");
    private static final URI ORIGINAL_URI = URI.create("https://rp.example/resource");
    private static final Instant NOW = Instant.parse("2026-05-21T00:00:00Z");
    private static final String STATE = authorizationState("default", 0);
    private static final String OTHER_STATE = authorizationState("default", 1);
    private static final String SECOND_STATE = authorizationState("second", 0);
    private static final String UNKNOWN_STATE = authorizationState("unknown", 0);

    @Test
    void validAuthorizationResponseValidatesStateAndClearsCookie() {
        OidcTenantConfig tenant = authorizationCodeTenant("test-cookie-password", REDIRECTION_ENDPOINT_URI);
        OidcProviderConfig config = providerConfig("default", tenant);
        OidcAuthenticationRequestState state = authenticationRequestState("default",
                                                                          STATE,
                                                                          REDIRECTION_ENDPOINT_URI,
                                                                          NOW.plusSeconds(60));

        OidcAuthorizationResponseResult result = process(config,
                                                         UriQuery.create("code=authorization-code&state=" + STATE),
                                                         cookies(tenant, state),
                                                         URI.create(REDIRECTION_ENDPOINT_URI
                                                                            + "?code=authorization-code&state=" + STATE),
                                                         NOW);

        assertThat(result.stateValidated(), is(true));
        assertThat(result.authorizationCode().orElse(""), is("authorization-code"));
        assertThat(result.tenantContext().orElseThrow().tenantId(), is("default"));
        assertThat(result.authenticationRequestState().orElseThrow().state(), is(STATE));

        SetCookie removalCookie = result.stateCookies().getFirst();
        assertThat(removalCookie.name(), is("__Host-helidon-oidc-state"));
        assertThat(removalCookie.value(), is(""));
        assertThat(removalCookie.maxAge().orElseThrow().getSeconds(), is(0L));
    }

    @Test
    void authorizationResponseIssuerParameterMatchesExpectedIssuer() {
        OidcTenantConfig tenant = authorizationCodeTenant("test-cookie-password", REDIRECTION_ENDPOINT_URI);
        OidcProviderConfig config = providerConfig("default", tenant);
        OidcAuthenticationRequestState state = authenticationRequestState("default",
                                                                          STATE,
                                                                          REDIRECTION_ENDPOINT_URI,
                                                                          NOW.plusSeconds(60));

        OidcAuthorizationResponseResult result = process(config,
                                                         UriQuery.create("code=authorization-code"
                                                                                 + "&state=" + STATE
                                                                                 + "&iss=https%3A%2F%2Fissuer.example"),
                                                         cookies(tenant, state),
                                                         REDIRECTION_ENDPOINT_URI,
                                                         NOW);

        assertThat(result.stateValidated(), is(true));
        assertThat(result.authorizationCode().orElse(""), is("authorization-code"));
    }

    @Test
    void mismatchedAuthorizationResponseIssuerFailsAndClearsCookie() {
        OidcTenantConfig tenant = authorizationCodeTenant("test-cookie-password", REDIRECTION_ENDPOINT_URI);
        OidcProviderConfig config = providerConfig("default", tenant);
        OidcAuthenticationRequestState state = authenticationRequestState("default",
                                                                          STATE,
                                                                          REDIRECTION_ENDPOINT_URI,
                                                                          NOW.plusSeconds(60));

        OidcAuthorizationResponseResult result = process(config,
                                                         UriQuery.create("code=authorization-code"
                                                                                 + "&state=" + STATE
                                                                                 + "&iss=https%3A%2F%2Fother.example"),
                                                         cookies(tenant, state),
                                                         REDIRECTION_ENDPOINT_URI,
                                                         NOW);

        assertThat(result.invalid(), is(true));
        assertThat(result.description(), is("Authorization Response iss does not match Authentication Request issuer"));
        assertThat(result.stateCookies().size(), is(1));
    }

    @Test
    void duplicateAuthorizationResponseIssuerFailsAndClearsCookie() {
        OidcTenantConfig tenant = authorizationCodeTenant("test-cookie-password", REDIRECTION_ENDPOINT_URI);
        OidcProviderConfig config = providerConfig("default", tenant);
        OidcAuthenticationRequestState state = authenticationRequestState("default",
                                                                          STATE,
                                                                          REDIRECTION_ENDPOINT_URI,
                                                                          NOW.plusSeconds(60));

        OidcAuthorizationResponseResult result = process(config,
                                                         UriQuery.create("code=authorization-code"
                                                                                 + "&state=" + STATE
                                                                                 + "&iss=https%3A%2F%2Fissuer.example"
                                                                                 + "&iss=https%3A%2F%2Fissuer.example"),
                                                         cookies(tenant, state),
                                                         REDIRECTION_ENDPOINT_URI,
                                                         NOW);

        assertThat(result.invalid(), is(true));
        assertThat(result.description(), is("Authorization Response iss must appear exactly once"));
        assertThat(result.stateCookies().size(), is(1));
    }

    @Test
    void blankAuthorizationResponseIssuerFailsAndClearsCookie() {
        OidcTenantConfig tenant = authorizationCodeTenant("test-cookie-password", REDIRECTION_ENDPOINT_URI);
        OidcProviderConfig config = providerConfig("default", tenant);
        OidcAuthenticationRequestState state = authenticationRequestState("default",
                                                                          STATE,
                                                                          REDIRECTION_ENDPOINT_URI,
                                                                          NOW.plusSeconds(60));

        OidcAuthorizationResponseResult result = process(config,
                                                         UriQuery.create("code=authorization-code"
                                                                                 + "&state=" + STATE
                                                                                 + "&iss="),
                                                         cookies(tenant, state),
                                                         REDIRECTION_ENDPOINT_URI,
                                                         NOW);

        assertThat(result.invalid(), is(true));
        assertThat(result.description(), is("Authorization Response iss must appear exactly once"));
        assertThat(result.stateCookies().size(), is(1));
    }

    @Test
    void missingAuthorizationResponseIssuerFailsWhenMetadataAdvertisesSupport() {
        OidcTenantConfig tenant = authorizationCodeTenant("test-cookie-password", REDIRECTION_ENDPOINT_URI);
        OidcProviderConfig config = providerConfig("default", tenant);
        OidcAuthenticationRequestState state = authenticationRequestState("default",
                                                                          STATE,
                                                                          REDIRECTION_ENDPOINT_URI,
                                                                          NOW.plusSeconds(60));

        OidcAuthorizationResponseResult result = process(config,
                                                         UriQuery.create("code=authorization-code&state=" + STATE),
                                                         cookies(tenant, state),
                                                         REDIRECTION_ENDPOINT_URI,
                                                         NOW,
                                                         true);

        assertThat(result.invalid(), is(true));
        assertThat(result.description(), is("Authorization Response iss is missing"));
        assertThat(result.stateCookies().size(), is(1));
    }

    @Test
    void authorizationErrorResponseValidatesIssuerBeforeError() {
        OidcTenantConfig tenant = authorizationCodeTenant("test-cookie-password", REDIRECTION_ENDPOINT_URI);
        OidcProviderConfig config = providerConfig("default", tenant);
        OidcAuthenticationRequestState state = authenticationRequestState("default",
                                                                          STATE,
                                                                          REDIRECTION_ENDPOINT_URI,
                                                                          NOW.plusSeconds(60));

        OidcAuthorizationResponseResult result = process(config,
                                                         UriQuery.create("error=access_denied"
                                                                                 + "&state=" + STATE
                                                                                 + "&iss=https%3A%2F%2Fother.example"),
                                                         cookies(tenant, state),
                                                         REDIRECTION_ENDPOINT_URI,
                                                         NOW);

        assertThat(result.invalid(), is(true));
        assertThat(result.description(), is("Authorization Response iss does not match Authentication Request issuer"));
        assertThat(result.stateCookies().size(), is(1));
    }

    @Test
    void missingAuthorizationResponseStateFails() {
        OidcTenantConfig tenant = authorizationCodeTenant("test-cookie-password", REDIRECTION_ENDPOINT_URI);
        OidcProviderConfig config = providerConfig("default", tenant);

        OidcAuthorizationResponseResult result = process(config,
                                                         UriQuery.create("code=authorization-code"),
                                                         Map.of(),
                                                         REDIRECTION_ENDPOINT_URI,
                                                         NOW);

        assertThat(result.invalid(), is(true));
        assertThat(result.description(), is("Authorization Response state is missing"));
        assertThat(result.stateCookies().isEmpty(), is(true));
    }

    @Test
    void duplicateAuthorizationResponseStateFails() {
        OidcTenantConfig tenant = authorizationCodeTenant("test-cookie-password", REDIRECTION_ENDPOINT_URI);
        OidcProviderConfig config = providerConfig("default", tenant);

        OidcAuthorizationResponseResult result = process(config,
                                                         UriQuery.create("code=authorization-code"
                                                                                 + "&state=" + STATE
                                                                                 + "&state=" + STATE),
                                                         Map.of(),
                                                         REDIRECTION_ENDPOINT_URI,
                                                         NOW);

        assertThat(result.invalid(), is(true));
        assertThat(result.description(), is("Authorization Response state must appear exactly once"));
        assertThat(result.stateCookies().isEmpty(), is(true));
    }

    @Test
    void blankAuthorizationResponseStateFails() {
        OidcTenantConfig tenant = authorizationCodeTenant("test-cookie-password", REDIRECTION_ENDPOINT_URI);
        OidcProviderConfig config = providerConfig("default", tenant);

        OidcAuthorizationResponseResult result = process(config,
                                                         UriQuery.create("code=authorization-code&state="),
                                                         Map.of(),
                                                         REDIRECTION_ENDPOINT_URI,
                                                         NOW);

        assertThat(result.invalid(), is(true));
        assertThat(result.description(), is("Authorization Response state must appear exactly once"));
        assertThat(result.stateCookies().isEmpty(), is(true));
    }

    @Test
    void reusedAuthorizationResponseStateWithoutCookieFails() {
        OidcTenantConfig tenant = authorizationCodeTenant("test-cookie-password", REDIRECTION_ENDPOINT_URI);
        OidcProviderConfig config = providerConfig("default", tenant);

        OidcAuthorizationResponseResult result = process(config,
                                                         UriQuery.create("code=authorization-code&state=" + STATE),
                                                         Map.of(),
                                                         REDIRECTION_ENDPOINT_URI,
                                                         NOW);

        assertThat(result.invalid(), is(true));
        assertThat(result.description(), is("Authentication Request state cookie is missing or invalid"));
        assertThat(result.stateCookies().isEmpty(), is(true));
    }

    @Test
    void malformedAuthenticationRequestStateCookieFails() {
        OidcTenantConfig tenant = authorizationCodeTenant("test-cookie-password", REDIRECTION_ENDPOINT_URI);
        OidcProviderConfig config = providerConfig("default", tenant);

        OidcAuthorizationResponseResult result = process(config,
                                                         UriQuery.create("code=authorization-code&state=" + STATE),
                                                         Map.of("__Host-helidon-oidc-state", List.of("not-protected")),
                                                         REDIRECTION_ENDPOINT_URI,
                                                         NOW);

        assertThat(result.invalid(), is(true));
        assertThat(result.description(), is("Authentication Request state cookie is missing or invalid"));
        assertThat(result.stateCookies().isEmpty(), is(true));
    }

    @Test
    void authenticationRequestStateCookieWithWrongTenantIdFails() {
        OidcTenantConfig tenant = authorizationCodeTenant("test-cookie-password", REDIRECTION_ENDPOINT_URI);
        OidcProviderConfig config = providerConfig("default", tenant);
        OidcAuthenticationRequestState state = authenticationRequestState("second",
                                                                          STATE,
                                                                          REDIRECTION_ENDPOINT_URI,
                                                                          NOW.plusSeconds(60));

        OidcAuthorizationResponseResult result = process(config,
                                                         UriQuery.create("code=authorization-code&state=" + STATE),
                                                         cookies(tenant, state),
                                                         REDIRECTION_ENDPOINT_URI,
                                                         NOW);

        assertThat(result.invalid(), is(true));
        assertThat(result.description(), is("Authentication Request state cookie is missing or invalid"));
        assertThat(result.stateCookies().isEmpty(), is(true));
    }

    @Test
    void unknownRoutedTenantFailsWithoutInitializingAnyTenant() {
        OidcTenantConfig defaultTenant = authorizationCodeTenant("shared-cookie-password", REDIRECTION_ENDPOINT_URI);
        OidcTenantConfig secondTenant = authorizationCodeTenant("shared-cookie-password", REDIRECTION_ENDPOINT_URI);
        OidcProviderConfig config = OidcProviderConfig.builder()
                .putTenant("default", defaultTenant)
                .putTenant("second", secondTenant)
                .buildPrototype();
        AtomicInteger initializations = new AtomicInteger();

        OidcAuthorizationResponseResult result = process(
                config,
                UriQuery.create("code=authorization-code&state=" + UNKNOWN_STATE),
                Map.of(),
                REDIRECTION_ENDPOINT_URI,
                NOW,
                OidcTenantContextFactory.create((tenantId, tenantConfig) -> {
                    initializations.incrementAndGet();
                    return OidcTenantContext.ready(tenantId, tenantConfig, providerMetadata(false));
                }));

        assertThat(result.invalid(), is(true));
        assertThat(result.description(), is("Authentication Request state cookie is missing or invalid"));
        assertThat(initializations.get(), is(0));
    }

    @Test
    void spoofedRouteFailsCookieBindingEvenWhenTenantsSharePassword() {
        OidcTenantConfig defaultTenant = authorizationCodeTenant("shared-cookie-password", REDIRECTION_ENDPOINT_URI);
        OidcTenantConfig secondTenant = authorizationCodeTenant("shared-cookie-password", REDIRECTION_ENDPOINT_URI);
        OidcProviderConfig config = OidcProviderConfig.builder()
                .putTenant("default", defaultTenant)
                .putTenant("second", secondTenant)
                .buildPrototype();
        OidcAuthenticationRequestState state = authenticationRequestState("default",
                                                                          STATE,
                                                                          REDIRECTION_ENDPOINT_URI,
                                                                          NOW.plusSeconds(60));
        AtomicInteger initializations = new AtomicInteger();

        OidcAuthorizationResponseResult result = process(
                config,
                UriQuery.create("code=authorization-code&state=" + SECOND_STATE),
                cookies(defaultTenant, state),
                REDIRECTION_ENDPOINT_URI,
                NOW,
                OidcTenantContextFactory.create((tenantId, tenantConfig) -> {
                    initializations.incrementAndGet();
                    return OidcTenantContext.ready(tenantId, tenantConfig, providerMetadata(false));
                }));

        assertThat(result.invalid(), is(true));
        assertThat(result.description(), is("Authentication Request state cookie is missing or invalid"));
        assertThat(result.stateCookies().isEmpty(), is(true));
        assertThat(initializations.get(), is(0));
    }

    @Test
    void validCallbackInitializesOnlyRoutedTenant() {
        OidcTenantConfig defaultTenant = authorizationCodeTenant("default-cookie-password", REDIRECTION_ENDPOINT_URI);
        OidcTenantConfig secondTenant = authorizationCodeTenant("second-cookie-password", REDIRECTION_ENDPOINT_URI);
        OidcProviderConfig config = OidcProviderConfig.builder()
                .putTenant("default", defaultTenant)
                .putTenant("second", secondTenant)
                .buildPrototype();
        OidcAuthenticationRequestState state = authenticationRequestState("second",
                                                                          SECOND_STATE,
                                                                          REDIRECTION_ENDPOINT_URI,
                                                                          NOW.plusSeconds(60));
        AtomicInteger defaultInitializations = new AtomicInteger();
        AtomicInteger secondInitializations = new AtomicInteger();

        OidcAuthorizationResponseResult result = process(
                config,
                UriQuery.create("code=authorization-code&state=" + SECOND_STATE),
                cookies(secondTenant, state),
                REDIRECTION_ENDPOINT_URI,
                NOW,
                OidcTenantContextFactory.create((tenantId, tenantConfig) -> {
                    if ("default".equals(tenantId)) {
                        defaultInitializations.incrementAndGet();
                    } else if ("second".equals(tenantId)) {
                        secondInitializations.incrementAndGet();
                    }
                    return OidcTenantContext.ready(tenantId, tenantConfig, providerMetadata(false));
                }));

        assertThat(result.stateValidated(), is(true));
        assertThat(result.tenantContext().orElseThrow().tenantId(), is("second"));
        assertThat(defaultInitializations.get(), is(0));
        assertThat(secondInitializations.get(), is(1));
    }

    @Test
    void duplicateAuthenticationRequestStateCookiesFailWithoutClearingUnverifiedCookies() {
        OidcTenantConfig defaultTenant = authorizationCodeTenant("default-cookie-password", REDIRECTION_ENDPOINT_URI);
        OidcTenantConfig secondTenant = authorizationCodeTenant("second-cookie-password", REDIRECTION_ENDPOINT_URI);
        OidcProviderConfig config = OidcProviderConfig.builder()
                .putTenant("default", defaultTenant)
                .putTenant("second", secondTenant)
                .buildPrototype();
        OidcAuthenticationRequestState defaultState = authenticationRequestState("default",
                                                                                STATE,
                                                                                REDIRECTION_ENDPOINT_URI,
                                                                                NOW.plusSeconds(60));
        OidcAuthenticationRequestState secondState = authenticationRequestState("second",
                                                                               SECOND_STATE,
                                                                               REDIRECTION_ENDPOINT_URI,
                                                                               NOW.plusSeconds(60));
        SetCookie defaultCookie = stateCookie(defaultTenant, defaultState);
        SetCookie secondCookie = stateCookie(secondTenant, secondState);

        OidcAuthorizationResponseResult result = process(config,
                                                         UriQuery.create("code=authorization-code&state=" + STATE),
                                                         Map.of(defaultCookie.name(),
                                                                List.of(defaultCookie.value(), secondCookie.value())),
                                                         REDIRECTION_ENDPOINT_URI,
                                                         NOW);

        assertThat(result.invalid(), is(true));
        assertThat(result.description(), is("Authentication Request state cookie is missing or invalid"));
        assertThat(result.stateCookies().isEmpty(), is(true));
    }

    @Test
    void mismatchedAuthorizationResponseStateFailsAndClearsCookie() {
        OidcTenantConfig tenant = authorizationCodeTenant("test-cookie-password", REDIRECTION_ENDPOINT_URI);
        OidcProviderConfig config = providerConfig("default", tenant);
        OidcAuthenticationRequestState state = authenticationRequestState("default",
                                                                          STATE,
                                                                          REDIRECTION_ENDPOINT_URI,
                                                                          NOW.plusSeconds(60));

        OidcAuthorizationResponseResult result = process(config,
                                                         UriQuery.create("code=authorization-code&state=" + OTHER_STATE),
                                                         cookies(tenant, state),
                                                         REDIRECTION_ENDPOINT_URI,
                                                         NOW);

        assertThat(result.invalid(), is(true));
        assertThat(result.description(), is("Authorization Response state does not match Authentication Request state"));
        assertThat(result.stateCookies().size(), is(1));
    }

    @Test
    void expiredAuthenticationRequestStateFailsAndClearsCookie() {
        OidcTenantConfig tenant = authorizationCodeTenant("test-cookie-password", REDIRECTION_ENDPOINT_URI);
        OidcProviderConfig config = providerConfig("default", tenant);
        OidcAuthenticationRequestState state = authenticationRequestState("default",
                                                                          STATE,
                                                                          REDIRECTION_ENDPOINT_URI,
                                                                          NOW.minusSeconds(1));

        OidcAuthorizationResponseResult result = process(config,
                                                         UriQuery.create("code=authorization-code&state=" + STATE),
                                                         cookies(tenant, state),
                                                         REDIRECTION_ENDPOINT_URI,
                                                         NOW);

        assertThat(result.invalid(), is(true));
        assertThat(result.description(), is("Authentication Request state has expired"));
        assertThat(result.stateCookies().size(), is(1));
    }

    @Test
    void authorizationResponseTenantComesFromCookieBackedState() {
        OidcTenantConfig defaultTenant = authorizationCodeTenant("default-cookie-password", REDIRECTION_ENDPOINT_URI);
        OidcTenantConfig secondTenant = authorizationCodeTenant("second-cookie-password", REDIRECTION_ENDPOINT_URI);
        OidcProviderConfig config = OidcProviderConfig.builder()
                .putTenant("default", defaultTenant)
                .putTenant("second", secondTenant)
                .buildPrototype();
        OidcAuthenticationRequestState state = authenticationRequestState("second",
                                                                          SECOND_STATE,
                                                                          REDIRECTION_ENDPOINT_URI,
                                                                          NOW.plusSeconds(60));

        OidcAuthorizationResponseResult result = process(config,
                                                         UriQuery.create("code=authorization-code&state=" + SECOND_STATE),
                                                         cookies(secondTenant, state),
                                                         REDIRECTION_ENDPOINT_URI,
                                                         NOW);

        assertThat(result.stateValidated(), is(true));
        assertThat(result.tenantContext().orElseThrow().tenantId(), is("second"));
    }

    @Test
    void authorizationErrorResponseIsHandledBeforeTokenExchange() {
        OidcTenantConfig tenant = authorizationCodeTenant("test-cookie-password", REDIRECTION_ENDPOINT_URI);
        OidcProviderConfig config = providerConfig("default", tenant);
        OidcAuthenticationRequestState state = authenticationRequestState("default",
                                                                          STATE,
                                                                          REDIRECTION_ENDPOINT_URI,
                                                                          NOW.plusSeconds(60));

        OidcAuthorizationResponseResult result = process(config,
                                                         UriQuery.create("error=access_denied"
                                                                                 + "&error_description=denied"
                                                                                 + "&state=" + STATE),
                                                         cookies(tenant, state),
                                                         REDIRECTION_ENDPOINT_URI,
                                                         NOW);

        assertThat(result.authorizationError(), is(true));
        assertThat(result.error().orElse(""), is("access_denied"));
        assertThat(result.errorDescription().orElse(""), is("denied"));
        assertThat(result.authorizationCode().isEmpty(), is(true));
        assertThat(result.stateCookies().size(), is(1));
    }

    @Test
    void authorizationErrorResponseRejectsInvalidErrorCharacters() {
        OidcTenantConfig tenant = authorizationCodeTenant("test-cookie-password", REDIRECTION_ENDPOINT_URI);
        OidcProviderConfig config = providerConfig("default", tenant);
        OidcAuthenticationRequestState state = authenticationRequestState("default",
                                                                          STATE,
                                                                          REDIRECTION_ENDPOINT_URI,
                                                                          NOW.plusSeconds(60));

        OidcAuthorizationResponseResult result = process(config,
                                                         UriQuery.create("error=access%5Cdenied&state=" + STATE),
                                                         cookies(tenant, state),
                                                         REDIRECTION_ENDPOINT_URI,
                                                         NOW);

        assertThat(result.invalid(), is(true));
        assertThat(result.description(), is("Authorization Response error contains invalid characters"));
    }

    @Test
    void authorizationErrorResponseRejectsInvalidErrorDescriptionCharacters() {
        OidcTenantConfig tenant = authorizationCodeTenant("test-cookie-password", REDIRECTION_ENDPOINT_URI);
        OidcProviderConfig config = providerConfig("default", tenant);
        OidcAuthenticationRequestState state = authenticationRequestState("default",
                                                                          STATE,
                                                                          REDIRECTION_ENDPOINT_URI,
                                                                          NOW.plusSeconds(60));

        OidcAuthorizationResponseResult result = process(config,
                                                         UriQuery.create("error=access_denied"
                                                                                 + "&error_description=bad%22value"
                                                                                 + "&state=" + STATE),
                                                         cookies(tenant, state),
                                                         REDIRECTION_ENDPOINT_URI,
                                                         NOW);

        assertThat(result.invalid(), is(true));
        assertThat(result.description(), is("Authorization Response error_description contains invalid characters"));
    }

    @Test
    void authorizationErrorResponseRejectsInvalidErrorUri() {
        OidcTenantConfig tenant = authorizationCodeTenant("test-cookie-password", REDIRECTION_ENDPOINT_URI);
        OidcProviderConfig config = providerConfig("default", tenant);
        OidcAuthenticationRequestState state = authenticationRequestState("default",
                                                                          STATE,
                                                                          REDIRECTION_ENDPOINT_URI,
                                                                          NOW.plusSeconds(60));

        OidcAuthorizationResponseResult result = process(config,
                                                         UriQuery.create("error=access_denied"
                                                                                 + "&error_uri=https://issuer.example/"
                                                                                 + "error%20docs"
                                                                                 + "&state=" + STATE),
                                                         cookies(tenant, state),
                                                         REDIRECTION_ENDPOINT_URI,
                                                         NOW);

        assertThat(result.invalid(), is(true));
        assertThat(result.description(), is("Authorization Response error_uri is invalid"));
    }

    @Test
    void redirectionEndpointMismatchFailsAndClearsCookie() {
        OidcTenantConfig tenant = authorizationCodeTenant("test-cookie-password", REDIRECTION_ENDPOINT_URI);
        OidcProviderConfig config = providerConfig("default", tenant);
        OidcAuthenticationRequestState state = authenticationRequestState("default",
                                                                          STATE,
                                                                          REDIRECTION_ENDPOINT_URI,
                                                                          NOW.plusSeconds(60));

        OidcAuthorizationResponseResult result = process(config,
                                                         UriQuery.create("code=authorization-code&state=" + STATE),
                                                         cookies(tenant, state),
                                                         OTHER_REDIRECTION_ENDPOINT_URI,
                                                         NOW);

        assertThat(result.invalid(), is(true));
        assertThat(result.description(),
                   is("Authorization Response Redirection Endpoint does not match Authentication Request state"));
        assertThat(result.stateCookies().size(), is(1));
    }

    @Test
    void featureRegistersConfiguredRedirectionEndpointPaths() {
        OidcProviderConfig config = OidcProviderConfig.builder()
                .putTenant("default", authorizationCodeTenant("default-cookie-password", REDIRECTION_ENDPOINT_URI))
                .putTenant("second", authorizationCodeTenant("second-cookie-password", OTHER_REDIRECTION_ENDPOINT_URI))
                .putTenant("disabled", OidcTenantConfig.builder()
                        .enabled(false)
                        .authorizationCode(it -> it.redirectionEndpointUri(URI.create("https://rp.example/disabled/callback")))
                        .buildPrototype())
                .putTenant("bearer", OidcTenantConfig.create())
                .buildPrototype();

        assertThat(OidcFeature.create(config).redirectionEndpointPaths(),
                   is(Set.of("/oidc/callback", "/other/callback")));
    }

    private static OidcAuthorizationResponseResult process(OidcProviderConfig config,
                                                           UriQuery parameters,
                                                           Map<String, List<String>> cookies,
                                                           URI redirectionEndpointUri,
                                                           Instant now) {
        OidcTenantRuntimeRegistry tenantRuntimeRegistry = OidcTenantRuntimeRegistry.create(config);
        return new OidcAuthorizationResponseProcessor(config, tenantRuntimeRegistry)
                .process(parameters, cookies, redirectionEndpointUri, now);
    }

    private static OidcAuthorizationResponseResult process(OidcProviderConfig config,
                                                           UriQuery parameters,
                                                           Map<String, List<String>> cookies,
                                                           URI redirectionEndpointUri,
                                                           Instant now,
                                                           boolean authorizationResponseIssuerParameterSupported) {
        OidcTenantContextFactory factory = OidcTenantContextFactory.create(
                (tenantId, tenantConfig) -> OidcTenantContext.ready(
                        tenantId,
                        tenantConfig,
                        providerMetadata(authorizationResponseIssuerParameterSupported)));
        return process(config, parameters, cookies, redirectionEndpointUri, now, factory);
    }

    private static OidcAuthorizationResponseResult process(OidcProviderConfig config,
                                                           UriQuery parameters,
                                                           Map<String, List<String>> cookies,
                                                           URI redirectionEndpointUri,
                                                           Instant now,
                                                           OidcTenantContextFactory tenantContextFactory) {
        OidcTenantRuntimeRegistry tenantRuntimeRegistry = OidcTenantRuntimeRegistry.create(config,
                                                                                           tenantContextFactory);
        return new OidcAuthorizationResponseProcessor(config, tenantRuntimeRegistry)
                .process(parameters, cookies, redirectionEndpointUri, now);
    }

    private static Map<String, List<String>> cookies(OidcTenantConfig tenantConfig,
                                                     OidcAuthenticationRequestState state) {
        SetCookie cookie = stateCookie(tenantConfig, state);
        return Map.of(cookie.name(), List.of(cookie.value()));
    }

    private static SetCookie stateCookie(OidcTenantConfig tenantConfig, OidcAuthenticationRequestState state) {
        return OidcCookieStateHandler.create(state.tenantId(), tenantConfig)
                .createAuthenticationRequestCookie(state);
    }

    private static OidcAuthenticationRequestState authenticationRequestState(String tenantId,
                                                                             String state,
                                                                             URI redirectionEndpointUri,
                                                                             Instant expiresAt) {
        return new OidcAuthenticationRequestState(tenantId,
                                                     state,
                                                     "nonce",
                                                     "pkce-verifier",
                                                     ISSUER.toString(),
                                                     ORIGINAL_URI,
                                                     redirectionEndpointUri,
                                                     NOW.minusSeconds(1),
                                                     expiresAt);
    }

    private static OidcProviderConfig providerConfig(String tenantId, OidcTenantConfig tenantConfig) {
        return OidcProviderConfig.builder()
                .putTenant(tenantId, tenantConfig)
                .buildPrototype();
    }

    private static OidcTenantConfig authorizationCodeTenant(String cookiePassword, URI redirectionEndpointUri) {
        return OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId("client-id")
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .authorizationCode(it -> it.redirectionEndpointUri(redirectionEndpointUri))
                .cookies(it -> it.protection(protection -> protection.password(cookiePassword)))
                .buildPrototype();
    }

    private static OidcProviderMetadata providerMetadata(boolean authorizationResponseIssuerParameterSupported) {
        return OidcProviderMetadata.fromWellKnownMetadataJson(JsonObject.builder()
                .set("issuer", ISSUER.toString())
                .set("authorization_endpoint", AUTHORIZATION_ENDPOINT_URI.toString())
                .set("token_endpoint", TOKEN_ENDPOINT_URI.toString())
                .set("authorization_response_iss_parameter_supported", authorizationResponseIssuerParameterSupported)
                .build());
    }

    private static String authorizationState(String tenantId, int requestMarker) {
        byte[] requestId = new byte[32];
        requestId[0] = (byte) requestMarker;
        String encodedRequestId = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(requestId);
        return OidcAuthorizationState.create(tenantId, encodedRequestId).value();
    }
}
