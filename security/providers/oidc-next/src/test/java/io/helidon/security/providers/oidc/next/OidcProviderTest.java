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
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.ServiceLoader;
import java.util.function.Consumer;

import io.helidon.common.configurable.Resource;
import io.helidon.common.uri.UriQuery;
import io.helidon.config.Config;
import io.helidon.http.SetCookie;
import io.helidon.json.JsonObject;
import io.helidon.security.EndpointConfig;
import io.helidon.security.AuthenticationResponse;
import io.helidon.security.Grant;
import io.helidon.security.OutboundSecurityResponse;
import io.helidon.security.ProviderRequest;
import io.helidon.security.Role;
import io.helidon.security.SecurityContext;
import io.helidon.security.SecurityEnvironment;
import io.helidon.security.SecurityResponse;
import io.helidon.security.Subject;
import io.helidon.security.jwt.Jwt;
import io.helidon.security.jwt.SignedJwt;
import io.helidon.security.jwt.jwk.JwkKeys;
import io.helidon.security.providers.common.TokenCredential;
import io.helidon.security.spi.SecurityProviderService;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;

class OidcProviderTest {
    private static final String CURRENT_PROVIDER_CONFIG_KEY = "oidc";
    private static final String OIDC_NEXT_PACKAGE = "io.helidon.security.providers.oidc.next";
    private static final URI ISSUER = URI.create("https://issuer.example");
    private static final URI AUTHORIZATION_ENDPOINT_URI = URI.create("https://issuer.example/authorize");
    private static final URI TOKEN_ENDPOINT_URI = URI.create("https://issuer.example/token");
    private static final URI REDIRECTION_ENDPOINT_URI = URI.create("https://rp.example/oidc/callback");
    private static final URI ORIGINAL_URI = URI.create("https://rp.example/resource?name=value");
    private static final String SUBJECT = "user1-id";
    private static final String USERNAME = "user1";

    private static JwkKeys signKeys;

    @BeforeAll
    static void initClass() {
        signKeys = JwkKeys.builder()
                .resource(Resource.create("oidc-next-sign-jwk.json"))
                .build();
    }

    @Test
    void serviceCreatesProvider() {
        OidcProviderService service = new OidcProviderService();

        assertThat(service.providerConfigKey(), is("oidc-next"));
        assertThat(service.providerClass() == OidcProvider.class, is(true));
        assertThat(service.create(Config.empty()), instanceOf(OidcProvider.class));
    }

    @Test
    void serviceIsDiscoverable() {
        boolean found = false;

        for (SecurityProviderService service : ServiceLoader.load(SecurityProviderService.class)) {
            if (OidcProviderService.PROVIDER_CONFIG_KEY.equals(service.providerConfigKey())) {
                assertThat(service.providerClass() == OidcProvider.class, is(true));
                found = true;
            }
        }

        assertThat(found, is(true));
    }

    @Test
    void stage0KeepsNewProviderIsolatedFromCurrentProvider() {
        assertThat(OidcProvider.class.getPackageName(), is(OIDC_NEXT_PACKAGE));
        assertThat(OidcProviderService.PROVIDER_CONFIG_KEY, is("oidc-next"));
        assertThat(OidcProviderService.PROVIDER_CONFIG_KEY, is(not(CURRENT_PROVIDER_CONFIG_KEY)));
    }

    @Test
    void providerAbstainsUntilFlowsAreImplemented() {
        OidcProvider provider = OidcProvider.create();

        assertThat(provider.authenticate(null).status(), is(SecurityResponse.SecurityStatus.ABSTAIN));
        assertThat(provider.isOutboundSupported(null, null, null), is(false));
        assertThat(provider.outboundSecurity(null, null, null).status(), is(SecurityResponse.SecurityStatus.ABSTAIN));
    }

    @Test
    void protectedResourceMissingBearerTokenReturnsChallenge() {
        OidcProvider provider = providerWithTenant();

        AuthenticationResponse response = provider.authenticate(
                request(OidcEndpointPolicy.protectedResource(), SecurityEnvironment.create()));

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.FAILURE));
        assertThat(response.statusCode().orElse(-1), is(401));
        assertThat(response.responseHeaders().get("WWW-Authenticate"), is(List.of("Bearer")));
    }

    @Test
    void bearerTokenSelectsBearerTokenAuthenticationWhenBothOperationsArePossible() {
        OidcProvider provider = providerWithTenant();
        SecurityEnvironment environment = SecurityEnvironment.builder()
                .header("Authorization", "Bearer access-token")
                .build();

        AuthenticationResponse response = provider.authenticate(
                request(OidcEndpointPolicy.protectedResourceAndAuthorizationCodeFlow(), environment));

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.FAILURE));
        assertThat(response.statusCode().orElse(-1), is(401));
        assertThat(response.description().orElse(""), is("Bearer Token validation is not implemented yet"));
        assertThat(response.responseHeaders().get("WWW-Authenticate").get(0).startsWith("Bearer "), is(true));
    }

    @Test
    void invalidBearerTokenRequestFailsSafely() {
        OidcProvider provider = providerWithQueryParameterTransport();
        SecurityEnvironment environment = SecurityEnvironment.builder()
                .header("Authorization", "Bearer header-token")
                .queryParam("access_token", "query-token")
                .build();

        AuthenticationResponse response = provider.authenticate(
                request(OidcEndpointPolicy.protectedResource(), environment));

        assertInvalidBearerTokenRequest(response, "Multiple Bearer Token credential sources found");
    }

    @Test
    void multipleAuthorizationHeaderBearerTokensFailSafely() {
        OidcProvider provider = providerWithTenant();
        SecurityEnvironment environment = SecurityEnvironment.builder()
                .header("Authorization", List.of("Bearer first-token", "Bearer second-token"))
                .build();

        AuthenticationResponse response = provider.authenticate(
                request(OidcEndpointPolicy.protectedResource(), environment));

        assertInvalidBearerTokenRequest(response, "Multiple Bearer Tokens found in Authorization header");
    }

    @Test
    void multipleQueryParameterBearerTokensFailSafely() {
        OidcProvider provider = providerWithQueryParameterTransport();
        SecurityEnvironment environment = SecurityEnvironment.builder()
                .queryParam("access_token", List.of("first-token", "second-token"))
                .build();

        AuthenticationResponse response = provider.authenticate(
                request(OidcEndpointPolicy.protectedResource(), environment));

        assertInvalidBearerTokenRequest(response, "Multiple Bearer Tokens found in query parameter");
    }

    @Test
    void malformedQueryParameterBearerTokenFailsSafely() {
        OidcProvider provider = providerWithQueryParameterTransport();
        SecurityEnvironment environment = SecurityEnvironment.builder()
                .queryParam("access_token", " ")
                .build();

        AuthenticationResponse response = provider.authenticate(
                request(OidcEndpointPolicy.protectedResource(), environment));

        assertInvalidBearerTokenRequest(response, "Malformed Bearer Token in query parameter");
    }

    @Test
    void bareQueryParameterBearerTokenFailsSafely() {
        OidcProvider provider = providerWithQueryParameterTransport();
        SecurityEnvironment environment = SecurityEnvironment.builder()
                .queryParams(UriQuery.create("access_token"))
                .build();

        AuthenticationResponse response = provider.authenticate(
                request(OidcEndpointPolicy.protectedResource(), environment));

        assertInvalidBearerTokenRequest(response, "Malformed Bearer Token in query parameter");
    }

    @Test
    void bareQueryParameterWithAnotherBearerTokenFailsSafely() {
        OidcProvider provider = providerWithQueryParameterTransport();
        SecurityEnvironment environment = SecurityEnvironment.builder()
                .targetUri(URI.create("https://rp.example/resource?access_token&access_token=access-token"))
                .queryParams(UriQuery.create("access_token&access_token=access-token"))
                .build();

        AuthenticationResponse response = provider.authenticate(
                request(OidcEndpointPolicy.protectedResource(), environment));

        assertInvalidBearerTokenRequest(response, "Multiple Bearer Tokens found in query parameter");
    }

    @Test
    void disabledTransportCredentialIsIgnoredWhenEnabledTransportHasBearerToken() {
        OidcProvider provider = OidcProvider.create(OidcProviderConfig.builder()
                                                  .putTenant("default", OidcTenantConfig.builder()
                                                          .tokenTransport(it -> it.authorizationHeaderEnabled(false)
                                                                  .queryParameterEnabled(true))
                                                          .buildPrototype())
                                                  .buildPrototype());
        SecurityEnvironment environment = SecurityEnvironment.builder()
                .header("Authorization", "Bearer disabled-header-token")
                .queryParam("access_token", "query-token")
                .build();

        AuthenticationResponse response = provider.authenticate(
                request(OidcEndpointPolicy.protectedResource(), environment));

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.FAILURE));
        assertThat(response.statusCode().orElse(-1), is(401));
        assertThat(response.description().orElse(""), is("Bearer Token validation is not implemented yet"));
    }

    @Test
    void malformedBearerTokenFailsEvenWhenProviderIsOptional() {
        OidcProvider provider = OidcProvider.create(OidcProviderConfig.builder()
                                                  .optional(true)
                                                  .putTenant("default", OidcTenantConfig.create())
                                                  .buildPrototype());
        SecurityEnvironment environment = SecurityEnvironment.builder()
                .header("Authorization", "Bearer ")
                .build();

        AuthenticationResponse response = provider.authenticate(
                request(OidcEndpointPolicy.protectedResource(), environment));

        assertInvalidBearerTokenRequest(response, "Malformed Bearer Token in Authorization header");
    }

    @Test
    void bothProtocolOperationsWithoutEvidenceFailsSafely() {
        OidcProvider provider = providerWithTenant();

        AuthenticationResponse response = provider.authenticate(
                request(OidcEndpointPolicy.protectedResourceAndAuthorizationCodeFlow(), SecurityEnvironment.create()));

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.FAILURE));
        assertThat(response.statusCode().orElse(-1), is(400));
        assertThat(response.description().orElse(""), is("OIDC request cannot be classified by protocol operation"));
    }

    @Test
    void authorizationCodeFlowInitiationRedirectsToAuthorizationEndpoint() {
        OidcTenantConfig tenant = authorizationCodeTenant();
        OidcProvider provider = provider(tenant);
        SecurityEnvironment environment = SecurityEnvironment.builder()
                .targetUri(ORIGINAL_URI)
                .path("/resource")
                .transport("https")
                .build();

        AuthenticationResponse response = provider.authenticate(
                request(null, environment));

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.FAILURE_FINISH));
        assertThat(response.statusCode().orElse(-1), is(303));

        URI location = URI.create(response.responseHeaders().get("Location").get(0));
        assertThat(location.getScheme(), is("https"));
        assertThat(location.getHost(), is("issuer.example"));
        assertThat(location.getPath(), is("/authorize"));

        UriQuery query = UriQuery.create(location);
        assertThat(query.get("response_type"), is("code"));
        assertThat(query.get("client_id"), is("client-id"));
        assertThat(query.get("redirect_uri"), is(REDIRECTION_ENDPOINT_URI.toString()));
        assertThat(query.get("scope"), is("openid profile"));
        assertThat(query.contains("state"), is(true));
        assertThat(query.contains("nonce"), is(true));
        assertThat(query.get("code_challenge_method"), is("S256"));

        OidcAuthenticationRequestState state = authenticationRequestState(response, tenant);
        assertThat(state.tenantId(), is("default"));
        assertThat(state.state(), is(query.get("state")));
        assertThat(state.nonce(), is(query.get("nonce")));
        assertThat(state.originalUri(), is(ORIGINAL_URI));
        assertThat(state.redirectionEndpointUri(), is(REDIRECTION_ENDPOINT_URI));
        assertThat(state.pkceVerifier().isPresent(), is(true));
        assertThat(query.get("code_challenge"),
                   is(OidcAuthenticationRequestFactory.codeChallenge(state.pkceVerifier().orElseThrow(),
                                                                     OidcPkceMethod.S256)));
    }

    @Test
    void authorizationCodeFlowCanDisablePkce() {
        OidcTenantConfig tenant = authorizationCodeTenant(code -> code.pkceRequired(false));
        OidcProvider provider = provider(tenant);

        AuthenticationResponse response = provider.authenticate(
                request(null, SecurityEnvironment.builder()
                        .targetUri(ORIGINAL_URI)
                        .build()));

        URI location = URI.create(response.responseHeaders().get("Location").get(0));
        UriQuery query = UriQuery.create(location);
        assertThat(query.contains("code_challenge"), is(false));
        assertThat(query.contains("code_challenge_method"), is(false));
        assertThat(authenticationRequestState(response, tenant).pkceVerifier().isEmpty(), is(true));
    }

    @Test
    void authenticationRequestStateCookieIsProtectedAndScoped() {
        OidcTenantConfig tenant = authorizationCodeTenant();
        OidcProvider provider = provider(tenant);

        AuthenticationResponse response = provider.authenticate(
                request(null, SecurityEnvironment.builder()
                        .targetUri(ORIGINAL_URI)
                        .build()));

        SetCookie cookie = SetCookie.parse(response.responseHeaders().get("Set-Cookie").get(0));
        assertThat(cookie.name(), is("__Host-helidon-oidc-state"));
        assertThat(cookie.value().startsWith("v1."), is(true));
        assertThat(cookie.path().orElse(""), is("/"));
        assertThat(cookie.httpOnly(), is(true));
        assertThat(cookie.secure(), is(true));
        assertThat(cookie.sameSite().orElseThrow(), is(SetCookie.SameSite.LAX));
        assertThat(cookie.maxAge().orElseThrow().getSeconds(), is(300L));

        OidcAuthenticationRequestState state = authenticationRequestState(response, tenant);
        assertThat(state.expiresAt().isAfter(Instant.now()), is(true));
        assertThat(cookie.value(), not(containsString(state.state())));
        assertThat(cookie.value(), not(containsString(state.nonce())));
        assertThat(cookie.value(), not(containsString(state.pkceVerifier().orElseThrow())));
        assertThat(OidcCookieStateHandler.create(tenant)
                           .readAuthenticationRequestState(tamperCookieValue(cookie.value()), Instant.now())
                           .isEmpty(),
                   is(true));
    }

    @Test
    void localAuthenticationResultCookieAuthenticatesSubjectFromIdToken() {
        OidcTenantConfig tenant = authorizationCodeTenant();
        OidcProvider provider = provider(tenant);
        String idToken = signedIdToken(it -> it.email("user1@example.org")
                .preferredUsername(USERNAME));
        SignedJwt signedJwt = SignedJwt.parseToken(idToken);
        Instant now = Instant.now();
        SetCookie cookie = OidcCookieStateHandler.create(tenant)
                .createLocalAuthenticationResultCookie(OidcLocalAuthenticationResult.create(
                        "default",
                        OidcValidatedIdToken.create(idToken, signedJwt, signedJwt.getJwt()),
                        "access-token",
                        "Bearer",
                        "refresh-token",
                        "openid profile",
                        now,
                        now.plusSeconds(3600),
                        now.plusSeconds(600)));
        assertThat(cookie.name(), is("__Host-helidon-oidc-auth"));
        assertThat(cookie.value(), not(containsString(idToken)));
        assertThat(cookie.value(), not(containsString("access-token")));
        assertThat(cookie.value(), not(containsString("refresh-token")));
        assertThat(cookie.path().orElse(""), is("/"));
        assertThat(cookie.httpOnly(), is(true));
        assertThat(cookie.secure(), is(true));
        assertThat(cookie.sameSite().orElseThrow(), is(SetCookie.SameSite.LAX));
        assertThat(cookie.maxAge().orElseThrow().getSeconds(), is(3600L));
        assertThat(OidcCookieStateHandler.create(tenant)
                           .readLocalAuthenticationResult(tamperCookieValue(cookie.value()), now)
                           .isEmpty(),
                   is(true));

        AuthenticationResponse response = provider.authenticate(
                request(null, SecurityEnvironment.builder()
                        .targetUri(ORIGINAL_URI)
                        .header("Cookie", cookie.name() + "=" + cookie.value())
                        .build()));

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        Subject subject = response.user().orElseThrow();
        assertThat(subject.principal().id(), is(SUBJECT));
        assertThat(subject.principal().getName(), is(USERNAME));
        assertThat(subject.principal().abacAttributeRaw("email"), is("user1@example.org"));
        assertThat(subject.grantsByType("scope").stream().map(Grant::getName).toList(),
                   is(List.of("openid", "profile")));

        TokenCredential credential = subject.publicCredential(TokenCredential.class).orElseThrow();
        assertThat(credential.token(), is("access-token"));
        assertThat(credential.getIssuer().orElse(""), is(ISSUER.toString()));
        assertThat(credential.getExpTime().orElseThrow(), is(now.plusSeconds(600)));
    }

    @Test
    void localAuthenticationResultCookieUsesCustomSubjectMapping() {
        OidcTenantConfig tenant = authorizationCodeTenant(code -> { }, builder -> builder
                .subjectMapping(mapping -> mapping
                        .principalIdClaimPaths(List.of("tenant_user"))
                        .principalNameClaimPaths(List.of("display_name"))
                        .roleClaimPaths(List.of("realm_access.roles"))
                        .scopeGrantsEnabled(false)));
        OidcProvider provider = provider(tenant);
        String idToken = signedIdToken(it -> it
                .addPayloadClaim("tenant_user", "tenant-user-id")
                .addPayloadClaim("display_name", "Tenant User")
                .addPayloadClaim("realm_access", JsonObject.builder()
                        .setStrings("roles", List.of("app-admin", "app-auditor"))
                        .build()));
        SignedJwt signedJwt = SignedJwt.parseToken(idToken);
        Instant now = Instant.now();
        SetCookie cookie = OidcCookieStateHandler.create(tenant)
                .createLocalAuthenticationResultCookie(OidcLocalAuthenticationResult.create(
                        "default",
                        OidcValidatedIdToken.create(idToken, signedJwt, signedJwt.getJwt()),
                        "access-token",
                        "Bearer",
                        "refresh-token",
                        "openid profile",
                        now,
                        now.plusSeconds(3600),
                        now.plusSeconds(600)));

        AuthenticationResponse response = provider.authenticate(
                request(null, SecurityEnvironment.builder()
                        .targetUri(ORIGINAL_URI)
                        .header("Cookie", cookie.name() + "=" + cookie.value())
                        .build()));

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        Subject subject = response.user().orElseThrow();
        assertThat(subject.principal().id(), is("tenant-user-id"));
        assertThat(subject.principal().getName(), is("Tenant User"));
        assertThat(subject.grants(Role.class).stream().map(Role::getName).toList(),
                   is(List.of("app-admin", "app-auditor")));
        assertThat(subject.grantsByType("scope").isEmpty(), is(true));
    }

    @Test
    void localAuthenticationResultCookieRequiresConfiguredPrincipalIdClaim() {
        OidcTenantConfig tenant = authorizationCodeTenant(code -> { }, builder -> builder
                .subjectMapping(mapping -> mapping.principalIdClaimPaths(List.of("tenant_user"))));
        OidcProvider provider = provider(tenant);
        Instant now = Instant.now();
        SetCookie cookie = localAuthenticationCookie(tenant, "default", now, now.plusSeconds(3600));

        AuthenticationResponse response = provider.authenticate(
                request(null, SecurityEnvironment.builder()
                        .targetUri(ORIGINAL_URI)
                        .header("Cookie", cookie.name() + "=" + cookie.value())
                        .build()));

        assertAuthenticationRequestStarted(response);
    }

    @Test
    void localAuthenticationResultCookieUsesTokenResponseScopesOnly() {
        OidcTenantConfig tenant = authorizationCodeTenant(code -> { }, builder -> builder
                .subjectMapping(mapping -> mapping.scopeClaimPaths(List.of("id_scopes"))));
        OidcProvider provider = provider(tenant);
        String idToken = signedIdToken(it -> it
                .preferredUsername(USERNAME)
                .addPayloadClaim("id_scopes", List.of("app.read", "app.write")));
        SignedJwt signedJwt = SignedJwt.parseToken(idToken);
        Instant now = Instant.now();
        SetCookie cookie = OidcCookieStateHandler.create(tenant)
                .createLocalAuthenticationResultCookie(OidcLocalAuthenticationResult.create(
                        "default",
                        OidcValidatedIdToken.create(idToken, signedJwt, signedJwt.getJwt()),
                        "access-token",
                        "Bearer",
                        "refresh-token",
                        "openid profile",
                        now,
                        now.plusSeconds(3600),
                        now.plusSeconds(600)));

        AuthenticationResponse response = provider.authenticate(
                request(null, SecurityEnvironment.builder()
                        .targetUri(ORIGINAL_URI)
                        .header("Cookie", cookie.name() + "=" + cookie.value())
                        .build()));

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.user().orElseThrow().grantsByType("scope").stream().map(Grant::getName).toList(),
                   is(List.of("openid", "profile")));
    }

    @Test
    void localAuthenticationResultCookieAuthenticatesCombinedProtectedResourceAndCodeFlowPolicy() {
        OidcTenantConfig tenant = authorizationCodeAndProtectedResourceTenant();
        OidcProvider provider = provider(tenant);
        Instant now = Instant.now();
        SetCookie cookie = localAuthenticationCookie(tenant, "default", now, now.plusSeconds(3600));

        AuthenticationResponse response = provider.authenticate(
                request(null, SecurityEnvironment.builder()
                        .targetUri(ORIGINAL_URI)
                        .header("Cookie", cookie.name() + "=" + cookie.value())
                        .build()));

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.SUCCESS));
        assertThat(response.user().orElseThrow().principal().id(), is(SUBJECT));
    }

    @Test
    void invalidLocalAuthenticationResultCookiesStartAuthenticationRequest() {
        OidcTenantConfig tenant = authorizationCodeTenant();
        OidcProvider provider = provider(tenant);
        Instant now = Instant.now();
        SetCookie validCookie = localAuthenticationCookie(tenant, "default", now, now.plusSeconds(3600));
        SetCookie expiredCookie = localAuthenticationCookie(tenant, "default", now.minusSeconds(3600), now.minusSeconds(1));
        SetCookie wrongTenantCookie = localAuthenticationCookie(tenant, "other", now, now.plusSeconds(3600));

        assertAuthenticationRequestStarted(provider.authenticate(request(null, environmentWithCookie(
                expiredCookie.name() + "=" + expiredCookie.value()))));
        assertAuthenticationRequestStarted(provider.authenticate(request(null, environmentWithCookie(
                validCookie.name() + "=" + tamperCookieValue(validCookie.value())))));
        assertAuthenticationRequestStarted(provider.authenticate(request(null, environmentWithCookie(
                wrongTenantCookie.name() + "=" + wrongTenantCookie.value()))));
        assertAuthenticationRequestStarted(provider.authenticate(request(null, environmentWithCookie(
                validCookie.name() + "=" + validCookie.value() + "; "
                        + validCookie.name() + "=" + validCookie.value()))));
    }

    @Test
    void localAuthenticationResultLifetimeUsesConfiguredLifetimeWhenShorterThanIdToken() {
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        String idToken = signedIdToken(it -> it.expirationTime(now.plusSeconds(3600)));
        OidcLocalAuthenticationResult result = OidcLocalAuthenticationResult.create(
                "default",
                tokenResponse(idToken, 600L, null),
                validatedIdToken(idToken),
                List.of("openid", "profile"),
                now,
                Duration.ofSeconds(300));

        assertThat(result.expiresAt(), is(now.plusSeconds(300)));
        assertThat(result.accessTokenExpiresAt().orElseThrow(), is(now.plusSeconds(600)));
        assertThat(result.scope().orElse(""), is("openid profile"));
    }

    @Test
    void localAuthenticationResultLifetimeUsesIdTokenExpirationWhenShorterThanConfiguredLifetime() {
        OidcTenantConfig tenant = authorizationCodeTenant();
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        String idToken = signedIdToken(it -> it.expirationTime(now.plusSeconds(120)));
        OidcLocalAuthenticationResult result = OidcLocalAuthenticationResult.create(
                "default",
                tokenResponse(idToken, null, "openid"),
                validatedIdToken(idToken),
                List.of("openid", "profile"),
                now,
                Duration.ofSeconds(3600));

        assertThat(result.expiresAt(), is(now.plusSeconds(120)));
        assertThat(OidcCookieStateHandler.create(tenant)
                           .createLocalAuthenticationResultCookie(result)
                           .maxAge()
                           .orElseThrow()
                           .getSeconds(),
                   is(120L));
    }

    @Test
    void authorizationResponseProcessingIsLeftToFeatureEndpoint() {
        OidcProvider provider = OidcProvider.create();
        SecurityEnvironment environment = SecurityEnvironment.builder()
                .queryParam("code", "authorization-code")
                .queryParam("state", "stored-state")
                .build();

        AuthenticationResponse response = provider.authenticate(request(null, environment));

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.ABSTAIN));
    }

    @Test
    void outboundWithoutPolicyAbstains() {
        OidcProvider provider = OidcProvider.create();
        ProviderRequest providerRequest = request(null, SecurityEnvironment.create());
        EndpointConfig outboundConfig = EndpointConfig.create();

        assertThat(provider.isOutboundSupported(providerRequest, SecurityEnvironment.create(), outboundConfig), is(false));
        assertThat(provider.outboundSecurity(providerRequest, SecurityEnvironment.create(), outboundConfig).status(),
                   is(SecurityResponse.SecurityStatus.ABSTAIN));
    }

    @Test
    void tokenPropagationIsClassifiedButDeferred() {
        OidcProvider provider = providerWithTenant();
        ProviderRequest providerRequest = request(null, SecurityEnvironment.create());
        EndpointConfig outboundConfig = outboundConfig(OidcOutboundPolicy.tokenPropagation());

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest,
                                                                      SecurityEnvironment.create(),
                                                                      outboundConfig);

        assertThat(provider.isOutboundSupported(providerRequest, SecurityEnvironment.create(), outboundConfig), is(true));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.FAILURE));
        assertThat(response.description().orElse(""), is("Token Propagation is not implemented yet"));
    }

    @Test
    void clientCredentialsGrantIsClassifiedButDeferred() {
        OidcProvider provider = providerWithTenant();
        ProviderRequest providerRequest = request(null, SecurityEnvironment.create());
        EndpointConfig outboundConfig = outboundConfig(OidcOutboundPolicy.clientCredentialsGrant());

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest,
                                                                      SecurityEnvironment.create(),
                                                                      outboundConfig);

        assertThat(provider.isOutboundSupported(providerRequest, SecurityEnvironment.create(), outboundConfig), is(true));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.FAILURE));
        assertThat(response.description().orElse(""), is("Client Credentials Grant is not implemented yet"));
    }

    @Test
    void outboundProtocolOperationAmbiguityFailsSafely() {
        OidcProvider provider = providerWithTenant();
        ProviderRequest providerRequest = request(null, SecurityEnvironment.create());
        EndpointConfig outboundConfig = outboundConfig(OidcOutboundPolicy.tokenPropagationAndClientCredentialsGrant());

        OutboundSecurityResponse response = provider.outboundSecurity(providerRequest,
                                                                      SecurityEnvironment.create(),
                                                                      outboundConfig);

        assertThat(provider.isOutboundSupported(providerRequest, SecurityEnvironment.create(), outboundConfig), is(true));
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.FAILURE));
        assertThat(response.description().orElse(""),
                   is("OIDC outbound request cannot be classified by protocol operation"));
    }

    static ProviderRequest request(OidcEndpointPolicy endpointPolicy, SecurityEnvironment environment) {
        EndpointConfig.Builder endpointConfig = EndpointConfig.builder();
        if (endpointPolicy != null) {
            endpointConfig.customObject(OidcEndpointPolicy.class, endpointPolicy);
        }
        return new TestProviderRequest(endpointConfig.build(), environment);
    }

    private static EndpointConfig outboundConfig(OidcOutboundPolicy outboundPolicy) {
        return EndpointConfig.builder()
                .customObject(OidcOutboundPolicy.class, outboundPolicy)
                .build();
    }

    private static OidcProvider providerWithTenant() {
        return provider(OidcTenantConfig.create());
    }

    private static OidcProvider providerWithQueryParameterTransport() {
        return provider(OidcTenantConfig.builder()
                                .tokenTransport(it -> it.queryParameterEnabled(true))
                                .buildPrototype());
    }

    private static OidcProvider provider(OidcTenantConfig tenant) {
        return OidcProvider.create(OidcProviderConfig.builder()
                                           .putTenant("default", tenant)
                                           .buildPrototype());
    }

    private static OidcTenantConfig authorizationCodeTenant() {
        return authorizationCodeTenant(it -> { });
    }

    private static OidcTenantConfig authorizationCodeTenant(Consumer<OidcAuthorizationCodeConfig.Builder> customizer) {
        return authorizationCodeTenant(customizer, builder -> { });
    }

    private static OidcTenantConfig authorizationCodeTenant(
            Consumer<OidcAuthorizationCodeConfig.Builder> authorizationCodeCustomizer,
            Consumer<OidcTenantConfig.Builder> tenantCustomizer) {
        OidcTenantConfig.Builder builder = OidcTenantConfig.builder()
                .issuer(ISSUER)
                .clientId("client-id")
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .authorizationCode(it -> {
                    it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI)
                            .scopes(List.of("openid", "profile"));
                    authorizationCodeCustomizer.accept(it);
                })
                .cookies(it -> it.encryptionSecret("test-cookie-secret"));
        tenantCustomizer.accept(builder);
        return builder.buildPrototype();
    }

    private static OidcTenantConfig authorizationCodeAndProtectedResourceTenant() {
        return OidcTenantConfig.builder()
                .issuer(ISSUER)
                .clientId("client-id")
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI)
                        .jwksUri(URI.create("https://issuer.example/jwks")))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI)
                        .scopes(List.of("openid", "profile")))
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.JWT)
                                .audience("api://default")))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype();
    }

    private static SetCookie localAuthenticationCookie(OidcTenantConfig tenant,
                                                       String tenantId,
                                                       Instant createdAt,
                                                       Instant expiresAt) {
        String idToken = signedIdToken(it -> it.email("user1@example.org")
                .preferredUsername(USERNAME));
        SignedJwt signedJwt = SignedJwt.parseToken(idToken);
        return OidcCookieStateHandler.create(tenant)
                .createLocalAuthenticationResultCookie(OidcLocalAuthenticationResult.create(
                        tenantId,
                        OidcValidatedIdToken.create(idToken, signedJwt, signedJwt.getJwt()),
                        "access-token",
                        "Bearer",
                        "refresh-token",
                        "openid profile",
                        createdAt,
                        expiresAt,
                        createdAt.plusSeconds(600)));
    }

    private static SecurityEnvironment environmentWithCookie(String cookieHeader) {
        return SecurityEnvironment.builder()
                .targetUri(ORIGINAL_URI)
                .header("Cookie", cookieHeader)
                .build();
    }

    private static OidcAuthenticationRequestState authenticationRequestState(AuthenticationResponse response,
                                                                             OidcTenantConfig tenant) {
        SetCookie cookie = SetCookie.parse(response.responseHeaders().get("Set-Cookie").get(0));
        return OidcCookieStateHandler.create(tenant)
                .readAuthenticationRequestState(cookie.value(), Instant.now())
                .orElseThrow();
    }

    private static String tamperCookieValue(String value) {
        int ciphertextStart = value.indexOf('.', value.indexOf('.') + 1) + 1;
        char firstCiphertextChar = value.charAt(ciphertextStart);
        return value.substring(0, ciphertextStart)
                + (firstCiphertextChar == 'A' ? 'B' : 'A')
                + value.substring(ciphertextStart + 1);
    }

    private static String signedIdToken(Consumer<Jwt.Builder> customizer) {
        Instant now = Instant.now();
        Jwt.Builder builder = Jwt.builder()
                .type("JWT")
                .subject(SUBJECT)
                .issuer(ISSUER.toString())
                .algorithm("RS256")
                .keyId("verify-rsa")
                .issueTime(now)
                .expirationTime(now.plusSeconds(3600))
                .addAudience("client-id")
                .nonce("nonce");
        customizer.accept(builder);
        return SignedJwt.sign(builder.build(), signKeys.forKeyId("sign-rsa").orElseThrow())
                .tokenContent();
    }

    private static OidcValidatedIdToken validatedIdToken(String idToken) {
        SignedJwt signedJwt = SignedJwt.parseToken(idToken);
        return OidcValidatedIdToken.create(idToken, signedJwt, signedJwt.getJwt());
    }

    private static OidcTokenResponse tokenResponse(String idToken, Long expiresIn, String scope) {
        JsonObject.Builder builder = JsonObject.builder()
                .set("access_token", "access-token")
                .set("token_type", "Bearer")
                .set("id_token", idToken);
        if (expiresIn != null) {
            builder.set("expires_in", expiresIn);
        }
        if (scope != null) {
            builder.set("scope", scope);
        }
        return OidcTokenResponse.fromAuthorizationCodeJson(builder.build());
    }

    private static void assertAuthenticationRequestStarted(AuthenticationResponse response) {
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.FAILURE_FINISH));
        assertThat(response.statusCode().orElse(-1), is(303));
        assertThat(response.responseHeaders().get("Location").getFirst(), containsString("/authorize"));
    }

    private static void assertInvalidBearerTokenRequest(AuthenticationResponse response, String description) {
        assertThat(response.status(), is(SecurityResponse.SecurityStatus.FAILURE));
        assertThat(response.statusCode().orElse(-1), is(400));
        assertThat(response.description().orElse(""), is(description));
        assertThat(response.responseHeaders().get("WWW-Authenticate").get(0).contains("invalid_request"), is(true));
    }

    private static final class TestProviderRequest implements ProviderRequest {
        private final EndpointConfig endpointConfig;
        private final SecurityEnvironment environment;

        private TestProviderRequest(EndpointConfig endpointConfig, SecurityEnvironment environment) {
            this.endpointConfig = endpointConfig;
            this.environment = environment;
        }

        @Override
        public EndpointConfig endpointConfig() {
            return endpointConfig;
        }

        @Override
        public SecurityContext securityContext() {
            return null;
        }

        @Override
        public Optional<Subject> subject() {
            return Optional.empty();
        }

        @Override
        public Optional<Subject> service() {
            return Optional.empty();
        }

        @Override
        public SecurityEnvironment env() {
            return environment;
        }

        @Override
        public Optional<Object> getObject() {
            return Optional.empty();
        }

        @Override
        public Object abacAttributeRaw(String key) {
            return null;
        }

        @Override
        public Collection<String> abacAttributeNames() {
            return List.of();
        }
    }
}
