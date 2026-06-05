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

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;

import javax.net.ssl.SSLContext;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import io.helidon.common.configurable.Resource;
import io.helidon.common.pki.Keys;
import io.helidon.common.socket.SocketOptions;
import io.helidon.common.tls.Tls;
import io.helidon.common.tls.TlsConfig;
import io.helidon.common.tls.TlsManager;
import io.helidon.config.Config;
import io.helidon.config.ConfigSources;
import io.helidon.config.spi.ConfigNode.ListNode;
import io.helidon.config.spi.ConfigNode.ObjectNode;
import io.helidon.security.SecurityEnvironment;
import io.helidon.security.SecurityResponse;
import io.helidon.security.providers.common.OutboundTarget;
import io.helidon.webclient.api.Proxy;
import io.helidon.webclient.api.WebClientConfig;
import io.helidon.webserver.WebServer;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class OidcProviderConfigTest {
    private static final URI ISSUER = URI.create("https://issuer.example");
    private static final URI WELL_KNOWN_URI = URI.create("https://issuer.example/.well-known/openid-configuration");
    private static final URI JWKS_URI = URI.create("https://issuer.example/jwks");
    private static final URI REDIRECTION_ENDPOINT_URI = URI.create("https://rp.example/oidc/callback");
    private static final URI LOGOUT_ENDPOINT_URI = URI.create("/oidc/logout");
    private static final URI END_SESSION_ENDPOINT_URI = URI.create("https://issuer.example/logout");
    private static final URI USER_INFO_ENDPOINT_URI = URI.create("https://issuer.example/userinfo");
    private static final URI POST_LOGOUT_REDIRECT_URI = URI.create("https://rp.example/logged-out");
    private static final URI AUTHORIZATION_ENDPOINT_URI = URI.create("https://issuer.example/authorize");
    private static final URI TOKEN_ENDPOINT_URI = URI.create("https://issuer.example/token");
    private static final String AUDIENCE = "api://default";

    @Test
    void defaultsAreSecureAndSpecFirst() {
        OidcProviderConfig providerConfig = OidcProviderConfig.create();
        OidcTenantConfig tenantConfig = OidcTenantConfig.create();
        OidcAuthorizationCodeConfig authorizationCode = OidcAuthorizationCodeConfig.create();
        OidcLogoutConfig logout = OidcLogoutConfig.create();
        OidcEndSessionConfig endSession = OidcEndSessionConfig.create();
        OidcUserInfoConfig userInfo = OidcUserInfoConfig.create();
        OidcProtectedResourceConfig protectedResource = OidcProtectedResourceConfig.create();
        OidcEndpointPolicyConfig endpointPolicy = OidcEndpointPolicyConfig.create();
        OidcTokenTransportConfig tokenTransport = OidcTokenTransportConfig.create();
        OidcTokenValidationConfig tokenValidation = OidcTokenValidationConfig.create();
        OidcCookieConfig cookies = OidcCookieConfig.create();
        OidcSubjectMappingConfig subjectMapping = OidcSubjectMappingConfig.create();
        OidcClientAssertionConfig clientAssertion = OidcClientAssertionConfig.create();
        OidcJwkSetConfig jwkSet = OidcJwkSetConfig.create();

        assertThat(providerConfig.providerName(), is("oidc-next"));
        assertThat(providerConfig.optional(), is(false));
        assertThat(providerConfig.socket().isEmpty(), is(true));
        assertThat(providerConfig.socketRequired(), is(true));
        assertThat(providerConfig.tenants().isEmpty(), is(true));
        assertThat(tenantConfig.enabled(), is(true));
        assertThat(tenantConfig.idTokenDecryptionJwk().isEmpty(), is(true));
        assertThat(tenantConfig.protectedResource().isEmpty(), is(true));
        assertThat(tenantConfig.authorizationCode().isEmpty(), is(true));
        assertThat(tenantConfig.endpointPolicy(), is(endpointPolicy));
        assertThat(endpointPolicy.acceptedCredentials().isEmpty(), is(true));
        assertThat(endpointPolicy.authenticationFailureResponse().isEmpty(), is(true));
        assertThat(tenantConfig.logout().isEmpty(), is(true));
        assertThat(authorizationCode.enabled(), is(true));
        assertThat(logout.enabled(), is(true));
        assertThat(logout.localEndpointUri(), is(LOGOUT_ENDPOINT_URI));
        assertThat(logout.endSession().isEmpty(), is(true));
        assertThat(endSession.enabled(), is(true));
        assertThat(endSession.idTokenHintRequired(), is(true));
        assertThat(endSession.postLogoutRedirectUri().isEmpty(), is(true));
        assertThat(endSession.allowedPostLogoutRedirectUris().isEmpty(), is(true));
        assertThat(tenantConfig.userInfo().isEmpty(), is(true));
        assertThat(userInfo.enabled(), is(true));
        assertThat(protectedResource.enabled(), is(true));
        assertThat(authorizationCode.scopes(), is(List.of("openid")));
        assertThat(authorizationCode.pkceRequired(), is(true));
        assertThat(authorizationCode.pkceMethod(), is(OidcPkceMethod.S256));
        assertThat(tokenTransport.authorizationHeaderEnabled(), is(true));
        assertThat(tokenTransport.queryParameterEnabled(), is(false));
        assertThat(tokenTransport.secureTransportRequired(), is(true));
        assertThat(tokenValidation.audienceValidationEnabled(), is(true));
        assertThat(tokenValidation.allowedAlgorithms(), is(List.of("RS256")));
        assertThat(subjectMapping.principalIdClaimPaths(), is(List.of("sub", "username", "client_id")));
        assertThat(subjectMapping.principalNameClaimPaths(), is(List.of("preferred_username", "username")));
        assertThat(subjectMapping.roleClaimPaths(), is(List.of("groups")));
        assertThat(subjectMapping.scopeClaimPaths(), is(List.of("scope")));
        assertThat(subjectMapping.scopeGrantsEnabled(), is(true));
        assertThat(tenantConfig.subjectMapping().principalIdClaimPaths(), is(subjectMapping.principalIdClaimPaths()));
        assertThat(cookies.authenticationRequestCookieName(), is("__Host-helidon-oidc-state"));
        assertThat(cookies.localAuthenticationCookieName(), is("__Host-helidon-oidc-auth"));
        assertThat(List.of(OidcPkceMethod.values()), is(List.of(OidcPkceMethod.PLAIN, OidcPkceMethod.S256)));
        assertThat(List.of(OidcEndpointCredential.values()),
                   is(List.of(OidcEndpointCredential.BEARER_TOKEN,
                              OidcEndpointCredential.AUTHENTICATION_COOKIE)));
        assertThat(List.of(OidcAuthenticationFailureResponse.values()),
                   is(List.of(OidcAuthenticationFailureResponse.UNAUTHORIZED,
                              OidcAuthenticationFailureResponse.AUTHORIZATION_CODE_REDIRECT)));
        assertThat(clientAssertion.algorithm().isEmpty(), is(true));
        assertThat(clientAssertion.keyId().isEmpty(), is(true));
        assertThat(clientAssertion.jwk().isEmpty(), is(true));
        assertThat(clientAssertion.lifetime(), is(Duration.ofMinutes(1)));
        assertThat(jwkSet.unknownKeyIdRefreshEnabled(), is(true));
        assertThat(jwkSet.unknownKeyIdRefreshInterval(), is(Duration.ofMinutes(5)));
        assertThat(jwkSet.refreshInterval().isEmpty(), is(true));
        assertThat(jwkSet.staleOnError(), is(true));
        assertThat(providerConfig.outboundTargets().isEmpty(), is(true));
        assertThat(List.of(OidcClientAuthenticationMethod.values()),
                   is(List.of(OidcClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                              OidcClientAuthenticationMethod.CLIENT_SECRET_POST,
                              OidcClientAuthenticationMethod.CLIENT_SECRET_JWT,
                              OidcClientAuthenticationMethod.PRIVATE_KEY_JWT,
                              OidcClientAuthenticationMethod.TLS_CLIENT_AUTH,
                              OidcClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH,
                              OidcClientAuthenticationMethod.NONE)));
    }

    @Test
    void pkceMethodsUseSpecWireNames() {
        assertThat(OidcPkceMethod.PLAIN.wireName(), is("plain"));
        assertThat(OidcPkceMethod.S256.wireName(), is("S256"));
        assertThat(OidcAuthenticationRequestFactory.codeChallenge("plain-verifier", OidcPkceMethod.PLAIN),
                   is("plain-verifier"));
    }

    @Test
    void clientAuthenticationMethodsUseSpecWireNames() {
        assertThat(OidcClientAuthenticationMethod.CLIENT_SECRET_BASIC.wireName(), is("client_secret_basic"));
        assertThat(OidcClientAuthenticationMethod.CLIENT_SECRET_POST.wireName(), is("client_secret_post"));
        assertThat(OidcClientAuthenticationMethod.CLIENT_SECRET_JWT.wireName(), is("client_secret_jwt"));
        assertThat(OidcClientAuthenticationMethod.PRIVATE_KEY_JWT.wireName(), is("private_key_jwt"));
        assertThat(OidcClientAuthenticationMethod.TLS_CLIENT_AUTH.wireName(), is("tls_client_auth"));
        assertThat(OidcClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH.wireName(),
                   is("self_signed_tls_client_auth"));
        assertThat(OidcClientAuthenticationMethod.NONE.wireName(), is("none"));
    }

    @Test
    void mutualTlsClientAuthenticationMethodsCanBeReadFromConfig() {
        Config tlsClientAuth = Config.builder()
                .sources(ConfigSources.create(Map.of("tenants.default.client-id", "client-id",
                                                     "tenants.default.token-endpoint-auth-method", "TLS_CLIENT_AUTH")))
                .build();
        Config selfSignedTlsClientAuth = Config.builder()
                .sources(ConfigSources.create(Map.of("tenants.default.client-id", "client-id",
                                                     "tenants.default.token-endpoint-auth-method",
                                                     "SELF_SIGNED_TLS_CLIENT_AUTH")))
                .build();

        assertThat(OidcProviderConfig.create(tlsClientAuth)
                           .tenants()
                           .get("default")
                           .tokenEndpointAuthenticationMethod()
                           .orElseThrow(),
                   is(OidcClientAuthenticationMethod.TLS_CLIENT_AUTH));
        assertThat(OidcProviderConfig.create(selfSignedTlsClientAuth)
                           .tenants()
                           .get("default")
                           .tokenEndpointAuthenticationMethod()
                           .orElseThrow(),
                   is(OidcClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH));
    }

    @Test
    void providerConfigCreatesImmutableValuesAndHidesSecrets() {
        OidcTenantConfig tenant = jwtProtectedResourceTenant();

        OidcProviderConfig providerConfig = OidcProviderConfig.builder()
                .tenants(Map.of("default", tenant))
                .buildPrototype();

        assertThat(providerConfig.defaultTenant().orElse(""), is("default"));
        assertThat(providerConfig.tenants().get("default").clientId().orElse(""), is("client-id"));
        assertThat(providerConfig.toString().contains("client-secret-value"), is(false));
        assertThrows(UnsupportedOperationException.class, () -> providerConfig.tenants().put("other", tenant));
    }

    @Test
    void providerConfigCanBeReadFromConfig() {
        Config config = Config.builder()
                .sources(ConfigSources.create(Map.ofEntries(
                        Map.entry("tenants.default.issuer", ISSUER.toString()),
                        Map.entry("tenants.default.client-id", "client-id"),
                        Map.entry("tenants.default.client-secret", "client-secret-value"),
                        Map.entry("tenants.default.token-endpoint-auth-method", "PRIVATE_KEY_JWT"),
                        Map.entry("tenants.default.id-token-decryption-jwk.resource-path",
                                  "oidc-next-sign-jwk.json"),
                        Map.entry("tenants.default.client-assertion.algorithm", "RS256"),
                        Map.entry("tenants.default.client-assertion.key-id", "sign-rsa"),
                        Map.entry("tenants.default.client-assertion.jwk.resource-path", "oidc-next-sign-jwk.json"),
                        Map.entry("tenants.default.client-assertion.lifetime", "PT2M"),
                        Map.entry("tenants.default.jwk-set.unknown-key-id-refresh-enabled", "false"),
                        Map.entry("tenants.default.jwk-set.unknown-key-id-refresh-interval", "PT30S"),
                        Map.entry("tenants.default.jwk-set.refresh-interval", "PT10M"),
                        Map.entry("tenants.default.jwk-set.stale-on-error", "false"),
                        Map.entry("tenants.default.endpoints.jwks-uri", JWKS_URI.toString()),
                        Map.entry("tenants.default.webclient.read-timeout", "PT2S"),
                        Map.entry("tenants.default.webclient.proxy.type", "HTTP"),
                        Map.entry("tenants.default.webclient.proxy.host", "proxy.example.com"),
                        Map.entry("tenants.default.webclient.proxy.port", "8080"),
                        Map.entry("tenants.default.authorization-code.redirection-endpoint-uri",
                                  REDIRECTION_ENDPOINT_URI.toString()),
                        Map.entry("tenants.default.authorization-code.pkce-method", "plain"),
                        Map.entry("tenants.default.cookies.encryption-secret",
                                  "this-secret-is-long-enough-for-config-test"),
                        Map.entry("tenants.default.protected-resource.token-validation.method", "JWT"),
                        Map.entry("tenants.default.protected-resource.token-validation.audience", AUDIENCE),
                        Map.entry("tenants.default.endpoint-policy.accepted-credentials.0", "bearer-token"),
                        Map.entry("tenants.default.endpoint-policy.accepted-credentials.1", "authentication-cookie"),
                        Map.entry("tenants.default.endpoint-policy.authentication-failure-response", "unauthorized"),
                        Map.entry("tenants.default.logout.enabled", "false"),
                        Map.entry("tenants.default.logout.local-endpoint-uri", "/oidc/logout"),
                        Map.entry("tenants.default.logout.end-session.enabled", "false"),
                        Map.entry("tenants.default.logout.end-session.id-token-hint-required", "false"),
                        Map.entry("tenants.default.logout.end-session.post-logout-redirect-uri",
                                  POST_LOGOUT_REDIRECT_URI.toString()),
                        Map.entry("tenants.default.logout.end-session.allowed-post-logout-redirect-uris.0",
                                  "https://rp.example/other-logged-out"),
                        Map.entry("tenants.default.user-info.enabled", "false"),
                        Map.entry("tenants.default.subject-mapping.principal-id-claim-paths.0", "custom_sub"),
                        Map.entry("tenants.default.subject-mapping.principal-id-claim-paths.1", "sub"),
                        Map.entry("tenants.default.subject-mapping.principal-name-claim-paths.0", "display_name"),
                        Map.entry("tenants.default.subject-mapping.role-claim-paths.0", "realm_access.roles"),
                        Map.entry("tenants.default.subject-mapping.scope-claim-paths.0", "scp"),
                        Map.entry("tenants.default.subject-mapping.scope-grants-enabled", "false"),
                        Map.entry("socket", "oidc"),
                        Map.entry("socket-required", "false"),
                        Map.entry("outbound.0.name", "orders"),
                        Map.entry("outbound.0.transports.0", "https"),
                        Map.entry("outbound.0.hosts.0", "api.example.com"),
                        Map.entry("outbound.0.paths.0", "/orders/.*"))))
                .build();

        OidcProviderConfig providerConfig = OidcProviderConfig.create(config);

        assertThat(providerConfig.defaultTenant().orElse(""), is("default"));
        assertThat(providerConfig.socket().orElse(""), is("oidc"));
        assertThat(providerConfig.socketRequired(), is(false));
        OidcTenantConfig tenant = providerConfig.tenants().get("default");
        OutboundTarget outboundTarget = providerConfig.outboundTargets().getFirst();
        assertThat(outboundTarget.name(), is("orders"));
        assertThat(outboundTarget.hosts(), is(Set.of("api.example.com")));
        assertThat(tenant.issuer().orElseThrow(), is(ISSUER.toString()));
        assertThat(tenant.clientId().orElse(""), is("client-id"));
        assertThat(tenant.tokenEndpointAuthenticationMethod().orElseThrow(),
                   is(OidcClientAuthenticationMethod.PRIVATE_KEY_JWT));
        assertThat(tenant.idTokenDecryptionJwk().orElseThrow().location(), is("oidc-next-sign-jwk.json"));
        assertThat(providerConfig.toString().contains("oidc-next-sign-jwk.json"), is(false));
        assertThat(tenant.clientAssertion().algorithm().orElse(""), is("RS256"));
        assertThat(tenant.clientAssertion().keyId().orElse(""), is("sign-rsa"));
        assertThat(tenant.clientAssertion().jwk().orElseThrow().location(), is("oidc-next-sign-jwk.json"));
        assertThat(providerConfig.toString().contains("oidc-next-sign-jwk.json"), is(false));
        assertThat(tenant.clientAssertion().lifetime(), is(Duration.ofMinutes(2)));
        assertThat(tenant.jwkSet().unknownKeyIdRefreshEnabled(), is(false));
        assertThat(tenant.jwkSet().unknownKeyIdRefreshInterval(), is(Duration.ofSeconds(30)));
        assertThat(tenant.jwkSet().refreshInterval().orElseThrow(), is(Duration.ofMinutes(10)));
        assertThat(tenant.jwkSet().staleOnError(), is(false));
        assertThat(tenant.endpoints().jwksUri().orElseThrow(), is(JWKS_URI));
        assertThat(tenant.webClient().readTimeout().orElseThrow(), is(Duration.ofSeconds(2)));
        assertThat(tenant.webClient().proxy().type(), is(Proxy.ProxyType.HTTP));
        assertThat(tenant.webClient().proxy().host(), is("proxy.example.com"));
        assertThat(tenant.webClient().proxy().port(), is(8080));
        OidcAuthorizationCodeConfig authorizationCode = tenant.authorizationCode().orElseThrow();
        assertThat(authorizationCode.redirectionEndpointUri().orElseThrow(), is(REDIRECTION_ENDPOINT_URI));
        assertThat(authorizationCode.pkceMethod(), is(OidcPkceMethod.PLAIN));
        OidcProtectedResourceConfig protectedResource = tenant.protectedResource().orElseThrow();
        assertThat(protectedResource.enabled(), is(true));
        assertThat(protectedResource.tokenValidation().method().orElseThrow(),
                   is(OidcTokenValidationMethod.JWT));
        assertThat(protectedResource.tokenValidation().audience().orElse(""), is(AUDIENCE));
        assertThat(tenant.endpointPolicy().acceptedCredentials(),
                   is(List.of(OidcEndpointCredential.BEARER_TOKEN,
                              OidcEndpointCredential.AUTHENTICATION_COOKIE)));
        assertThat(tenant.endpointPolicy().authenticationFailureResponse().orElseThrow(),
                   is(OidcAuthenticationFailureResponse.UNAUTHORIZED));
        assertThat(tenant.logout().orElseThrow().localEndpointUri(), is(LOGOUT_ENDPOINT_URI));
        assertThat(tenant.logout().orElseThrow().enabled(), is(false));
        OidcEndSessionConfig endSession = tenant.logout().orElseThrow().endSession().orElseThrow();
        assertThat(endSession.enabled(), is(false));
        assertThat(endSession.idTokenHintRequired(), is(false));
        assertThat(endSession.postLogoutRedirectUri().orElseThrow(), is(POST_LOGOUT_REDIRECT_URI));
        assertThat(endSession.allowedPostLogoutRedirectUris(),
                   is(List.of(URI.create("https://rp.example/other-logged-out"))));
        assertThat(tenant.userInfo().orElseThrow().enabled(), is(false));
        assertThat(tenant.subjectMapping().principalIdClaimPaths(), is(List.of("custom_sub", "sub")));
        assertThat(tenant.subjectMapping().principalNameClaimPaths(), is(List.of("display_name")));
        assertThat(tenant.subjectMapping().roleClaimPaths(), is(List.of("realm_access.roles")));
        assertThat(tenant.subjectMapping().scopeClaimPaths(), is(List.of("scp")));
        assertThat(tenant.subjectMapping().scopeGrantsEnabled(), is(false));
    }

    @Test
    void singleTenantCanBeReadFromProviderRootConfig() {
        Config config = Config.builder()
                .sources(ConfigSources.create(Map.ofEntries(
                        Map.entry("issuer", ISSUER.toString()),
                        Map.entry("client-id", "client-id"),
                        Map.entry("client-secret", "client-secret-value"),
                        Map.entry("id-token-decryption-jwk.resource-path", "oidc-next-sign-jwk.json"),
                        Map.entry("jwk-set.refresh-interval", "PT15M"),
                        Map.entry("endpoints.jwks-uri", JWKS_URI.toString()),
                        Map.entry("protected-resource.token-validation.method", "JWT"),
                        Map.entry("protected-resource.token-validation.audience", AUDIENCE))))
                .build();

        OidcProviderConfig providerConfig = OidcProviderConfig.create(config);
        OidcTenantConfig tenant = providerConfig.tenants().get("default");

        assertThat(providerConfig.defaultTenant().orElseThrow(), is("default"));
        assertThat(tenant.issuer().orElseThrow(), is(ISSUER.toString()));
        assertThat(tenant.clientId().orElseThrow(), is("client-id"));
        assertThat(tenant.clientSecret().orElseThrow(), is("client-secret-value"));
        assertThat(tenant.idTokenDecryptionJwk().orElseThrow().location(), is("oidc-next-sign-jwk.json"));
        assertThat(tenant.jwkSet().refreshInterval().orElseThrow(), is(Duration.ofMinutes(15)));
        assertThat(tenant.endpoints().jwksUri().orElseThrow(), is(JWKS_URI));
        assertThat(tenant.protectedResource().orElseThrow().tokenValidation().method().orElseThrow(),
                   is(OidcTokenValidationMethod.JWT));
    }

    @Test
    void singleTenantCanBeBuiltFromProviderRootBuilder() {
        OidcProviderConfig providerConfig = OidcProviderConfig.builder()
                .issuer(ISSUER.toString())
                .clientId("client-id")
                .endpoints(it -> it.jwksUri(JWKS_URI))
                .protectedResource(it -> it.tokenValidation(validation -> validation
                        .method(OidcTokenValidationMethod.JWT)
                        .audience(AUDIENCE)))
                .buildPrototype();
        OidcTenantConfig tenant = providerConfig.tenants().get("default");

        assertThat(providerConfig.defaultTenant().orElseThrow(), is("default"));
        assertThat(tenant.issuer().orElseThrow(), is(ISSUER.toString()));
        assertThat(tenant.clientId().orElseThrow(), is("client-id"));
        assertThat(tenant.endpoints().jwksUri().orElseThrow(), is(JWKS_URI));
        assertThat(tenant.protectedResource().orElseThrow().tokenValidation().method().orElseThrow(),
                   is(OidcTokenValidationMethod.JWT));
    }

    @Test
    void singleTenantRootBuilderCanBeReusedAndCopied() {
        OidcProviderConfig.Builder builder = OidcProviderConfig.builder()
                .issuer(ISSUER.toString())
                .clientId("client-id");

        OidcProviderConfig first = builder.buildPrototype();
        OidcProviderConfig second = builder.buildPrototype();
        OidcProviderConfig copy = OidcProviderConfig.builder()
                .from(first)
                .buildPrototype();

        assertThat(second.tenants().get("default"), is(first.tenants().get("default")));
        assertThat(copy.tenants().get("default"), is(first.tenants().get("default")));
    }

    @Test
    void singleTenantRootBuilderDetectsNestedOnlyConfiguration() {
        OidcProviderConfig providerConfig = OidcProviderConfig.builder()
                .webClient(WebClientConfig.builder()
                        .connectTimeout(Duration.ofSeconds(2))
                        .buildPrototype())
                .buildPrototype();
        OidcTenantConfig tenant = providerConfig.tenants().get("default");

        assertThat(providerConfig.defaultTenant().orElseThrow(), is("default"));
        assertThat(tenant.webClient().connectTimeout().orElseThrow(), is(Duration.ofSeconds(2)));
    }

    @Test
    void singleTenantRootConfigUsesDefaultTenantNameWhenConfigured() {
        Config config = Config.builder()
                .sources(ConfigSources.create(Map.of("default-tenant", "web",
                                                     "issuer", ISSUER.toString())))
                .build();

        OidcProviderConfig providerConfig = OidcProviderConfig.create(config);

        assertThat(providerConfig.defaultTenant().orElseThrow(), is("web"));
        assertThat(providerConfig.tenants().containsKey("web"), is(true));
    }

    @Test
    void featureUsesDefaultSocketWhenProviderSocketIsNotConfigured() {
        OidcProviderConfig providerConfig = OidcProviderConfig.create();
        OidcFeature feature = OidcFeature.create(providerConfig);

        assertThat(feature.socket(), is(WebServer.DEFAULT_SOCKET_NAME));
        assertThat(feature.socketRequired(), is(false));
    }

    @Test
    void featureUsesConfiguredSocket() {
        OidcProviderConfig providerConfig = OidcProviderConfig.builder()
                .socket("oidc")
                .buildPrototype();
        OidcFeature feature = OidcFeature.create(providerConfig);

        assertThat(feature.socket(), is("oidc"));
        assertThat(feature.socketRequired(), is(true));
    }

    @Test
    void featureCanAllowConfiguredSocketFallback() {
        OidcProviderConfig providerConfig = OidcProviderConfig.builder()
                .socket("oidc")
                .socketRequired(false)
                .buildPrototype();
        OidcFeature feature = OidcFeature.create(providerConfig);

        assertThat(feature.socket(), is("oidc"));
        assertThat(feature.socketRequired(), is(false));
    }

    @Test
    void singleTenantRootConfigCannotBeCombinedWithTenants() {
        Config config = Config.builder()
                .sources(ConfigSources.create(Map.of("issuer", ISSUER.toString(),
                                                     "tenants.default.issuer", ISSUER.toString())))
                .build();

        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                                                       () -> OidcProviderConfig.create(config));

        assertThat(thrown.getMessage(), containsString("Root tenant configuration"));
    }

    @Test
    void jwkSetRejectsNegativeUnknownKeyIdRefreshInterval() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                                                       () -> OidcTenantConfig.builder()
                                                               .jwkSet(it -> it.unknownKeyIdRefreshInterval(
                                                                       Duration.ofSeconds(-1)))
                                                               .buildPrototype());

        assertThat(thrown.getMessage(), containsString("unknown-key-id-refresh-interval"));
    }

    @Test
    void jwkSetRejectsNonPositiveRefreshInterval() {
        IllegalArgumentException zero = assertThrows(IllegalArgumentException.class,
                                                     () -> OidcTenantConfig.builder()
                                                             .jwkSet(it -> it.refreshInterval(Duration.ZERO))
                                                             .buildPrototype());
        IllegalArgumentException negative = assertThrows(IllegalArgumentException.class,
                                                         () -> OidcTenantConfig.builder()
                                                                 .jwkSet(it -> it.refreshInterval(
                                                                         Duration.ofSeconds(-1)))
                                                                 .buildPrototype());

        assertThat(zero.getMessage(), containsString("jwk-set.refresh-interval"));
        assertThat(negative.getMessage(), containsString("jwk-set.refresh-interval"));
    }

    @Test
    void tenantWebClientUsesOidcDefaultReadTimeoutUnlessConfigured() {
        OidcTenantConfig defaultTenant = OidcTenantConfig.create();
        OidcTenantConfig configuredTenant = OidcTenantConfig.builder()
                .webClient(WebClientConfig.builder()
                        .readTimeout(Duration.ofSeconds(2))
                        .buildPrototype())
                .buildPrototype();
        OidcTenantConfig socketConfiguredTenant = OidcTenantConfig.builder()
                .webClient(WebClientConfig.builder()
                        .socketOptions(SocketOptions.builder()
                                .readTimeout(Duration.ofSeconds(4))
                                .build())
                        .buildPrototype())
                .buildPrototype();

        assertThat(OidcConfigSupport.createWebClient(defaultTenant).prototype().readTimeout().orElseThrow(),
                   is(Duration.ofSeconds(10)));
        assertThat(OidcConfigSupport.createWebClient(configuredTenant).prototype().readTimeout().orElseThrow(),
                   is(Duration.ofSeconds(2)));
        assertThat(OidcConfigSupport.createWebClient(socketConfiguredTenant).prototype().readTimeout().isEmpty(),
                   is(true));
        assertThat(OidcConfigSupport.createWebClient(socketConfiguredTenant).prototype().socketOptions().readTimeout(),
                   is(Duration.ofSeconds(4)));
    }

    @Test
    void disabledTenantCanKeepIncompleteFlowConfiguration() {
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .enabled(false)
                .protectedResource(OidcProtectedResourceConfig.create())
                .authorizationCode(OidcAuthorizationCodeConfig.create())
                .buildPrototype();

        assertThat(tenant.enabled(), is(false));
        assertThat(tenant.protectedResource().orElseThrow().enabled(), is(true));
        assertThat(tenant.authorizationCode().orElseThrow().enabled(), is(true));
    }

    @Test
    void tenantResolutionConfigRejectsInvalidValues() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                                                       () -> OidcTenantResolutionConfig.builder()
                                                               .headerName(" ")
                                                               .buildPrototype());

        assertThat(thrown.getMessage(), containsString("header-name"));

        thrown = assertThrows(IllegalArgumentException.class,
                              () -> OidcTenantResolutionConfig.builder()
                                      .pathSegment(-1)
                                      .buildPrototype());

        assertThat(thrown.getMessage(), containsString("path-segment"));

        thrown = assertThrows(IllegalArgumentException.class,
                              () -> OidcTenantResolutionConfig.builder()
                                      .pathTemplate(" ")
                                      .buildPrototype());

        assertThat(thrown.getMessage(), containsString("path-template"));

        thrown = assertThrows(IllegalArgumentException.class,
                              () -> OidcTenantResolutionConfig.builder()
                                      .pathTemplate("/tenants/{tenant}/{tenant}")
                                      .buildPrototype());

        assertThat(thrown.getMessage(), containsString("{tenant}"));

        thrown = assertThrows(IllegalArgumentException.class,
                              () -> OidcTenantResolutionConfig.builder()
                                      .pathTemplate("/tenants/tenant-{tenant}")
                                      .buildPrototype());

        assertThat(thrown.getMessage(), containsString("complete path segment"));

        thrown = assertThrows(IllegalArgumentException.class,
                              () -> OidcTenantResolutionConfig.builder()
                                      .hostTemplate(" ")
                                      .buildPrototype());

        assertThat(thrown.getMessage(), containsString("host-template"));

        thrown = assertThrows(IllegalArgumentException.class,
                              () -> OidcTenantResolutionConfig.builder()
                                      .hostTemplate("example.com")
                                      .buildPrototype());

        assertThat(thrown.getMessage(), containsString("{tenant}"));

        thrown = assertThrows(IllegalArgumentException.class,
                              () -> OidcTenantResolutionConfig.builder()
                                      .hostTemplate("{tenant}.{tenant}.example.com")
                                      .buildPrototype());

        assertThat(thrown.getMessage(), containsString("{tenant}"));
    }

    @Test
    void subjectMappingConfigRejectsInvalidClaimPaths() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .subjectMapping(it -> it.principalIdClaimPaths(List.of()))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("subject-mapping.principal-id-claim-paths"));

        thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .subjectMapping(it -> it.principalIdClaimPaths(List.of(" ")))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("subject-mapping.principal-id-claim-paths"));

        thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .subjectMapping(it -> it.roleClaimPaths(List.of("realm_access..roles")))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("subject-mapping.role-claim-paths"));

        thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .subjectMapping(it -> it.roleClaimPaths(List.of("realm_access. roles")))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("subject-mapping.role-claim-paths"));
    }

    @Test
    void protectedResourceRequiresValidationMethod() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .endpoints(it -> it.jwksUri(JWKS_URI))
                .protectedResource(OidcProtectedResourceConfig.create())
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("token-validation.method"));
    }

    @Test
    void jwtValidationRequiresIssuerOrWellKnownUriAndJwksOrWellKnownUri() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.JWT)))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("issuer or well-known-uri"));

        thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.JWT)))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("token-validation.audience"));

        OidcTenantConfig derivedWellKnownTenant = OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.JWT)
                                .audience(AUDIENCE)))
                .buildPrototype();
        assertThat(derivedWellKnownTenant.endpoints().jwksUri().isEmpty(), is(true));

        OidcTenantConfig explicitWellKnownTenant = OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .endpoints(it -> it.wellKnownUri(WELL_KNOWN_URI))
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.JWT)
                                .audience(AUDIENCE)))
                .buildPrototype();
        assertThat(explicitWellKnownTenant.endpoints().jwksUri().isEmpty(), is(true));

        OidcTenantConfig wellKnownOnlyTenant = OidcTenantConfig.builder()
                .endpoints(it -> it.wellKnownUri(WELL_KNOWN_URI))
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.JWT)
                                .audience(AUDIENCE)))
                .buildPrototype();
        assertThat(wellKnownOnlyTenant.issuer().isEmpty(), is(true));

        thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .endpoints(it -> it.jwksUri(JWKS_URI))
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.JWT)))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("token-validation.audience"));
    }

    @Test
    void tokenValidationMethodRequiresPrerequisitesWithoutProtectedResource() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .protectedResource(it -> it.enabled(false)
                        .tokenValidation(validation -> validation
                                .method(OidcTokenValidationMethod.JWT)
                                .audience(AUDIENCE)))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("issuer or well-known-uri"));

        thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .clientId("client-id")
                .clientSecret("client-secret")
                .protectedResource(it -> it.enabled(false)
                        .tokenValidation(validation -> validation
                                .method(OidcTokenValidationMethod.INTROSPECTION)
                                .audience(AUDIENCE)))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("introspection-endpoint-uri"));
    }

    @Test
    void jwtValidationRequiresSecureJwksUriScheme() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .endpoints(it -> it.jwksUri(URI.create("http://issuer.example/jwks")))
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.JWT)
                                .audience(AUDIENCE)))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("jwks-uri must use https"));
    }

    @Test
    void tokenValidationAllowedAlgorithmsRejectsNone() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .endpoints(it -> it.jwksUri(JWKS_URI))
                .protectedResource(it -> it.tokenValidation(validation -> validation
                        .method(OidcTokenValidationMethod.JWT)
                        .audience(AUDIENCE)
                        .allowedAlgorithms(List.of("RS256", " none "))))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("token-validation.allowed-algorithms"));
        assertThat(thrown.getMessage(), containsString("none"));
    }

    @Test
    void endpointTlsRequirementCanBeDisabledForJwksUri() {
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .endpoints(it -> it.jwksUri(URI.create("file:///tmp/oidc-next-jwks.json"))
                        .tlsRequired(false))
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.JWT)
                                .audience(AUDIENCE)))
                .buildPrototype();

        assertThat(tenant.endpoints().tlsRequired(), is(false));
    }

    @Test
    void issuerRejectsInsecureUriByDefault() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer("http://issuer.example")
                .endpoints(it -> it.jwksUri(JWKS_URI))
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.JWT)
                                .audience(AUDIENCE)))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("issuer must use https"));
    }

    @Test
    void endpointTlsRequirementCanBeDisabledForIssuer() {
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .issuer("http://issuer.example")
                .endpoints(it -> it.jwksUri(JWKS_URI)
                        .tlsRequired(false))
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.JWT)
                                .audience(AUDIENCE)))
                .buildPrototype();

        assertThat(tenant.endpoints().tlsRequired(), is(false));
    }

    @Test
    void issuerRejectsQueryAndFragment() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer("https://issuer.example?tenant=default")
                .endpoints(it -> it.jwksUri(JWKS_URI))
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.JWT)
                                .audience(AUDIENCE)))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("issuer must not include a query"));

        thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer("https://issuer.example#fragment")
                .endpoints(it -> it.jwksUri(JWKS_URI))
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.JWT)
                                .audience(AUDIENCE)))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("issuer must not include a fragment"));
    }

    @Test
    void jwtValidationCanExplicitlyDisableAudienceValidation() {
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .endpoints(it -> it.jwksUri(JWKS_URI))
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.JWT)
                                .audienceValidationEnabled(false)))
                .buildPrototype();

        OidcTokenValidationConfig tokenValidation = tenant.protectedResource().orElseThrow().tokenValidation();
        assertThat(tokenValidation.audience().isEmpty(), is(true));
        assertThat(tokenValidation.audienceValidationEnabled(), is(false));
    }

    @Test
    void audienceCanBeDisabledFromConfig() {
        Config config = Config.builder()
                .sources(ConfigSources.create(Map.of(
                        "tenants.default.issuer", ISSUER.toString(),
                        "tenants.default.endpoints.jwks-uri", JWKS_URI.toString(),
                        "tenants.default.protected-resource.token-validation.method", "JWT",
                        "tenants.default.protected-resource.token-validation.audience-validation-enabled", "false")))
                .build();

        OidcTokenValidationConfig tokenValidation = OidcProviderConfig.create(config)
                .tenants()
                .get("default")
                .protectedResource()
                .orElseThrow()
                .tokenValidation();

        assertThat(tokenValidation.audience().isEmpty(), is(true));
        assertThat(tokenValidation.audienceValidationEnabled(), is(false));
    }

    @Test
    void introspectionRequiresEndpointAndClientAuthentication() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .clientId("client-id")
                .clientSecret("client-secret-value")
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.INTROSPECTION)))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("introspection-endpoint-uri or well-known-uri"));

        thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .endpoints(it -> it.introspectionEndpointUri(URI.create("https://issuer.example/introspect")))
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.INTROSPECTION)))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("client-id"));

        thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .clientId("client-id")
                .endpoints(it -> it.introspectionEndpointUri(URI.create("https://issuer.example/introspect")))
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.INTROSPECTION)))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("client-secret"));
    }

    @Test
    void introspectionRequiresAudienceWhenAudienceValidationIsEnabled() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .clientId("client-id")
                .clientSecret("client-secret-value")
                .endpoints(it -> it.introspectionEndpointUri(URI.create("https://issuer.example/introspect")))
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.INTROSPECTION)))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("token-validation.audience"));
    }

    @Test
    void introspectionCanUseWellKnownMetadata() {
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .clientId("client-id")
                .clientSecret("client-secret-value")
                .endpoints(it -> it.wellKnownUri(URI.create("https://issuer.example/.well-known/openid-configuration")))
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.INTROSPECTION)
                                .audience("api://default")))
                .buildPrototype();

        assertThat(tenant.endpoints().introspectionEndpointUri().isEmpty(), is(true));
    }

    @Test
    void introspectionRejectsInsecureRemoteEndpoint() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .clientId("client-id")
                .clientSecret("client-secret-value")
                .endpoints(it -> it.introspectionEndpointUri(URI.create("http://issuer.example/introspect")))
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.INTROSPECTION)
                                .audience("api://default")))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("introspection-endpoint-uri must use https"));
    }

    @Test
    void endpointTlsRequirementCanBeDisabledForIntrospection() {
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .clientId("client-id")
                .clientSecret("client-secret-value")
                .endpoints(it -> it.introspectionEndpointUri(URI.create("http://issuer.example/introspect"))
                        .tlsRequired(false))
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.INTROSPECTION)
                                .audience("api://default")))
                .buildPrototype();

        assertThat(tenant.endpoints().tlsRequired(), is(false));
    }

    @Test
    void authorizationCodeFlowRequiresClientAndDefaultsRedirectionEndpoint() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .endpoints(it -> it.authorizationEndpointUri(URI.create("https://issuer.example/authorize"))
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .authorizationCode(OidcAuthorizationCodeConfig.create())
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("client-id"));

        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId("client-id")
                .endpoints(it -> it.authorizationEndpointUri(URI.create("https://issuer.example/authorize"))
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .authorizationCode(OidcAuthorizationCodeConfig.create())
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype();

        assertThat(tenant.authorizationCode().orElseThrow().redirectionEndpointUri().orElseThrow(),
                   is(URI.create("/oidc/callback")));
    }

    @Test
    void authorizationCodeFlowRejectsInvalidRedirectionEndpointUri() {
        OidcTenantConfig localRedirectionEndpointTenant = OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId("client-id")
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .authorizationCode(it -> it.redirectionEndpointUri(URI.create("/oidc/callback")))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype();

        assertThat(localRedirectionEndpointTenant.authorizationCode()
                           .orElseThrow()
                           .redirectionEndpointUri()
                           .orElseThrow(),
                   is(URI.create("/oidc/callback")));

        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId("client-id")
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .authorizationCode(it -> it.redirectionEndpointUri(URI.create("oidc/callback")))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("redirection-endpoint-uri must be an absolute URI or local absolute path"));

        thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId("client-id")
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .authorizationCode(it -> it.redirectionEndpointUri(URI.create("https://rp.example/oidc/callback#fragment")))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("redirection-endpoint-uri must not include a fragment"));

        thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId("client-id")
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .authorizationCode(it -> it.redirectionEndpointUri(URI.create("http://rp.example/oidc/callback")))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("redirection-endpoint-uri must use https"));
    }

    @Test
    void endpointTlsRequirementCanBeDisabledForRedirectionEndpoint() {
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId("client-id")
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI)
                        .tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(URI.create("http://rp.example/oidc/callback")))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype();

        assertThat(tenant.endpoints().tlsRequired(), is(false));
    }

    @Test
    void authorizationCodeFlowRequiresOpenIdScope() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId("client-id")
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI)
                        .scopes(List.of("email")))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("openid scope"));
    }

    @Test
    void authorizationCodeFlowRejectsInvalidScopes() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId("client-id")
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI)
                        .scopes(List.of("openid", "profile read")))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("authorization-code.scopes"));
        assertThat(thrown.getMessage(), containsString("invalid scope"));

        thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId("client-id")
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI)
                        .scopes(List.of("openid", "openid")))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("duplicate scope"));
    }

    @Test
    void authorizationCodeFlowRequiresCookieEncryptionSecret() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId("client-id")
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("cookies.encryption-secret"));
    }

    @Test
    void authorizationCodeFlowRejectsInsecureAuthorizationEndpoint() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId("client-id")
                .endpoints(it -> it.authorizationEndpointUri(URI.create("http://issuer.example/authorize"))
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("authorization-endpoint-uri must use https"));
    }

    @Test
    void endpointTlsRequirementCanBeDisabledForAuthorizationEndpoint() {
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId("client-id")
                .endpoints(it -> it.authorizationEndpointUri(URI.create("http://issuer.example/authorize"))
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI)
                        .tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype();

        assertThat(tenant.endpoints().tlsRequired(), is(false));
    }

    @Test
    void authorizationCodeFlowRejectsInsecureTokenEndpoint() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId("client-id")
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(URI.create("http://issuer.example/token")))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("token-endpoint-uri must use https"));
    }

    @Test
    void endpointTlsRequirementCanBeDisabledForTokenEndpoint() {
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId("client-id")
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(URI.create("http://issuer.example/token"))
                        .tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype();

        assertThat(tenant.endpoints().tlsRequired(), is(false));
    }

    @Test
    void authorizationCodeFlowRejectsTokenEndpointWithFragment() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId("client-id")
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(URI.create("https://issuer.example/token#fragment")))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("token-endpoint-uri must not include a fragment"));
    }

    @Test
    void authorizationCodeFlowRejectsAuthorizationEndpointWithFragment() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId("client-id")
                .endpoints(it -> it.authorizationEndpointUri(URI.create("https://issuer.example/authorize#fragment"))
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("authorization-endpoint-uri must not include a fragment"));
    }

    @Test
    void logoutRequiresLocalEndpointPath() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .logout(logout -> logout.localEndpointUri(URI.create("https://app.example/oidc/logout")))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("local-endpoint-uri must be a local absolute path"));

        thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .logout(logout -> logout.localEndpointUri(URI.create("oidc/logout")))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("local absolute path"));

        thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .logout(logout -> logout.localEndpointUri(URI.create("")))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("local absolute path"));

        thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .logout(logout -> logout.localEndpointUri(URI.create("/oidc/logout?tenant=a")))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("query"));

        thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .logout(logout -> logout.localEndpointUri(URI.create("/oidc/logout#fragment")))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("fragment"));
    }

    @Test
    void logoutEndpointMustNotCollideWithRedirectionEndpoint() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId("client-id")
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .logout(logout -> logout.localEndpointUri(URI.create("/oidc/callback")))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("redirection-endpoint-uri"));
    }

    @Test
    void logoutEndSessionRequiresEndpointOrWellKnownUri() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .logout(logout -> logout.endSession(endSession -> { }))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("end-session-endpoint-uri or well-known-uri"));
    }

    @Test
    void logoutEndSessionRejectsInsecureEndpointByDefault() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .endpoints(it -> it.endSessionEndpointUri(URI.create("http://issuer.example/logout")))
                .logout(logout -> logout.endSession(endSession -> { }))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("end-session-endpoint-uri must use https"));
    }

    @Test
    void logoutEndSessionCanDisableTlsRequirementForEndpoint() {
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .clientId("client-id")
                .endpoints(it -> it.endSessionEndpointUri(URI.create("http://issuer.example/logout"))
                        .tlsRequired(false))
                .logout(logout -> logout.endSession(endSession -> endSession.idTokenHintRequired(false)))
                .buildPrototype();

        assertThat(tenant.endpoints().tlsRequired(), is(false));
    }

    @Test
    void logoutEndSessionRejectsEndpointWithFragment() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .endpoints(it -> it.endSessionEndpointUri(URI.create("https://issuer.example/logout#fragment")))
                .logout(logout -> logout.endSession(endSession -> { }))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("end-session-endpoint-uri must not include a fragment"));
    }

    @Test
    void logoutEndSessionRejectsInsecurePostLogoutRedirectUriByDefault() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .endpoints(it -> it.endSessionEndpointUri(END_SESSION_ENDPOINT_URI))
                .logout(logout -> logout.endSession(endSession -> endSession
                        .postLogoutRedirectUri(URI.create("http://rp.example/logged-out"))))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("post-logout-redirect-uri must use https"));
    }

    @Test
    void logoutEndSessionRejectsPostLogoutRedirectUriWithFragment() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId("client-id")
                .endpoints(it -> it.endSessionEndpointUri(END_SESSION_ENDPOINT_URI))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .logout(logout -> logout.endSession(endSession -> endSession
                        .postLogoutRedirectUri(URI.create("https://rp.example/logged-out#fragment"))))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("post-logout-redirect-uri must not include a fragment"));
    }

    @Test
    void logoutEndSessionRejectsInsecureAllowedPostLogoutRedirectUriByDefault() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId("client-id")
                .endpoints(it -> it.endSessionEndpointUri(END_SESSION_ENDPOINT_URI))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .logout(logout -> logout.endSession(endSession -> endSession
                        .addAllowedPostLogoutRedirectUri(URI.create("http://rp.example/logged-out"))))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("allowed-post-logout-redirect-uris must use https"));
    }

    @Test
    void logoutEndSessionRequiresAuthorizationCodeWhenIdTokenHintIsRequired() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .endpoints(it -> it.endSessionEndpointUri(END_SESSION_ENDPOINT_URI))
                .logout(logout -> logout.endSession(endSession -> { }))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("authorization-code"));
    }

    @Test
    void logoutEndSessionRequiresClientIdWhenIdTokenHintCanBeOmitted() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .endpoints(it -> it.endSessionEndpointUri(END_SESSION_ENDPOINT_URI))
                .logout(logout -> logout.endSession(endSession -> endSession.idTokenHintRequired(false)))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("client-id"));
    }

    @Test
    void authorizationCodeFlowCanExplicitlyDisablePkce() {
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId("client-id")
                .clientSecret("client-secret")
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI)
                        .pkceRequired(false))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype();

        OidcAuthorizationCodeConfig authorizationCode = tenant.authorizationCode().orElseThrow();
        assertThat(authorizationCode.pkceRequired(), is(false));
        assertThat(authorizationCode.pkceMethod(), is(OidcPkceMethod.S256));
    }

    @Test
    void authorizationCodeFlowRejectsDisabledPkceForPublicClient() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId("client-id")
                .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.NONE)
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI)
                        .pkceRequired(false))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("pkce-required"));
        assertThat(thrown.getMessage(), containsString("NONE"));
    }

    @Test
    void authorizationCodeFlowRejectsPlainPkceForPublicClient() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId("client-id")
                .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.NONE)
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI)
                        .pkceMethod(OidcPkceMethod.PLAIN))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("pkce-method"));
        assertThat(thrown.getMessage(), containsString("S256"));
        assertThat(thrown.getMessage(), containsString("NONE"));
    }

    @Test
    void userInfoRequiresAuthorizationCodeFlow() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId("client-id")
                .endpoints(it -> it.userInfoEndpointUri(USER_INFO_ENDPOINT_URI))
                .userInfo(it -> { })
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("authorization-code"));
    }

    @Test
    void userInfoRejectsInsecureEndpointByDefault() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId("client-id")
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI)
                        .userInfoEndpointUri(URI.create("http://issuer.example/userinfo")))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .userInfo(it -> { })
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("user-info-endpoint-uri must use https"));
    }

    @Test
    void endpointTlsRequirementCanBeDisabledForUserInfoEndpoint() {
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId("client-id")
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI)
                        .userInfoEndpointUri(URI.create("http://issuer.example/userinfo"))
                        .tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .userInfo(it -> { })
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype();

        assertThat(tenant.endpoints().tlsRequired(), is(false));
        assertThat(tenant.userInfo().orElseThrow().enabled(), is(true));
    }

    @Test
    void userInfoRejectsEndpointWithFragment() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId("client-id")
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI)
                        .userInfoEndpointUri(URI.create("https://issuer.example/userinfo#fragment")))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .userInfo(it -> { })
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("user-info-endpoint-uri must not include a fragment"));
    }

    @Test
    void authorizationCodeFlowCanUseClientSecretPostTokenEndpointAuthentication() {
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId("client-id")
                .clientSecret("client-secret-value")
                .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.CLIENT_SECRET_POST)
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype();

        assertThat(tenant.tokenEndpointAuthenticationMethod()
                           .orElseThrow(),
                   is(OidcClientAuthenticationMethod.CLIENT_SECRET_POST));
    }

    @Test
    void authorizationCodeFlowCanUseClientAssertionTokenEndpointAuthentication() {
        OidcTenantConfig clientSecretJwt = OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId("client-id")
                .clientSecret("client-secret-value")
                .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.CLIENT_SECRET_JWT)
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype();

        OidcTenantConfig privateKeyJwt = OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId("client-id")
                .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.PRIVATE_KEY_JWT)
                .clientAssertion(it -> it.jwk(Resource.create("oidc-next-sign-jwk.json"))
                        .keyId("sign-rsa")
                        .algorithm("RS256"))
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype();

        assertThat(clientSecretJwt.tokenEndpointAuthenticationMethod().orElseThrow(),
                   is(OidcClientAuthenticationMethod.CLIENT_SECRET_JWT));
        assertThat(privateKeyJwt.tokenEndpointAuthenticationMethod().orElseThrow(),
                   is(OidcClientAuthenticationMethod.PRIVATE_KEY_JWT));
    }

    @Test
    void authorizationCodeFlowCanUseMutualTlsTokenEndpointAuthentication() {
        OidcTenantConfig tlsClientAuth = OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId("client-id")
                .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.TLS_CLIENT_AUTH)
                .webClient(mutualTlsWebClient())
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype();
        OidcTenantConfig selfSignedTlsClientAuth = OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId("client-id")
                .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH)
                .webClient(mutualTlsWebClient())
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype();

        assertThat(tlsClientAuth.tokenEndpointAuthenticationMethod().orElseThrow(),
                   is(OidcClientAuthenticationMethod.TLS_CLIENT_AUTH));
        assertThat(selfSignedTlsClientAuth.tokenEndpointAuthenticationMethod().orElseThrow(),
                   is(OidcClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH));
    }

    @Test
    void mutualTlsClientAuthenticationAcceptsDocumentedWebClientTlsShapes() {
        OidcTenantConfig sslContextTenant = OidcTenantConfig.builder()
                .clientId("client-id")
                .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.TLS_CLIENT_AUTH)
                .webClient(sslContextMutualTlsWebClient())
                .endpoints(it -> it.tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .buildPrototype();
        OidcTenantConfig customManagerTenant = OidcTenantConfig.builder()
                .clientId("client-id")
                .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH)
                .webClient(customManagerMutualTlsWebClient())
                .endpoints(it -> it.tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .buildPrototype();

        OidcProviderConfig.builder()
                .putTenant("ssl-context", sslContextTenant)
                .putTenant("custom-manager", customManagerTenant)
                .outboundTargets(List.of(clientCredentialsTarget()))
                .buildPrototype();

        assertThat(sslContextTenant.tokenEndpointAuthenticationMethod().orElseThrow(),
                   is(OidcClientAuthenticationMethod.TLS_CLIENT_AUTH));
        assertThat(customManagerTenant.tokenEndpointAuthenticationMethod().orElseThrow(),
                   is(OidcClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH));
    }

    @Test
    void authorizationCodeFlowRequiresMutualTlsWebClientTls() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId("client-id")
                .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.TLS_CLIENT_AUTH)
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("webclient.tls"));

        thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId("client-id")
                .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH)
                .webClient(disabledTlsWebClient())
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("webclient.tls must be enabled"));

        thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId("client-id")
                .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.TLS_CLIENT_AUTH)
                .webClient(mutualTlsWebClient())
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(URI.create("http://issuer.example/token"))
                        .tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("token-endpoint-uri must use https"));

        Config missingMutualTlsWebClientConfig = Config.builder()
                .sources(ConfigSources.create(Map.ofEntries(
                        Map.entry("tenants.default.client-id", "client-id"),
                        Map.entry("tenants.default.token-endpoint-auth-method", "SELF_SIGNED_TLS_CLIENT_AUTH"),
                        Map.entry("tenants.default.endpoints.token-endpoint-uri", TOKEN_ENDPOINT_URI.toString()),
                        Map.entry("outbound.0.name", "api"),
                        Map.entry("outbound.0.client-credentials-grant-enabled", "true"))))
                .build();

        thrown = assertThrows(IllegalArgumentException.class,
                              () -> OidcProviderConfig.create(missingMutualTlsWebClientConfig));

        assertThat(thrown.getMessage(), containsString("webclient.tls"));

        thrown = assertThrows(IllegalArgumentException.class, () -> OidcProviderConfig.builder()
                .putTenant("default",
                           OidcTenantConfig.builder()
                                   .clientId("client-id")
                                   .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.TLS_CLIENT_AUTH)
                                   .webClient(mutualTlsWebClient())
                                   .endpoints(it -> it.tokenEndpointUri(URI.create("http://issuer.example/token"))
                                           .tlsRequired(false))
                                   .buildPrototype())
                .outboundTargets(List.of(clientCredentialsTarget()))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("token-endpoint-uri must use https"));
    }

    @Test
    void authorizationCodeFlowRequiresClientSecretForSecretTokenEndpointAuthentication() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId("client-id")
                .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("client-secret"));
    }

    @Test
    void authorizationCodeFlowRequiresClientAssertionPrerequisites() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId("client-id")
                .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.CLIENT_SECRET_JWT)
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("client-secret"));

        thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId("client-id")
                .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.PRIVATE_KEY_JWT)
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("client-assertion.jwk"));

        thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .clientAssertion(it -> it.lifetime(Duration.ZERO))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("client-assertion.lifetime"));

        thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId("client-id")
                .clientSecret("client-secret-value")
                .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.CLIENT_SECRET_JWT)
                .clientAssertion(it -> it.algorithm("none"))
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("client-assertion.algorithm"));

        thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId("client-id")
                .clientSecret("client-secret-value")
                .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.CLIENT_SECRET_JWT)
                .clientAssertion(it -> it.algorithm("RS256"))
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("client-assertion.algorithm"));

        thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId("client-id")
                .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.PRIVATE_KEY_JWT)
                .clientAssertion(it -> it.jwk(Resource.create("oidc-next-sign-jwk.json"))
                        .keyId("sign-rsa")
                        .algorithm("HS256"))
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("client-assertion.algorithm"));
    }

    @Test
    void authorizationCodeFlowCanUseWellKnownUriDerivedFromIssuer() {
        OidcTenantConfig tenant = OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId("client-id")
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype();

        assertThat(tenant.endpoints().wellKnownUri().isEmpty(), is(true));
    }

    @Test
    void protectedResourceRequiresUsableTokenTransport() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .endpoints(it -> it.jwksUri(JWKS_URI))
                .tokenTransport(it -> it.authorizationHeaderEnabled(false))
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.JWT)
                                .audience(AUDIENCE)))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("Bearer Token transport"));
    }

    @Test
    void endpointPolicyRejectsUnsupportedAcceptedCredentials() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId("client-id")
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .endpointPolicy(it -> it.acceptedCredentials(List.of(OidcEndpointCredential.BEARER_TOKEN)))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("bearer-token"));

        thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .endpoints(it -> it.jwksUri(JWKS_URI))
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.JWT)
                        .audience(AUDIENCE)))
                .endpointPolicy(it -> it.acceptedCredentials(List.of(OidcEndpointCredential.AUTHENTICATION_COOKIE)))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("authentication-cookie"));
    }

    @Test
    void endpointPolicyRejectsUnsupportedFailureResponse() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .endpoints(it -> it.jwksUri(JWKS_URI))
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.JWT)
                        .audience(AUDIENCE)))
                .endpointPolicy(it -> it.authenticationFailureResponse(
                        OidcAuthenticationFailureResponse.AUTHORIZATION_CODE_REDIRECT))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("authorization-code"));

        thrown = assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId("client-id")
                .endpoints(it -> it.authorizationEndpointUri(AUTHORIZATION_ENDPOINT_URI)
                        .tokenEndpointUri(TOKEN_ENDPOINT_URI)
                        .jwksUri(JWKS_URI))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.JWT)
                        .audience(AUDIENCE)))
                .endpointPolicy(it -> it.acceptedCredentials(List.of(OidcEndpointCredential.BEARER_TOKEN))
                        .authenticationFailureResponse(OidcAuthenticationFailureResponse.AUTHORIZATION_CODE_REDIRECT))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("authentication-cookie"));
    }

    @Test
    void endpointPolicyRejectsDuplicateAndExplicitEmptyAcceptedCredentials() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                                                       () -> OidcEndpointPolicyConfig.builder()
                                                               .acceptedCredentials(List.of(
                                                                       OidcEndpointCredential.BEARER_TOKEN,
                                                                       OidcEndpointCredential.BEARER_TOKEN))
                                                               .buildPrototype());

        assertThat(thrown.getMessage(), containsString("duplicate credential"));

        Config config = Config.just(ConfigSources.create(ObjectNode.builder()
                                                          .addList("accepted-credentials", ListNode.builder().build())
                                                          .build()));
        thrown = assertThrows(IllegalArgumentException.class,
                              () -> OidcEndpointPolicyConfig.create(config));

        assertThat(thrown.getMessage(), containsString("accepted-credentials"));
    }

    @Test
    void tokenTransportConfigDrivesBearerEvidence() {
        OidcProvider provider = OidcProvider.create(OidcProviderConfig.builder()
                                                  .tenants(Map.of("default", jwtProtectedResourceTenant(it -> it
                                                          .authorizationHeaderEnabled(false)
                                                          .queryParameterEnabled(true))))
                                                  .buildPrototype());

        var headerResponse = provider.authenticate(OidcProviderTest.request(null,
                                                                            SecurityEnvironment.builder()
                                                                                    .header("Authorization",
                                                                                            "Bearer access-token")
                                                                                    .build()));
        var queryResponse = provider.authenticate(OidcProviderTest.request(null,
                                                                           SecurityEnvironment.builder()
                                                                                   .targetUri(URI.create(
                                                                                           "https://rp.example/resource"))
                                                                                   .queryParam("access_token",
                                                                                               "access-token")
                                                                                   .build()));

        assertThat(headerResponse.description().orElse(""), is("Bearer Token is required"));
        assertThat(queryResponse.description().orElse(""), is("Bearer Token is not a valid signed JWT"));
    }

    @Test
    void defaultTenantMustReferenceConfiguredTenant() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                                                       () -> OidcProviderConfig.builder()
                                                               .defaultTenant("missing")
                                                               .putTenant("default", jwtProtectedResourceTenant())
                                                               .buildPrototype());

        assertThat(thrown.getMessage(), containsString("default-tenant"));
    }

    @Test
    void outboundTargetOperationsCannotBeAmbiguous() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                                                       () -> OidcOutboundTargetConfig.builder()
                                                               .tokenPropagationEnabled(true)
                                                               .clientCredentialsGrantEnabled(true)
                                                               .buildPrototype());

        assertThat(thrown.getMessage(), containsString("Token Propagation and Client Credentials Grant"));
    }

    @Test
    void clientCredentialsGrantRequiresClientAuthenticationAndTokenEndpoint() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> OidcProviderConfig.builder()
                .putTenant("default", OidcTenantConfig.create())
                .outboundTargets(List.of(clientCredentialsTarget()))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("client-id"));

        thrown = assertThrows(IllegalArgumentException.class, () -> OidcProviderConfig.builder()
                .putTenant("default", OidcTenantConfig.builder()
                        .clientId("client-id")
                        .buildPrototype())
                .outboundTargets(List.of(clientCredentialsTarget()))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("Token Endpoint authentication"));

        thrown = assertThrows(IllegalArgumentException.class, () -> OidcProviderConfig.builder()
                .putTenant("default", OidcTenantConfig.builder()
                        .clientId("client-id")
                        .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                        .buildPrototype())
                .outboundTargets(List.of(clientCredentialsTarget()))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("client-secret"));

        thrown = assertThrows(IllegalArgumentException.class, () -> OidcProviderConfig.builder()
                .putTenant("default", OidcTenantConfig.builder()
                        .clientId("client-id")
                        .clientSecret("client-secret-value")
                        .buildPrototype())
                .outboundTargets(List.of(clientCredentialsTarget()))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("token-endpoint-uri"));

        thrown = assertThrows(IllegalArgumentException.class, () -> OidcProviderConfig.builder()
                .putTenant("default", OidcTenantConfig.builder()
                        .clientId("client-id")
                        .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.TLS_CLIENT_AUTH)
                        .endpoints(it -> it.tokenEndpointUri(TOKEN_ENDPOINT_URI))
                        .buildPrototype())
                .outboundTargets(List.of(clientCredentialsTarget()))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("webclient.tls"));

        thrown = assertThrows(IllegalArgumentException.class, () -> OidcProviderConfig.builder()
                .putTenant("default", OidcTenantConfig.builder()
                        .clientId("client-id")
                        .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.TLS_CLIENT_AUTH)
                        .webClient(mutualTlsWebClient())
                        .endpoints(it -> it.tokenEndpointUri(URI.create("http://issuer.example/token"))
                                .tlsRequired(false))
                        .buildPrototype())
                .outboundTargets(List.of(clientCredentialsTarget()))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("token-endpoint-uri must use https"));

        thrown = assertThrows(IllegalArgumentException.class, () -> OidcProviderConfig.builder()
                .putTenant("default", OidcTenantConfig.builder()
                        .issuer("http://issuer.example")
                        .clientId("client-id")
                        .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.TLS_CLIENT_AUTH)
                        .webClient(mutualTlsWebClient())
                        .endpoints(it -> it.tlsRequired(false))
                        .buildPrototype())
                .outboundTargets(List.of(clientCredentialsTarget()))
                .buildPrototype());

        assertThat(thrown.getMessage(), containsString("well-known-uri must use https"));

        OidcTenantConfig mutualTlsClientCredentials = OidcTenantConfig.builder()
                .clientId("client-id")
                .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.TLS_CLIENT_AUTH)
                .webClient(mutualTlsWebClient())
                .endpoints(it -> it.tokenEndpointUri(TOKEN_ENDPOINT_URI))
                .buildPrototype();

        OidcProviderConfig.builder()
                .putTenant("default", mutualTlsClientCredentials)
                .outboundTargets(List.of(clientCredentialsTarget()))
                .buildPrototype();

        assertThat(mutualTlsClientCredentials.tokenEndpointAuthenticationMethod().orElseThrow(),
                   is(OidcClientAuthenticationMethod.TLS_CLIENT_AUTH));
    }

    @Test
    void targetClientCredentialsGrantRequiresClientAuthenticationAndTlsTokenEndpoint() {
        Config noneAuthenticationConfig = Config.builder()
                .sources(ConfigSources.create(Map.ofEntries(
                        Map.entry("tenants.default.client-id", "client-id"),
                        Map.entry("tenants.default.token-endpoint-auth-method", "NONE"),
                        Map.entry("tenants.default.endpoints.token-endpoint-uri", TOKEN_ENDPOINT_URI.toString()),
                        Map.entry("outbound.0.name", "api"),
                        Map.entry("outbound.0.client-credentials-grant-enabled", "true"))))
                .build();

        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                                                       () -> OidcProviderConfig.create(noneAuthenticationConfig));

        assertThat(thrown.getMessage(), containsString("Token Endpoint authentication cannot be NONE"));

        Config insecureTokenEndpointConfig = Config.builder()
                .sources(ConfigSources.create(Map.ofEntries(
                        Map.entry("tenants.default.client-id", "client-id"),
                        Map.entry("tenants.default.client-secret", "client-secret-value"),
                        Map.entry("tenants.default.endpoints.token-endpoint-uri", "http://issuer.example/token"),
                        Map.entry("outbound.0.name", "api"),
                        Map.entry("outbound.0.client-credentials-grant-enabled", "true"))))
                .build();

        thrown = assertThrows(IllegalArgumentException.class,
                              () -> OidcProviderConfig.create(insecureTokenEndpointConfig));

        assertThat(thrown.getMessage(), containsString("token-endpoint-uri must use https"));
    }

    @Test
    void protectedResourceDefaultsRequireBearerEvidence() {
        OidcProvider provider = OidcProvider.create(OidcProviderConfig.builder()
                                                  .tenants(Map.of("default", jwtProtectedResourceTenant()))
                                                  .buildPrototype());

        var response = provider.authenticate(OidcProviderTest.request(null, SecurityEnvironment.create()));

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.FAILURE));
        assertThat(response.statusCode().orElse(-1), is(401));
    }

    @Test
    void optionalProviderBehaviorAbstainsWhenCredentialIsMissing() {
        OidcProvider provider = OidcProvider.create(OidcProviderConfig.builder()
                                                  .optional(true)
                                                  .tenants(Map.of("default", jwtProtectedResourceTenant()))
                                                  .buildPrototype());

        var response = provider.authenticate(OidcProviderTest.request(null, SecurityEnvironment.create()));

        assertThat(response.status(), is(SecurityResponse.SecurityStatus.ABSTAIN));
        assertThat(response.description().orElse(""), is("Bearer Token is required"));
    }

    @Test
    void generatedConfigMetadataContainsProviderModel() throws IOException {
        String metadata = configMetadata();

        assertThat(metadata, containsString("oidc-next"));
        assertThat(metadata, containsString("redirection-endpoint-uri"));
        assertThat(metadata, containsString("query-parameter-enabled"));
        assertThat(metadata, containsString("secure-transport-required"));
        assertThat(metadata, containsString("token-validation"));
        assertThat(metadata, containsString("client-credentials-grant-enabled"));
        assertThat(metadata, containsString("pkce-required"));
        assertThat(metadata, containsString("audience-validation-enabled"));
        assertThat(metadata, containsString("tls-required"));
        assertThat(metadata, containsString("token-endpoint-auth-method"));
        assertThat(metadata, containsString("id-token-decryption-jwk"));
        assertThat(metadata, containsString("TLS_CLIENT_AUTH"));
        assertThat(metadata, containsString("SELF_SIGNED_TLS_CLIENT_AUTH"));
        assertThat(metadata, containsString("private key plus certificate chain"));
        assertThat(metadata, containsString("HTTPS well-known metadata"));
        assertThat(metadata, containsString("client-assertion"));
        assertThat(metadata, containsString("algorithm"));
        assertThat(metadata, containsString("key-id"));
        assertThat(metadata, containsString("jwk"));
        assertThat(metadata, containsString("resource-path"));
        assertThat(metadata, containsString("lifetime"));
        assertThat(metadata, containsString("path-template"));
        assertThat(metadata, containsString("webclient"));
        assertThat(metadata, containsString("subject-mapping"));
        assertThat(metadata, containsString("logout"));
        assertThat(metadata, containsString("local-endpoint-uri"));
        assertThat(metadata, containsString("end-session"));
        assertThat(metadata, containsString("id-token-hint-required"));
        assertThat(metadata, containsString("post-logout-redirect-uri"));
        assertThat(metadata, containsString("allowed-post-logout-redirect-uris"));
        assertThat(metadata, containsString("user-info"));
        assertThat(metadata, containsString("endpoint-policy"));
        assertThat(metadata, containsString("accepted-credentials"));
        assertThat(metadata, containsString("authentication-failure-response"));
        assertThat(metadata, containsString("principal-id-claim-paths"));
        assertThat(metadata, containsString("role-claim-paths"));
        assertThat(metadata, containsString("scope-grants-enabled"));
    }

    private static OidcTenantConfig jwtProtectedResourceTenant() {
        return jwtProtectedResourceTenant(it -> { });
    }

    private static OidcTenantConfig jwtProtectedResourceTenant(
            Consumer<OidcTokenTransportConfig.Builder> tokenTransport) {
        return OidcTenantConfig.builder()
                .issuer(ISSUER.toString())
                .clientId("client-id")
                .clientSecret("client-secret-value")
                .endpoints(it -> it.jwksUri(JWKS_URI))
                .tokenTransport(tokenTransport)
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.JWT)
                                .audience(AUDIENCE)))
                .buildPrototype();
    }

    private static WebClientConfig mutualTlsWebClient() {
        Keys privateKeyConfig = clientKeys();
        return WebClientConfig.builder()
                .tls(tls -> tls
                        .privateKey(privateKeyConfig)
                        .privateKeyCertChain(privateKeyConfig))
                .buildPrototype();
    }

    private static WebClientConfig sslContextMutualTlsWebClient() {
        SSLContext sslContext = defaultSslContext();
        return WebClientConfig.builder()
                .tls(tls -> tls.sslContext(sslContext))
                .buildPrototype();
    }

    private static WebClientConfig customManagerMutualTlsWebClient() {
        return WebClientConfig.builder()
                .tls(tls -> tls.manager(new TestTlsManager()))
                .buildPrototype();
    }

    private static WebClientConfig disabledTlsWebClient() {
        return WebClientConfig.builder()
                .tls(tls -> tls.enabled(false))
                .buildPrototype();
    }

    private static Keys clientKeys() {
        return Keys.builder()
                .keystore(store -> store
                        .passphrase("password")
                        .keystore(Resource.create("client.p12")))
                .build();
    }

    private static OutboundTarget clientCredentialsTarget() {
        return OutboundTarget.builder("api")
                .customObject(OidcOutboundTargetConfig.class,
                              OidcOutboundTargetConfig.builder()
                                      .clientCredentialsGrantEnabled(true)
                                      .buildPrototype())
                .build();
    }

    private static SSLContext defaultSslContext() {
        try {
            return SSLContext.getDefault();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static final class TestTlsManager implements TlsManager {
        private SSLContext sslContext;

        @Override
        public String name() {
            return "test";
        }

        @Override
        public String type() {
            return "test";
        }

        @Override
        public void init(TlsConfig tls) {
            sslContext = defaultSslContext();
        }

        @Override
        public void reload(Tls tls) {
        }

        @Override
        public SSLContext sslContext() {
            return sslContext;
        }

        @Override
        public Optional<X509KeyManager> keyManager() {
            return Optional.empty();
        }

        @Override
        public Optional<X509TrustManager> trustManager() {
            return Optional.empty();
        }
    }

    private static String configMetadata() throws IOException {
        String resource = "META-INF/helidon/config-metadata.json";
        Enumeration<java.net.URL> resources = OidcProviderConfigTest.class.getClassLoader().getResources(resource);
        StringBuilder metadata = new StringBuilder();
        while (resources.hasMoreElements()) {
            try (var stream = resources.nextElement().openStream()) {
                metadata.append(new String(stream.readAllBytes(), StandardCharsets.UTF_8));
            }
        }
        return metadata.toString();
    }
}
