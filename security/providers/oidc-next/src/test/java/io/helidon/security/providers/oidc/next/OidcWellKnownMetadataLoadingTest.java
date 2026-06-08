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
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import io.helidon.common.configurable.Resource;
import io.helidon.common.pki.Keys;
import io.helidon.http.HeaderName;
import io.helidon.http.HeaderNames;
import io.helidon.http.HeaderValues;
import io.helidon.http.Status;
import io.helidon.json.JsonObject;
import io.helidon.security.SecurityEnvironment;
import io.helidon.security.providers.common.OutboundTarget;
import io.helidon.webclient.api.WebClientConfig;
import io.helidon.webserver.http.HttpRouting;
import io.helidon.webserver.testing.junit5.ServerTest;
import io.helidon.webserver.testing.junit5.SetUpRoute;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ServerTest
class OidcWellKnownMetadataLoadingTest {
    private static final URI REDIRECTION_ENDPOINT_URI = URI.create("https://rp.example/oidc/callback");
    private static final String TENANT_WEBCLIENT_HEADER = "X-Tenant-WebClient";
    private static final String TENANT_WEBCLIENT_HEADER_VALUE = "configured";
    private static final HeaderName TENANT_WEBCLIENT_HEADER_NAME = HeaderNames.create(TENANT_WEBCLIENT_HEADER);
    private static final AtomicReference<String> PROVIDER_METADATA = new AtomicReference<>();
    private static final AtomicReference<String> WELL_KNOWN_WEBCLIENT_HEADER = new AtomicReference<>();
    private static final AtomicInteger REDIRECTED_WELL_KNOWN_REQUESTS = new AtomicInteger();

    private static volatile String redirectLocation;
    private static volatile String wellKnownContentType;
    private static volatile Status wellKnownStatus;

    private URI issuer;
    private URI authorizationEndpointUri;
    private URI tokenEndpointUri;
    private URI jwksUri;
    private URI introspectionEndpointUri;
    private URI userInfoEndpointUri;
    private URI endSessionEndpointUri;

    @SetUpRoute
    static void routing(HttpRouting.Builder routing) {
        routing.get("/.well-known/openid-configuration", (request, response) -> {
            WELL_KNOWN_WEBCLIENT_HEADER.set(request.headers().first(TENANT_WEBCLIENT_HEADER_NAME).orElse(""));
            if (redirectLocation != null) {
                response.status(Status.TEMPORARY_REDIRECT_307)
                        .header(HeaderNames.LOCATION, redirectLocation)
                        .send();
                return;
            }
            if (wellKnownContentType != null) {
                response.header(HeaderNames.CONTENT_TYPE, wellKnownContentType);
            }
            if (wellKnownStatus != null) {
                response.status(wellKnownStatus);
            }
            response.send(PROVIDER_METADATA.get());
        });
        routing.get("/redirected-openid-configuration", (request, response) -> {
            REDIRECTED_WELL_KNOWN_REQUESTS.incrementAndGet();
            response.header(HeaderValues.CONTENT_TYPE_JSON)
                    .send(PROVIDER_METADATA.get());
        });
    }

    @BeforeEach
    void setUp(URI serverUri) {
        issuer = URI.create(serverUri.toString().substring(0, serverUri.toString().length() - 1));
        authorizationEndpointUri = serverUri.resolve("authorize");
        tokenEndpointUri = serverUri.resolve("token");
        jwksUri = serverUri.resolve("jwks");
        introspectionEndpointUri = serverUri.resolve("introspect");
        userInfoEndpointUri = serverUri.resolve("userinfo");
        endSessionEndpointUri = serverUri.resolve("logout");
        PROVIDER_METADATA.set(providerMetadataBuilder()
                                      .build()
                                      .toString());
        WELL_KNOWN_WEBCLIENT_HEADER.set("");
        REDIRECTED_WELL_KNOWN_REQUESTS.set(0);
        redirectLocation = null;
        wellKnownContentType = "application/json";
        wellKnownStatus = null;
    }

    @Test
    void authorizationCodeTenantLoadsWellKnownMetadataEndpoints() {
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .webClient(tenantWebClient())
                .endpoints(it -> it.tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.ready(), is(true));
        assertThat(context.metadata().issuer(), is(Optional.of(issuer.toString())));
        assertThat(context.metadata().wellKnownUri(), is(Optional.of(issuer.resolve("/.well-known/openid-configuration"))));
        assertThat(context.metadata().authorizationEndpointUri(), is(Optional.of(authorizationEndpointUri)));
        assertThat(context.metadata().tokenEndpointUri(), is(Optional.of(tokenEndpointUri)));
        assertThat(context.jwkSetManager().jwkSetUri(), is(Optional.of(jwksUri)));
        assertThat(context.metadata().introspectionEndpointUri(), is(Optional.of(introspectionEndpointUri)));
        assertThat(context.metadata().userInfoEndpointUri(), is(Optional.of(userInfoEndpointUri)));
        assertThat(context.metadata().endSessionEndpointUri(), is(Optional.of(endSessionEndpointUri)));
        assertThat(WELL_KNOWN_WEBCLIENT_HEADER.get(), is(TENANT_WEBCLIENT_HEADER_VALUE));
    }

    @Test
    void authorizationCodeTenantLoadsWellKnownMetadataIssuerWhenEndpointsAreStatic() {
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .clientId("client-id")
                .webClient(tenantWebClient())
                .endpoints(it -> it.wellKnownUri(issuer.resolve("/.well-known/openid-configuration"))
                        .authorizationEndpointUri(authorizationEndpointUri)
                        .tokenEndpointUri(tokenEndpointUri)
                        .tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.ready(), is(true));
        assertThat(context.metadata().issuer(), is(Optional.of(issuer.toString())));
        assertThat(WELL_KNOWN_WEBCLIENT_HEADER.get(), is(TENANT_WEBCLIENT_HEADER_VALUE));
    }

    @Test
    void authorizationCodeTenantFailsWhenWellKnownMetadataResponseTypesAreMissing() {
        PROVIDER_METADATA.set(JsonObject.builder()
                .set("issuer", issuer.toString())
                .set("authorization_endpoint", authorizationEndpointUri.toString())
                .set("token_endpoint", tokenEndpointUri.toString())
                .set("jwks_uri", jwksUri.toString())
                .setStrings("grant_types_supported", List.of("authorization_code"))
                .setStrings("code_challenge_methods_supported", List.of("S256"))
                .setStrings("token_endpoint_auth_methods_supported", List.of("none"))
                .setStrings("id_token_signing_alg_values_supported", List.of("RS256"))
                .build()
                .toString());
        OidcTenantContext context = tenantContext(authorizationCodeTenantConfig());

        assertThat(context.state(), is(OidcTenantState.FAILED));
        assertThat(context.failureCause().orElseThrow().getMessage(), containsString("response_types_supported"));
    }

    @Test
    void authorizationCodeTenantFailsWhenWellKnownMetadataDoesNotSupportCodeResponseType() {
        PROVIDER_METADATA.set(authorizationCodeMetadataBuilder()
                                      .setStrings("response_types_supported", List.of("id_token"))
                                      .build()
                                      .toString());
        OidcTenantContext context = tenantContext(authorizationCodeTenantConfig());

        assertThat(context.state(), is(OidcTenantState.FAILED));
        assertThat(context.failureCause().orElseThrow().getMessage(), containsString("response_types_supported"));
    }

    @Test
    void authorizationCodeTenantFailsWhenWellKnownMetadataDoesNotSupportAuthorizationCodeGrant() {
        PROVIDER_METADATA.set(authorizationCodeMetadataBuilder()
                                      .setStrings("grant_types_supported", List.of("implicit"))
                                      .build()
                                      .toString());
        OidcTenantContext context = tenantContext(authorizationCodeTenantConfig());

        assertThat(context.state(), is(OidcTenantState.FAILED));
        assertThat(context.failureCause().orElseThrow().getMessage(), containsString("grant_types_supported"));
    }

    @Test
    void authorizationCodeTenantAcceptsMissingWellKnownMetadataGrantTypesDefault() {
        PROVIDER_METADATA.set(JsonObject.builder()
                .set("issuer", issuer.toString())
                .set("authorization_endpoint", authorizationEndpointUri.toString())
                .set("token_endpoint", tokenEndpointUri.toString())
                .set("jwks_uri", jwksUri.toString())
                .setStrings("response_types_supported", List.of("code"))
                .setStrings("code_challenge_methods_supported", List.of("S256"))
                .setStrings("token_endpoint_auth_methods_supported", List.of("none"))
                .setStrings("id_token_signing_alg_values_supported", List.of("RS256"))
                .build()
                .toString());
        OidcTenantContext context = tenantContext(authorizationCodeTenantConfig());

        assertThat(context.ready(), is(true));
    }

    @Test
    void authorizationCodeTenantFailsWhenWellKnownMetadataPkceMethodsAreMissing() {
        PROVIDER_METADATA.set(JsonObject.builder()
                .set("issuer", issuer.toString())
                .set("authorization_endpoint", authorizationEndpointUri.toString())
                .set("token_endpoint", tokenEndpointUri.toString())
                .set("jwks_uri", jwksUri.toString())
                .setStrings("response_types_supported", List.of("code"))
                .setStrings("grant_types_supported", List.of("authorization_code"))
                .setStrings("token_endpoint_auth_methods_supported", List.of("none"))
                .setStrings("id_token_signing_alg_values_supported", List.of("RS256"))
                .build()
                .toString());
        OidcTenantContext context = tenantContext(authorizationCodeTenantConfig());

        assertThat(context.state(), is(OidcTenantState.FAILED));
        assertThat(context.failureCause().orElseThrow().getMessage(), containsString("code_challenge_methods_supported"));
    }

    @Test
    void authorizationCodeTenantFailsWhenWellKnownMetadataDoesNotSupportConfiguredPkceMethod() {
        PROVIDER_METADATA.set(authorizationCodeMetadataBuilder()
                                      .setStrings("code_challenge_methods_supported", List.of("plain"))
                                      .build()
                                      .toString());
        OidcTenantContext context = tenantContext(authorizationCodeTenantConfig());

        assertThat(context.state(), is(OidcTenantState.FAILED));
        assertThat(context.failureCause().orElseThrow().getMessage(), containsString("code_challenge_methods_supported"));
    }

    @Test
    void authorizationCodeTenantSkipsPkceMetadataWhenPkceIsDisabled() {
        PROVIDER_METADATA.set(JsonObject.builder()
                .set("issuer", issuer.toString())
                .set("authorization_endpoint", authorizationEndpointUri.toString())
                .set("token_endpoint", tokenEndpointUri.toString())
                .set("jwks_uri", jwksUri.toString())
                .setStrings("response_types_supported", List.of("code"))
                .setStrings("grant_types_supported", List.of("authorization_code"))
                .setStrings("token_endpoint_auth_methods_supported", List.of("client_secret_basic"))
                .setStrings("id_token_signing_alg_values_supported", List.of("RS256"))
                .build()
                .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .clientSecret("client-secret")
                .endpoints(it -> it.tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI)
                        .pkceRequired(false))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.ready(), is(true));
    }

    @Test
    void authorizationCodeTenantFailsWhenWellKnownMetadataDefaultsTokenEndpointAuthToBasic() {
        PROVIDER_METADATA.set(JsonObject.builder()
                .set("issuer", issuer.toString())
                .set("authorization_endpoint", authorizationEndpointUri.toString())
                .set("token_endpoint", tokenEndpointUri.toString())
                .set("jwks_uri", jwksUri.toString())
                .setStrings("response_types_supported", List.of("code"))
                .setStrings("grant_types_supported", List.of("authorization_code"))
                .setStrings("code_challenge_methods_supported", List.of("S256"))
                .setStrings("id_token_signing_alg_values_supported", List.of("RS256"))
                .build()
                .toString());
        OidcTenantContext context = tenantContext(authorizationCodeTenantConfig());

        assertThat(context.state(), is(OidcTenantState.FAILED));
        assertThat(context.failureCause().orElseThrow().getMessage(),
                   containsString("token_endpoint_auth_methods_supported"));
    }

    @Test
    void authorizationCodeTenantAcceptsMissingWellKnownMetadataTokenEndpointAuthForBasicDefault() {
        PROVIDER_METADATA.set(JsonObject.builder()
                .set("issuer", issuer.toString())
                .set("authorization_endpoint", authorizationEndpointUri.toString())
                .set("token_endpoint", tokenEndpointUri.toString())
                .set("jwks_uri", jwksUri.toString())
                .setStrings("response_types_supported", List.of("code"))
                .setStrings("grant_types_supported", List.of("authorization_code"))
                .setStrings("code_challenge_methods_supported", List.of("S256"))
                .setStrings("id_token_signing_alg_values_supported", List.of("RS256"))
                .build()
                .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .clientSecret("client-secret")
                .endpoints(it -> it.tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.ready(), is(true));
    }

    @Test
    void authorizationCodeTenantFailsWhenWellKnownMetadataDoesNotSupportTokenEndpointAuthMethod() {
        PROVIDER_METADATA.set(authorizationCodeMetadataBuilder()
                                      .setStrings("token_endpoint_auth_methods_supported", List.of("client_secret_basic"))
                                      .build()
                                      .toString());
        OidcTenantContext context = tenantContext(authorizationCodeTenantConfig());

        assertThat(context.state(), is(OidcTenantState.FAILED));
        assertThat(context.failureCause().orElseThrow().getMessage(),
                   containsString("token_endpoint_auth_methods_supported"));
    }

    @Test
    void authorizationCodeTenantFailsWhenWellKnownMetadataJwtAuthSigningAlgorithmsAreMissing() {
        PROVIDER_METADATA.set(authorizationCodeMetadataBuilder()
                                      .setStrings("token_endpoint_auth_methods_supported", List.of("client_secret_jwt"))
                                      .build()
                                      .toString());
        OidcTenantContext context = tenantContext(jwtClientAuthenticationTenantConfig());

        assertThat(context.state(), is(OidcTenantState.FAILED));
        assertThat(context.failureCause().orElseThrow().getMessage(),
                   containsString("token_endpoint_auth_signing_alg_values_supported"));
    }

    @Test
    void authorizationCodeTenantFailsWhenWellKnownMetadataJwtAuthSigningAlgorithmDoesNotMatchConfig() {
        PROVIDER_METADATA.set(authorizationCodeMetadataBuilder()
                                      .setStrings("token_endpoint_auth_methods_supported", List.of("client_secret_jwt"))
                                      .setStrings("token_endpoint_auth_signing_alg_values_supported", List.of("HS512"))
                                      .build()
                                      .toString());
        OidcTenantContext context = tenantContext(jwtClientAuthenticationTenantConfig());

        assertThat(context.state(), is(OidcTenantState.FAILED));
        assertThat(context.failureCause().orElseThrow().getMessage(),
                   containsString("token_endpoint_auth_signing_alg_values_supported"));
    }

    @Test
    void authorizationCodeTenantFailsWhenWellKnownMetadataJwtAuthSigningAlgorithmsContainNone() {
        PROVIDER_METADATA.set(authorizationCodeMetadataBuilder()
                                      .setStrings("token_endpoint_auth_methods_supported", List.of("client_secret_jwt"))
                                      .setStrings("token_endpoint_auth_signing_alg_values_supported",
                                                  List.of("HS256", "none"))
                                      .build()
                                      .toString());
        OidcTenantContext context = tenantContext(jwtClientAuthenticationTenantConfig());

        assertThat(context.state(), is(OidcTenantState.FAILED));
        assertThat(context.failureCause().orElseThrow().getMessage(),
                   containsString("token_endpoint_auth_signing_alg_values_supported"));
    }

    @Test
    void authorizationCodeTenantFailsWhenWellKnownMetadataIdTokenSigningAlgorithmsAreMissing() {
        PROVIDER_METADATA.set(authorizationCodeCapabilityMetadataBuilder()
                                      .build()
                                      .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .endpoints(it -> it.tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));
    }

    @Test
    void authorizationCodeTenantFailsWhenWellKnownMetadataIdTokenSigningAlgorithmsDoNotMatchConfig() {
        PROVIDER_METADATA.set(authorizationCodeCapabilityMetadataBuilder()
                .setStrings("id_token_signing_alg_values_supported", List.of("ES256"))
                .build()
                .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .endpoints(it -> it.tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));
    }

    @Test
    void authorizationCodeTenantFailsWhenWellKnownMetadataIdTokenEncryptionAlgorithmsDoNotMatchConfig() {
        PROVIDER_METADATA.set(authorizationCodeMetadataBuilder()
                .setStrings("id_token_encryption_alg_values_supported", List.of("dir"))
                .build()
                .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .endpoints(it -> it.tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));
    }

    @Test
    void authorizationCodeTenantFailsWhenWellKnownMetadataIdTokenContentEncryptionAlgorithmsDoNotMatchConfig() {
        PROVIDER_METADATA.set(authorizationCodeMetadataBuilder()
                .setStrings("id_token_encryption_enc_values_supported", List.of("A192GCM"))
                .build()
                .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .endpoints(it -> it.tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));
    }

    @Test
    void introspectionTenantFailsWhenWellKnownMetadataIntrospectionEndpointHasFragment() {
        PROVIDER_METADATA.set(JsonObject.builder()
                .set("issuer", issuer.toString())
                .set("introspection_endpoint", issuer.resolve("/introspect#fragment").toString())
                .build()
                .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .clientSecret("client-secret-value")
                .endpoints(it -> it.tlsRequired(false))
                .protectedResource(it -> it.tokenValidation(validation -> validation
                        .method(OidcTokenValidationMethod.INTROSPECTION)
                        .audience("api://default")))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));
    }

    @Test
    void tenantFailsWhenWellKnownMetadataContentTypeIsNotJson() {
        wellKnownContentType = "text/plain";
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .endpoints(it -> it.tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));
        Throwable failureCause = context.failureCause().orElseThrow();
        assertThat(failureCause.getMessage(), is("Failed to load well-known metadata"));
        assertThat(failureCause.getCause().getMessage(),
                   is("well-known metadata response must be application/json"));
    }

    @Test
    void tenantFailsWhenWellKnownMetadataStatusIsNotOk() {
        wellKnownStatus = Status.CREATED_201;
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .endpoints(it -> it.tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));
        Throwable failureCause = context.failureCause().orElseThrow();
        assertThat(failureCause.getMessage(), is("Failed to load well-known metadata"));
        assertThat(failureCause.getCause().getMessage(), is("well-known metadata is unavailable"));
    }

    @Test
    void authorizationCodeTenantFailsWhenWellKnownMetadataAuthorizationEndpointIsMissing() {
        PROVIDER_METADATA.set(JsonObject.builder()
                .set("issuer", issuer.toString())
                .set("token_endpoint", tokenEndpointUri.toString())
                .build()
                .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .endpoints(it -> it.tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));
    }

    @Test
    void authorizationCodeTenantFailsWhenWellKnownMetadataAuthorizationEndpointHasFragment() {
        PROVIDER_METADATA.set(JsonObject.builder()
                .set("issuer", issuer.toString())
                .set("authorization_endpoint", issuer.resolve("/authorize#fragment").toString())
                .set("token_endpoint", tokenEndpointUri.toString())
                .build()
                .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .endpoints(it -> it.tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));
    }

    @Test
    void authorizationCodeTenantFailsWhenWellKnownMetadataAuthorizationEndpointHasUnsupportedScheme() {
        PROVIDER_METADATA.set(JsonObject.builder()
                .set("issuer", issuer.toString())
                .set("authorization_endpoint", "ftp://issuer.example/authorize")
                .set("token_endpoint", tokenEndpointUri.toString())
                .build()
                .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .endpoints(it -> it.tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));
    }

    @Test
    void authorizationCodeTenantFailsWhenWellKnownMetadataTokenEndpointIsMissing() {
        PROVIDER_METADATA.set(JsonObject.builder()
                .set("issuer", issuer.toString())
                .set("authorization_endpoint", authorizationEndpointUri.toString())
                .build()
                .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .endpoints(it -> it.tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));
    }

    @Test
    void authorizationCodeTenantFailsWhenWellKnownMetadataTokenEndpointHasFragment() {
        PROVIDER_METADATA.set(JsonObject.builder()
                .set("issuer", issuer.toString())
                .set("authorization_endpoint", authorizationEndpointUri.toString())
                .set("token_endpoint", issuer.resolve("/token#fragment").toString())
                .build()
                .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .endpoints(it -> it.tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));
    }

    @Test
    void authorizationCodeTenantFailsWhenWellKnownMetadataTokenEndpointHasUnsupportedScheme() {
        PROVIDER_METADATA.set(JsonObject.builder()
                .set("issuer", issuer.toString())
                .set("authorization_endpoint", authorizationEndpointUri.toString())
                .set("token_endpoint", "ftp://issuer.example/token")
                .build()
                .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .endpoints(it -> it.tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));
    }

    @Test
    void tenantFailsWhenWellKnownMetadataIssuerHasQueryOrFragment() {
        PROVIDER_METADATA.set(JsonObject.builder()
                .set("issuer", issuer + "?tenant=default")
                .set("jwks_uri", jwksUri.toString())
                .build()
                .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .endpoints(it -> it.wellKnownUri(issuer.resolve("/.well-known/openid-configuration"))
                        .tlsRequired(false))
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.JWT)
                                .audience("api://default")))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));

        PROVIDER_METADATA.set(JsonObject.builder()
                .set("issuer", issuer + "#fragment")
                .set("jwks_uri", jwksUri.toString())
                .build()
                .toString());

        context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));
    }

    @Test
    void logoutTenantLoadsEndSessionEndpointFromWellKnownMetadata() {
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .webClient(tenantWebClient())
                .endpoints(it -> it.tlsRequired(false))
                .logout(logout -> logout.endSession(endSession -> endSession.idTokenHintRequired(false)))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.ready(), is(true));
        assertThat(context.metadata().endSessionEndpointUri(), is(Optional.of(endSessionEndpointUri)));
        assertThat(WELL_KNOWN_WEBCLIENT_HEADER.get(), is(TENANT_WEBCLIENT_HEADER_VALUE));
    }

    @Test
    void logoutTenantFailsWhenWellKnownMetadataEndSessionEndpointIsMissing() {
        PROVIDER_METADATA.set(JsonObject.builder()
                .set("issuer", issuer.toString())
                .build()
                .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .endpoints(it -> it.tlsRequired(false))
                .logout(logout -> logout.endSession(endSession -> endSession.idTokenHintRequired(false)))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));
    }

    @Test
    void logoutTenantFailsWhenWellKnownMetadataEndSessionEndpointHasFragment() {
        PROVIDER_METADATA.set(JsonObject.builder()
                .set("issuer", issuer.toString())
                .set("end_session_endpoint", issuer.resolve("/logout#fragment").toString())
                .build()
                .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .endpoints(it -> it.tlsRequired(false))
                .logout(logout -> logout.endSession(endSession -> endSession.idTokenHintRequired(false)))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));
    }

    @Test
    void userInfoTenantLoadsUserInfoEndpointFromWellKnownMetadata() {
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .webClient(tenantWebClient())
                .endpoints(it -> it.authorizationEndpointUri(authorizationEndpointUri)
                        .tokenEndpointUri(tokenEndpointUri)
                        .tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .userInfo(it -> { })
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.ready(), is(true));
        assertThat(context.metadata().userInfoEndpointUri(), is(Optional.of(userInfoEndpointUri)));
        assertThat(WELL_KNOWN_WEBCLIENT_HEADER.get(), is(TENANT_WEBCLIENT_HEADER_VALUE));
    }

    @Test
    void userInfoTenantFailsWhenWellKnownMetadataUserInfoEndpointIsMissing() {
        PROVIDER_METADATA.set(authorizationCodeMetadataBuilder()
                                      .build()
                                      .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .endpoints(it -> it.authorizationEndpointUri(authorizationEndpointUri)
                        .tokenEndpointUri(tokenEndpointUri)
                        .tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .userInfo(it -> { })
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));
    }

    @Test
    void userInfoTenantFailsWhenWellKnownMetadataUserInfoEndpointHasFragment() {
        PROVIDER_METADATA.set(authorizationCodeMetadataBuilder()
                .set("userinfo_endpoint", issuer.resolve("/userinfo#fragment").toString())
                .build()
                .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .endpoints(it -> it.authorizationEndpointUri(authorizationEndpointUri)
                        .tokenEndpointUri(tokenEndpointUri)
                        .tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .userInfo(it -> { })
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));
    }

    @Test
    void jwtProtectedResourceTenantLoadsJwkSetUriFromWellKnownMetadata() {
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .endpoints(it -> it.tlsRequired(false))
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.JWT)
                                .audience("api://default")))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.ready(), is(true));
        assertThat(context.metadata().issuer(), is(Optional.of(issuer.toString())));
        assertThat(context.jwkSetManager().jwkSetUri(), is(Optional.of(jwksUri)));
    }

    @Test
    void introspectionProtectedResourceTenantLoadsEndpointFromWellKnownMetadata() {
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .clientSecret("client-secret")
                .webClient(tenantWebClient())
                .endpoints(it -> it.tlsRequired(false))
                .protectedResource(it -> it.tokenValidation(validation -> validation
                        .method(OidcTokenValidationMethod.INTROSPECTION)
                        .audience("api://default")))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.ready(), is(true));
        assertThat(context.metadata().introspectionEndpointUri(), is(Optional.of(introspectionEndpointUri)));
        assertThat(WELL_KNOWN_WEBCLIENT_HEADER.get(), is(TENANT_WEBCLIENT_HEADER_VALUE));
    }

    @Test
    void introspectionTenantFailsWhenWellKnownMetadataDoesNotSupportConfiguredAuthenticationMethod() {
        PROVIDER_METADATA.set(JsonObject.builder()
                .set("issuer", issuer.toString())
                .set("introspection_endpoint", introspectionEndpointUri.toString())
                .setStrings("introspection_endpoint_auth_methods_supported", List.of("private_key_jwt"))
                .build()
                .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .clientSecret("client-secret")
                .endpoints(it -> it.tlsRequired(false))
                .protectedResource(it -> it.tokenValidation(validation -> validation
                        .method(OidcTokenValidationMethod.INTROSPECTION)
                        .audience("api://default")))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));
    }

    @Test
    void introspectionTenantFailsWhenWellKnownMetadataDoesNotSupportConfiguredSigningAlgorithm() {
        PROVIDER_METADATA.set(JsonObject.builder()
                .set("issuer", issuer.toString())
                .set("introspection_endpoint", introspectionEndpointUri.toString())
                .setStrings("introspection_endpoint_auth_methods_supported", List.of("client_secret_jwt"))
                .setStrings("introspection_endpoint_auth_signing_alg_values_supported", List.of("HS512"))
                .build()
                .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .clientSecret("client-secret")
                .endpoints(it -> it.tlsRequired(false))
                .protectedResource(it -> it.tokenValidation(validation -> validation
                        .method(OidcTokenValidationMethod.INTROSPECTION)
                        .audience("api://default")
                        .introspection(introspection -> introspection
                                .authenticationMethod(OidcClientAuthenticationMethod.CLIENT_SECRET_JWT))))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));
    }

    @Test
    void introspectionProtectedResourceTenantFailsWhenWellKnownMetadataEndpointIsMissing() {
        PROVIDER_METADATA.set(JsonObject.builder()
                .set("issuer", issuer.toString())
                .build()
                .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .clientSecret("client-secret")
                .endpoints(it -> it.tlsRequired(false))
                .protectedResource(it -> it.tokenValidation(validation -> validation
                        .method(OidcTokenValidationMethod.INTROSPECTION)
                        .audience("api://default")))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));
    }

    @Test
    void targetClientCredentialsGrantTenantLoadsTokenEndpointFromWellKnownMetadata() {
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .clientSecret("client-secret")
                .endpoints(it -> it.tlsRequired(false))
                .buildPrototype();
        OidcProviderConfig providerConfig = OidcProviderConfig.builder()
                .putTenant("tenant", tenantConfig)
                .outboundTargets(List.of(clientCredentialsTarget()))
                .buildPrototype();

        OidcTenantContext context = OidcTenantRuntimeRegistry.create(providerConfig)
                .tenantContext(OidcProviderTest.request(null, SecurityEnvironment.create()))
                .orElseThrow();

        assertThat(context.ready(), is(true));
        assertThat(context.metadata().tokenEndpointUri(), is(Optional.of(tokenEndpointUri)));
    }

    @Test
    void targetClientCredentialsGrantTenantFailsWhenWellKnownMetadataGrantTypesAreMissing() {
        PROVIDER_METADATA.set(JsonObject.builder()
                .set("issuer", issuer.toString())
                .set("token_endpoint", tokenEndpointUri.toString())
                .setStrings("token_endpoint_auth_methods_supported", List.of("client_secret_basic"))
                .build()
                .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .clientSecret("client-secret")
                .endpoints(it -> it.tlsRequired(false))
                .buildPrototype();
        OidcProviderConfig providerConfig = OidcProviderConfig.builder()
                .putTenant("tenant", tenantConfig)
                .outboundTargets(List.of(clientCredentialsTarget()))
                .buildPrototype();

        OidcTenantContext context = OidcTenantRuntimeRegistry.create(providerConfig)
                .tenantContext(OidcProviderTest.request(null, SecurityEnvironment.create()))
                .orElseThrow();

        assertThat(context.state(), is(OidcTenantState.FAILED));
        assertThat(context.failureCause().orElseThrow().getMessage(), containsString("grant_types_supported"));
    }

    @Test
    void targetClientCredentialsGrantTenantFailsWhenWellKnownMetadataTokenEndpointIsMissing() {
        PROVIDER_METADATA.set(JsonObject.builder()
                .set("issuer", issuer.toString())
                .build()
                .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .clientSecret("client-secret")
                .endpoints(it -> it.tlsRequired(false))
                .buildPrototype();
        OidcProviderConfig providerConfig = OidcProviderConfig.builder()
                .putTenant("tenant", tenantConfig)
                .outboundTargets(List.of(clientCredentialsTarget()))
                .buildPrototype();

        OidcTenantContext context = OidcTenantRuntimeRegistry.create(providerConfig)
                .tenantContext(OidcProviderTest.request(null, SecurityEnvironment.create()))
                .orElseThrow();

        assertThat(context.state(), is(OidcTenantState.FAILED));
    }

    @Test
    void mutualTlsTenantFailsWhenWellKnownMetadataTokenEndpointAliasHasFragment() {
        URI httpsIssuer = URI.create("https://issuer.example");
        OidcProviderMetadata wellKnownMetadata = OidcProviderMetadata.fromWellKnownMetadataJson(JsonObject.builder()
                .set("issuer", httpsIssuer.toString())
                .set("token_endpoint", httpsIssuer.resolve("/token").toString())
                .set("mtls_endpoint_aliases", JsonObject.builder()
                        .set("token_endpoint", "https://issuer.example/mtls-token#fragment")
                        .build())
                .build());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(httpsIssuer.toString())
                .clientId("client-id")
                .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.TLS_CLIENT_AUTH)
                .webClient(mutualTlsWebClient())
                .buildPrototype();
        OidcProviderMetadata metadata = OidcProviderMetadata.fromStaticConfig(tenantConfig)
                .mergeWellKnownMetadata(wellKnownMetadata);

        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                                                       () -> OidcTenantContextFactory.validateMutualTlsMetadata(
                                                               tenantConfig,
                                                               metadata));

        assertThat(thrown.getMessage(), containsString("token-endpoint-uri must not include a fragment"));
    }

    @Test
    void mutualTlsTenantFailsWhenWellKnownMetadataTokenEndpointAliasIsInsecure() {
        URI httpsIssuer = URI.create("https://issuer.example");
        OidcProviderMetadata wellKnownMetadata = OidcProviderMetadata.fromWellKnownMetadataJson(JsonObject.builder()
                .set("issuer", httpsIssuer.toString())
                .set("token_endpoint", httpsIssuer.resolve("/token").toString())
                .set("mtls_endpoint_aliases", JsonObject.builder()
                        .set("token_endpoint", "http://issuer.example/mtls-token")
                        .build())
                .build());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(httpsIssuer.toString())
                .clientId("client-id")
                .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH)
                .webClient(mutualTlsWebClient())
                .buildPrototype();
        OidcProviderMetadata metadata = OidcProviderMetadata.fromStaticConfig(tenantConfig)
                .mergeWellKnownMetadata(wellKnownMetadata);

        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                                                       () -> OidcTenantContextFactory.validateMutualTlsMetadata(
                                                               tenantConfig,
                                                               metadata));

        assertThat(thrown.getMessage(), containsString("token-endpoint-uri must use https"));
    }

    @Test
    void wellKnownMetadataRedirectIsNotFollowedWhenTenantWebClientFollowsRedirects() {
        redirectLocation = issuer.resolve("/redirected-openid-configuration").toString();
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .webClient(redirectFollowingTenantWebClient())
                .endpoints(it -> it.tlsRequired(false))
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.JWT)
                                .audience("api://default")))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));
        assertThat(REDIRECTED_WELL_KNOWN_REQUESTS.get(), is(0));
        assertThat(WELL_KNOWN_WEBCLIENT_HEADER.get(), is(TENANT_WEBCLIENT_HEADER_VALUE));
    }

    private static OutboundTarget clientCredentialsTarget() {
        return OutboundTarget.builder("api")
                .customObject(OidcOutboundTargetConfig.class,
                              OidcOutboundTargetConfig.builder()
                                      .clientCredentialsGrantEnabled(true)
                                      .buildPrototype())
                .build();
    }

    private static WebClientConfig tenantWebClient() {
        return WebClientConfig.builder()
                .addHeader(TENANT_WEBCLIENT_HEADER, TENANT_WEBCLIENT_HEADER_VALUE)
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

    private static Keys clientKeys() {
        return Keys.builder()
                .keystore(store -> store
                        .passphrase("password")
                        .keystore(Resource.create("client.p12")))
                .build();
    }

    private static WebClientConfig redirectFollowingTenantWebClient() {
        return WebClientConfig.builder()
                .addHeader(TENANT_WEBCLIENT_HEADER, TENANT_WEBCLIENT_HEADER_VALUE)
                .followRedirects(true)
                .buildPrototype();
    }

    private JsonObject.Builder providerMetadataBuilder() {
        return authorizationCodeMetadataBuilder()
                .set("introspection_endpoint", introspectionEndpointUri.toString())
                .set("userinfo_endpoint", userInfoEndpointUri.toString())
                .set("end_session_endpoint", endSessionEndpointUri.toString());
    }

    private JsonObject.Builder authorizationCodeMetadataBuilder() {
        return authorizationCodeCapabilityMetadataBuilder()
                .setStrings("id_token_signing_alg_values_supported", List.of("RS256"));
    }

    private JsonObject.Builder authorizationCodeCapabilityMetadataBuilder() {
        return JsonObject.builder()
                .set("issuer", issuer.toString())
                .set("authorization_endpoint", authorizationEndpointUri.toString())
                .set("token_endpoint", tokenEndpointUri.toString())
                .set("jwks_uri", jwksUri.toString())
                .setStrings("response_types_supported", List.of("code"))
                .setStrings("grant_types_supported", List.of("authorization_code", "client_credentials"))
                .setStrings("code_challenge_methods_supported", List.of("S256"))
                .setStrings("token_endpoint_auth_methods_supported", List.of("none", "client_secret_basic"));
    }

    @Test
    void jwtProtectedResourceTenantFailsWhenWellKnownMetadataJwkSetUriIsMissing() {
        PROVIDER_METADATA.set(JsonObject.builder()
                .set("issuer", issuer.toString())
                .build()
                .toString());
        OidcTenantConfig tenantConfig = OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .endpoints(it -> it.tlsRequired(false))
                .protectedResource(it -> it.tokenValidation(validation -> validation.method(OidcTokenValidationMethod.JWT)
                                .audience("api://default")))
                .buildPrototype();

        OidcTenantContext context = tenantContext(tenantConfig);

        assertThat(context.state(), is(OidcTenantState.FAILED));
    }

    private OidcTenantConfig authorizationCodeTenantConfig() {
        return OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .endpoints(it -> it.tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype();
    }

    private OidcTenantConfig jwtClientAuthenticationTenantConfig() {
        return OidcTenantConfig.builder()
                .issuer(issuer.toString())
                .clientId("client-id")
                .clientSecret("client-secret")
                .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.CLIENT_SECRET_JWT)
                .endpoints(it -> it.tlsRequired(false))
                .authorizationCode(it -> it.redirectionEndpointUri(REDIRECTION_ENDPOINT_URI))
                .cookies(it -> it.encryptionSecret("test-cookie-secret"))
                .buildPrototype();
    }

    private static OidcTenantContext tenantContext(OidcTenantConfig tenantConfig) {
        OidcTenantRuntimeRegistry registry = OidcTenantRuntimeRegistry.create(OidcProviderConfig.builder()
                .putTenant("tenant", tenantConfig)
                .buildPrototype());
        return registry.tenantContext(OidcProviderTest.request(null, SecurityEnvironment.create()))
                .orElseThrow();
    }
}
