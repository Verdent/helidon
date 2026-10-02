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

package io.helidon.tests.integration.security.oidcnext.providers;

import java.net.URI;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;

import io.helidon.common.configurable.ResourceConfig;
import io.helidon.common.context.Contexts;
import io.helidon.json.JsonObject;
import io.helidon.security.Grant;
import io.helidon.security.Role;
import io.helidon.security.Security;
import io.helidon.security.SecurityContext;
import io.helidon.security.Subject;
import io.helidon.security.providers.common.OutboundTarget;
import io.helidon.security.providers.common.TokenCredential;
import io.helidon.security.providers.oidc.next.OidcClientAuthenticationMethod;
import io.helidon.security.providers.oidc.next.OidcEndpointCredential;
import io.helidon.security.providers.oidc.next.OidcEndpointPolicyConfig;
import io.helidon.security.providers.oidc.next.OidcFeature;
import io.helidon.security.providers.oidc.next.OidcOutboundPolicyConfig;
import io.helidon.security.providers.oidc.next.OidcProvider;
import io.helidon.security.providers.oidc.next.OidcProviderConfig;
import io.helidon.security.providers.oidc.next.OidcPushedAuthorizationRequestMode;
import io.helidon.security.providers.oidc.next.OidcRequestObjectMode;
import io.helidon.security.providers.oidc.next.OidcTenantConfig;
import io.helidon.security.providers.oidc.next.OidcTokenValidationMethod;
import io.helidon.webclient.api.HttpClientResponse;
import io.helidon.webclient.api.WebClient;
import io.helidon.webclient.security.WebClientSecurity;
import io.helidon.webserver.WebServer;
import io.helidon.webserver.http.HttpRouting;
import io.helidon.webserver.security.SecurityFeature;

final class RelyingParty implements AutoCloseable {
    private final OidcProvider provider;
    private final WebServer server;

    RelyingParty(IdpAdapter adapter, IdpAdapter.ClientMode mode, boolean browser,
                 Consumer<OidcTenantConfig.Builder> customizer) throws Exception {
        this(adapter, mode, browser, customizer, Optional.empty());
    }

    RelyingParty(IdpAdapter adapter, IdpAdapter.ClientMode mode, URI downstream,
                 OidcOutboundPolicyConfig policy) throws Exception {
        this(adapter, mode, false, _ -> { }, Optional.of(new Outbound(downstream, policy)));
    }

    private RelyingParty(IdpAdapter adapter, IdpAdapter.ClientMode mode, boolean browser,
                         Consumer<OidcTenantConfig.Builder> customizer, Optional<Outbound> outbound) throws Exception {
        OidcTenantConfig.Builder tenant = OidcTenantConfig.builder()
                .issuer(adapter.issuer().toString()).clientId(mode.id())
                .webClient(adapter.webClient())
                .subjectMapping(mapping -> mapping.principalIdClaimPaths(List.of("sub", "client_id"))
                        .principalNameClaimPaths(List.of("preferred_username", "username", "client_id", "sub"))
                        .roleClaimPaths(List.of("groups")))
                .protectedResource(resource -> resource.tokenValidation(validation -> {
                    validation.method(mode == IdpAdapter.ClientMode.JWT_ACCESS ? OidcTokenValidationMethod.JWT
                                : OidcTokenValidationMethod.INTROSPECTION)
                        .audience(IdpAdapter.AUDIENCE)
                        .introspection(introspection -> introspection.clientId(IdpAdapter.ClientMode.API.id())
                                .clientSecret(IdpAdapter.SECRET));
                    if (mode == IdpAdapter.ClientMode.JWT_ACCESS) {
                        validation.jwt(adapter.jwtLayout());
                    }
                }));
        if (mode != IdpAdapter.ClientMode.PUBLIC && mode != IdpAdapter.ClientMode.PRIVATE_JWT) {
            tenant.clientSecret(IdpAdapter.SECRET);
        }
        switch (mode) {
        case PUBLIC -> tenant.tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.NONE);
        case POST -> tenant.tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.CLIENT_SECRET_POST);
        case PRIVATE_JWT -> tenant.tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.PRIVATE_KEY_JWT)
                .clientAssertion(assertion -> assertion.algorithm("RS256").keyId("sign-rsa")
                        .jwk(ResourceConfig.builder().resourcePath("client-sign-jwk.json").buildPrototype()));
        case SECRET_JWT -> tenant.tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.CLIENT_SECRET_JWT)
                .clientAssertion(assertion -> assertion.algorithm("HS256"));
        default -> tenant.tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.CLIENT_SECRET_BASIC);
        }
        if (browser) {
            tenant.authorizationCode(code -> {
                code.scopes(List.of("openid", "profile", "email", "groups", "resource.read"))
                    .pushedAuthorizationRequests(mode == IdpAdapter.ClientMode.PAR
                            ? OidcPushedAuthorizationRequestMode.REQUIRED : OidcPushedAuthorizationRequestMode.DISABLED);
                if (mode == IdpAdapter.ClientMode.JAR) {
                    code.requestObject(request -> request.mode(OidcRequestObjectMode.REQUIRED).signingAlgorithm("RS256")
                            .signingKeyId("sign-rsa")
                            .signingJwk(ResourceConfig.builder().resourcePath("client-sign-jwk.json").buildPrototype()));
                }
            })
                    .userInfo(info -> {
                        info.attributeClaimPaths(List.of("email", "groups", "preferred_username"));
                        if (mode == IdpAdapter.ClientMode.SIGNED_USERINFO) {
                            info.jwt(jwt -> jwt.signingAlgorithm("RS256"));
                        }
                    })
                    .cookies(cookies -> cookies.protection(protection -> protection
                            .password("integration-test-authentication-cookie-password")))
                    .logout(logout -> logout.endSession(end -> end.enabled(false)));
        }
        if (mode == IdpAdapter.ClientMode.ENCRYPTED_ID_TOKEN) {
            tenant.idToken(token -> token.encryptionRequired(true)
                    .decryptionJwk(ResourceConfig.builder().resourcePath("client-encrypt-jwk.json").buildPrototype()));
        }
        customizer.accept(tenant);
        OidcProviderConfig.Builder config = OidcProviderConfig.builder().putTenant("default", tenant.buildPrototype());
        outbound.ifPresent(target -> config.addOutboundTarget(OutboundTarget.builder("shared-downstream")
                .addTransport(target.uri().getScheme()).addHost(target.uri().getHost()).addPath(target.uri().getPath())
                .addMethod("GET").customObject(OidcOutboundPolicyConfig.class, target.policy()).build()));
        provider = OidcProvider.create(config.buildPrototype());
        HttpRouting.Builder routing = HttpRouting.builder();
        OidcFeature.create(provider).setup(routing);
        OidcEndpointPolicyConfig cookiePolicy = OidcEndpointPolicyConfig.builder()
                .acceptedCredentials(List.of(OidcEndpointCredential.AUTHENTICATION_COOKIE)).buildPrototype();
        OidcEndpointPolicyConfig bearerPolicy = OidcEndpointPolicyConfig.builder()
                .acceptedCredentials(List.of(OidcEndpointCredential.BEARER_TOKEN)).buildPrototype();
        routing.get("/resource", SecurityFeature.authenticate().customObject(cookiePolicy),
                    (_, response) -> response.send(subject()));
        routing.get("/api", SecurityFeature.authenticate().customObject(bearerPolicy),
                    (_, response) -> response.send(subject()));
        outbound.ifPresent(target -> routing.get("/proxy", SecurityFeature.authenticate().customObject(bearerPolicy),
                (_, response) -> {
                    WebClient outboundClient = WebClient.builder().from(adapter.webClient()).servicesDiscoverServices(false)
                            .addService(WebClientSecurity.create()).build();
                    try (HttpClientResponse downstream = outboundClient.get().uri(target.uri()).request()) {
                        response.status(downstream.status()).send(downstream.as(String.class));
                    } finally {
                        outboundClient.closeResource();
                    }
                }));
        server = WebServer.builder().host("127.0.0.1").port(0).tls(IdpResources.serverTls())
                .addFeature(SecurityFeature.builder()
                        .security(Security.builder().addProvider(provider, "oidc-next").build()).build())
                .addRouting(routing).build().start();
        if (browser) {
            try {
                adapter.registerCallback(mode, baseUri().resolve("/oidc/callback"));
            } catch (Exception e) {
                close();
                throw e;
            }
        }
    }

    URI baseUri() {
        return URI.create("https://localhost:" + server.port());
    }

    @Override
    public void close() {
        try {
            server.stop();
        } finally {
            provider.close();
        }
    }

    private static JsonObject subject() {
        Subject subject = Contexts.context().flatMap(context -> context.get(SecurityContext.class))
                .flatMap(SecurityContext::user).orElseThrow();
        Object email = subject.principal().abacAttributeRaw("email");
        return JsonObject.builder().set("id", subject.principal().id()).set("name", subject.principal().getName())
                .set("email", email == null ? "" : email.toString())
                .setStrings("roles", subject.grants(Role.class).stream().map(Role::getName).sorted().toList())
                .setStrings("scopes", subject.grantsByType("scope").stream().map(Grant::getName).sorted().toList())
                .set("access_token", subject.publicCredential(TokenCredential.class).orElseThrow().token()).build();
    }

    private record Outbound(URI uri, OidcOutboundPolicyConfig policy) {
    }
}
