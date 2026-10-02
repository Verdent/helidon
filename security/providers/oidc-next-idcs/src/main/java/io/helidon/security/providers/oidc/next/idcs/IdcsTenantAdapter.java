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

package io.helidon.security.providers.oidc.next.idcs;

import java.net.URI;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;

import io.helidon.common.parameters.Parameters;
import io.helidon.config.Config;
import io.helidon.http.HeaderValues;
import io.helidon.http.Status;
import io.helidon.json.JsonObject;
import io.helidon.security.providers.oidc.next.OidcEndpointConfig;
import io.helidon.security.providers.oidc.next.OidcTenantConfig;
import io.helidon.security.providers.oidc.next.spi.OidcTenantAdapter;
import io.helidon.webclient.api.HttpClientResponse;
import io.helidon.webclient.api.WebClient;

/**
 * Optional Oracle IDCS tenant defaults and protected signing-key access for OIDC Next.
 * <p>
 * The user supplies the IDCS domain URL, not its individual OAuth endpoints. The paths below are documented by
 * Oracle's IDCS discovery response. Normal OIDC Next endpoint, issuer, token, and cookie validation remains in force;
 * this adapter is selected explicitly for each applicable tenant.
 */
public final class IdcsTenantAdapter implements OidcTenantAdapter {
    private static final String TYPE = "idcs";
    private static final String IDCS_ISSUER = "https://identity.oraclecloud.com/";
    private static final String AUTHORIZATION_PATH = "/oauth2/v1/authorize";
    private static final String TOKEN_PATH = "/oauth2/v1/token";
    private static final String JWKS_PATH = "/admin/v1/SigningCert/jwk";
    private static final String USER_INFO_PATH = "/oauth2/v1/userinfo";
    private static final String INTROSPECTION_PATH = "/oauth2/v1/introspect";
    private static final String END_SESSION_PATH = "/oauth2/v1/userlogout";
    private static final String DEFAULT_JWK_SET_SCOPE = "urn:opc:idm:__myscopes__";

    private final String name;
    private final URI domainUri;
    private final Optional<URI> secureDomainUri;
    private final JwkSetGrant jwkSetGrant;
    private final String jwkSetScope;

    private IdcsTenantAdapter(Builder builder) {
        this.name = builder.name;
        this.domainUri = requireDomainUri(builder.domainUri, "domain-uri");
        this.secureDomainUri = builder.secureDomainUri.map(uri -> requireDomainUri(uri, "secure-domain-uri"));
        this.jwkSetGrant = builder.jwkSetGrant;
        this.jwkSetScope = builder.jwkSetScope;
        if (jwkSetScope.isBlank() || !jwkSetScope.equals(jwkSetScope.strip())) {
            throw new IllegalArgumentException("jwks-scope must not be blank or padded");
        }
    }

    /**
     * Create a programmatic adapter builder.
     *
     * @return builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Create from the {@code adapter.idcs} configuration node.
     *
     * @param config IDCS adapter configuration
     * @return adapter
     */
    public static IdcsTenantAdapter create(Config config) {
        return builder().config(config).build();
    }

    @Override
    public String name() {
        return name;
    }

    @Override
    public String type() {
        return TYPE;
    }

    @Override
    public void configure(OidcTenantConfig.BuilderBase<?, ?> tenant) {
        if (tenant.issuer().isEmpty()) {
            tenant.issuer(IDCS_ISSUER);
        }
        OidcEndpointConfig.Builder endpoints = OidcEndpointConfig.builder().from(tenant.endpoints());
        if (endpoints.authorizationEndpointUri().isEmpty()) {
            endpoints.authorizationEndpointUri(domainUri.resolve(AUTHORIZATION_PATH));
        }
        if (endpoints.tokenEndpointUri().isEmpty()) {
            URI tokenDomain = jwkSetGrant == JwkSetGrant.TLS_CLIENT_AUTH
                    ? secureDomainUri.orElse(domainUri)
                    : domainUri;
            endpoints.tokenEndpointUri(tokenDomain.resolve(TOKEN_PATH));
        }
        if (endpoints.jwksUri().isEmpty()) {
            URI keyDomain = jwkSetGrant == JwkSetGrant.TLS_CLIENT_AUTH
                    ? secureDomainUri.orElse(domainUri)
                    : domainUri;
            endpoints.jwksUri(keyDomain.resolve(JWKS_PATH));
        }
        if (!trustedDomain(endpoints.jwksUri().orElseThrow())) {
            throw new IllegalArgumentException("IDCS jwks-uri must use the configured primary or secure domain origin");
        }
        if (endpoints.userInfoEndpointUri().isEmpty()) {
            endpoints.userInfoEndpointUri(domainUri.resolve(USER_INFO_PATH));
        }
        if (endpoints.introspectionEndpointUri().isEmpty()) {
            endpoints.introspectionEndpointUri(domainUri.resolve(INTROSPECTION_PATH));
        }
        if (endpoints.endSessionEndpointUri().isEmpty()) {
            endpoints.endSessionEndpointUri(domainUri.resolve(END_SESSION_PATH));
        }
        tenant.endpoints(endpoints.buildPrototype());
    }

    @Override
    public Optional<String> principalIdentityNamespace() {
        return Optional.of(domainUri.toString());
    }

    @Override
    public Optional<String> jwkSetAccessToken(OidcTenantConfig tenant,
                                              URI jwkSetUri,
                                              WebClient webClient,
                                              ClientCredentials clientCredentials) {
        if (!tenant.endpoints().jwksUri().filter(jwkSetUri::equals).isPresent() || !trustedDomain(jwkSetUri)) {
            throw new IllegalStateException("IDCS authenticated JWK Set access requires the configured IDCS domain URI");
        }
        URI tokenEndpoint = tenant.endpoints().tokenEndpointUri().orElseThrow();
        URI primaryToken = domainUri.resolve(TOKEN_PATH);
        URI secureToken = secureDomainUri.map(uri -> uri.resolve(TOKEN_PATH)).orElse(primaryToken);
        if (!tokenEndpoint.equals(primaryToken) && !tokenEndpoint.equals(secureToken)) {
            throw new IllegalStateException("IDCS signing-key grant requires a Token Endpoint on the IDCS domain");
        }
        if (jwkSetGrant == JwkSetGrant.CLIENT_CREDENTIALS) {
            return Optional.of(clientCredentials.accessToken(jwkSetScope));
        }
        Parameters form = Parameters.builder("idcs-signing-key-token-form")
                .add("grant_type", "tls_client_auth")
                .add("client_id", tenant.clientId().orElseThrow())
                .add("scope", jwkSetScope)
                .build();
        try (HttpClientResponse response = webClient.post()
                .uri(tokenEndpoint)
                .followRedirects(false)
                .header(HeaderValues.ACCEPT_JSON)
                .submit(form)) {
            if (response.status().code() != Status.OK_200_CODE) {
                throw new IllegalStateException("IDCS signing-key token request failed: status="
                                                        + response.status().code());
            }
            JsonObject json = response.as(JsonObject.class);
            json.stringValue("token_type")
                    .filter(type -> !"Bearer".equalsIgnoreCase(type))
                    .ifPresent(_ -> {
                        throw new IllegalStateException("IDCS signing-key token must use the Bearer type");
                    });
            return Optional.of(json.stringValue("access_token")
                                       .filter(value -> !value.isBlank())
                                       .orElseThrow(() -> new IllegalStateException("IDCS signing-key token is missing")));
        }
    }

    private static URI requireDomainUri(URI uri, String name) {
        Objects.requireNonNull(uri, name);
        if (!"https".equalsIgnoreCase(uri.getScheme())
                || uri.getHost() == null || uri.getHost().isBlank()
                || uri.getRawUserInfo() != null || uri.getRawQuery() != null || uri.getRawFragment() != null
                || uri.getRawPath() != null && !uri.getRawPath().isEmpty() && !"/".equals(uri.getRawPath())) {
            throw new IllegalArgumentException(name + " must be an HTTPS domain URL without path, query or fragment");
        }
        String authority = uri.getRawAuthority().toLowerCase(Locale.ROOT);
        if (uri.getPort() == 443) {
            authority = authority.substring(0, authority.length() - 4);
        }
        return URI.create("https://" + authority);
    }

    private boolean trustedDomain(URI uri) {
        return sameOrigin(uri, domainUri) || secureDomainUri.filter(domain -> sameOrigin(uri, domain)).isPresent();
    }

    private static boolean sameOrigin(URI uri, URI domain) {
        return "https".equalsIgnoreCase(uri.getScheme())
                && uri.getHost() != null && uri.getHost().equalsIgnoreCase(domain.getHost())
                && (uri.getPort() == -1 ? 443 : uri.getPort()) == (domain.getPort() == -1 ? 443 : domain.getPort())
                && uri.getRawUserInfo() == null && uri.getRawFragment() == null;
    }

    /**
     * Grant for obtaining a token to read a protected IDCS signing-key endpoint.
     */
    public enum JwkSetGrant {
        /** Standard OAuth client credentials, using the tenant's configured client-authentication method. */
        CLIENT_CREDENTIALS,
        /** Oracle's certificate-based {@code tls_client_auth} grant. */
        TLS_CLIENT_AUTH
    }

    /**
     * Programmatic and config-backed builder for a tenant adapter.
     */
    public static final class Builder implements io.helidon.common.Builder<Builder, IdcsTenantAdapter> {
        private String name = TYPE;
        private URI domainUri;
        private Optional<URI> secureDomainUri = Optional.empty();
        private JwkSetGrant jwkSetGrant = JwkSetGrant.CLIENT_CREDENTIALS;
        private String jwkSetScope = DEFAULT_JWK_SET_SCOPE;

        private Builder() {
        }

        /**
         * Configure from the {@code adapter.idcs} configuration node.
         *
         * @param config configuration node
         * @return this builder
         */
        public Builder config(Config config) {
            Objects.requireNonNull(config);
            config.get("domain-uri").as(URI.class).ifPresent(this::domainUri);
            config.get("secure-domain-uri").as(URI.class).ifPresent(this::secureDomainUri);
            config.get("jwks-grant").asString()
                    .ifPresent(value -> jwkSetGrant(JwkSetGrant.valueOf(value.toUpperCase(Locale.ROOT))));
            config.get("jwks-scope").asString().ifPresent(this::jwkSetScope);
            return this;
        }

        /**
         * Display name for this configured adapter.
         *
         * @param name adapter name
         * @return this builder
         */
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }

        /**
         * HTTPS base URL of the IDCS tenant, without a path.
         *
         * @param domainUri domain URL
         * @return this builder
         */
        public Builder domainUri(URI domainUri) {
            this.domainUri = Objects.requireNonNull(domainUri);
            return this;
        }

        /**
         * Optional HTTPS domain used for certificate-based IDCS token and key endpoints.
         *
         * @param secureDomainUri secure domain URL
         * @return this builder
         */
        public Builder secureDomainUri(URI secureDomainUri) {
            this.secureDomainUri = Optional.of(Objects.requireNonNull(secureDomainUri));
            return this;
        }

        /**
         * Grant used when the signing-key endpoint refuses an unauthenticated GET.
         *
         * @param jwkSetGrant grant
         * @return this builder
         */
        public Builder jwkSetGrant(JwkSetGrant jwkSetGrant) {
            this.jwkSetGrant = Objects.requireNonNull(jwkSetGrant);
            return this;
        }

        /**
         * Scope used only to acquire a token for the signing-key endpoint.
         *
         * @param jwkSetScope scope
         * @return this builder
         */
        public Builder jwkSetScope(String jwkSetScope) {
            this.jwkSetScope = Objects.requireNonNull(jwkSetScope);
            return this;
        }

        @Override
        public IdcsTenantAdapter build() {
            return new IdcsTenantAdapter(this);
        }
    }
}
