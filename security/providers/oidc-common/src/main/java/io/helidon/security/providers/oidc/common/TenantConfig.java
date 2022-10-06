package io.helidon.security.providers.oidc.common;

import java.net.URI;
import java.time.Duration;
import java.util.logging.Logger;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.WebTarget;

import io.helidon.common.LazyValue;
import io.helidon.common.http.FormParams;
import io.helidon.security.SecurityException;
import io.helidon.security.jwt.jwk.JwkKeys;
import io.helidon.security.util.TokenHandler;
import io.helidon.webclient.WebClient;
import io.helidon.webclient.WebClientRequestBuilder;

/**
 * TODO javadoc
 */
public class TenantConfig {

    private static final Logger LOGGER = Logger.getLogger(TenantConfig.class.getName());

    static final String DEFAULT_BASE_SCOPES = "openid";
    static final String DEFAULT_REALM = "helidon";
    static final boolean DEFAULT_JWT_VALIDATE_JWK = true;
    static final String DEFAULT_PARAM_NAME = "accessToken";
    static final boolean DEFAULT_PARAM_USE = false;
    static final boolean DEFAULT_HEADER_USE = false;
    static final boolean DEFAULT_COOKIE_USE = true;
    static final String DEFAULT_COOKIE_NAME = "JSESSIONID";
    static final int DEFAULT_TIMEOUT_SECONDS = 30;
    static final int DEFAULT_PROXY_PORT = 80;
    static final String DEFAULT_PROXY_PROTOCOL = "http";
    private final String authorizationEndpointUri;
    private final String clientId;
    private final boolean useParam;
    private final String paramName;
    private final URI identityUri;
    private final LazyValue<URI> tokenEndpointUri;
    private final boolean useHeader;
    private final TokenHandler headerHandler;
    private final boolean useCookie;
    private final OidcCookieHandler tokenCookieHandler;
    private final OidcCookieHandler idTokenCookieHandler;
    private final String baseScopes;
    private final boolean validateJwtWithJwk;
    private final LazyValue<String> issuer;
    private final String audience;
    private final String realm;
    private final OidcConfig.ClientAuthentication tokenEndpointAuthentication;
    private final Duration clientTimeout;
    private final LazyValue<JwkKeys> signJwk;
    private final LazyValue<WebTarget> introspectEndpoint;
    private final String clientSecret;
    private final LazyValue<URI> introspectUri;
    private final LazyValue<WebTarget> tokenEndpoint;
    private final Client appClient;
    private final Client generalClient;
    private final WebClient webClient;
    private final WebClient appWebClient;
    private final LazyValue<URI> logoutEndpointUri;
    private final String scopeAudience;

    TenantConfig(BaseBuilder<?, ?> builder) {
        this.clientId = builder.clientId;
        this.useParam = builder.useParam;
        this.paramName = builder.paramName;
        this.useHeader = builder.useHeader;
        this.headerHandler = builder.headerHandler;
        this.baseScopes = builder.baseScopes;
        this.validateJwtWithJwk = builder.validateJwtWithJwk;
        this.issuer = builder.issuer;
        this.audience = builder.audience;
        this.identityUri = builder.identityUri;
        this.realm = builder.realm;
        this.tokenEndpointUri = builder.tokenEndpointUri;
        this.tokenEndpointAuthentication = builder.tokenEndpointAuthentication;
        this.clientTimeout = builder.clientTimeout;
        this.authorizationEndpointUri = builder.authorizationEndpointUri.toString();
        this.logoutEndpointUri = builder.logoutEndpointUri;
        this.appClient = builder.appClient;
        this.appWebClient = builder.appWebClient;
        this.webClient = builder.webClient;
        this.tokenEndpoint = builder.tokenEndpoint;
        this.generalClient = builder.generalClient;
        this.useCookie = builder.useCookie;

        this.tokenCookieHandler = builder.tokenCookieBuilder.build();
        this.idTokenCookieHandler = builder.idTokenCookieBuilder.build();
        if (tokenEndpointAuthentication == OidcConfig.ClientAuthentication.CLIENT_SECRET_POST) {
            // we should only store this if required
            this.clientSecret = builder.clientSecret;
        } else {
            this.clientSecret = null;
        }

        this.signJwk = LazyValue.create(() -> {
            JwkKeys jwkKeys = builder.signJwk.get();
            if (jwkKeys == null) {
                return JwkKeys.builder().build();
            } else {
                return jwkKeys;
            }
        });

        if (validateJwtWithJwk) {
            this.introspectEndpoint = null;
            this.introspectUri = null;
        } else {
            this.introspectUri = builder.introspectUri;
            this.introspectEndpoint = LazyValue.create(() -> appClient.target(builder.introspectUri.get()));
        }

        if ((builder.scopeAudience == null) || builder.scopeAudience.trim().isEmpty()) {
            this.scopeAudience = "";
        } else {
            String tmp = builder.scopeAudience.trim();
            if (tmp.endsWith("/")) {
                this.scopeAudience = tmp;
            } else {
                this.scopeAudience = tmp + "/";
            }
        }

        LOGGER.finest(() -> "OIDC Scope audience: " + scopeAudience);
    }

    public static Builder tenantBuilder() {
        return new Builder();
    }

    /**
     * JWK used for signature validation.
     *
     * @return set of keys used use to verify tokens
     * @see BaseBuilder#signJwk(JwkKeys)
     */
    public JwkKeys signJwk() {
        return signJwk.get();
    }

    /**
     * Authorization endpoint.
     *
     * @return authorization endpoint uri as a string
     * @see BaseBuilder#authorizationEndpointUri(URI)
     */
    public String authorizationEndpointUri() {
        return authorizationEndpointUri;
    }

    /**
     * Logout endpoint on OIDC server.
     *
     * @return URI of the logout endpoint
     * @see OidcConfig.Builder#logoutEndpointUri(java.net.URI)
     */
    public URI logoutEndpointUri() {
        return logoutEndpointUri.get();
    }

    /**
     * Token endpoint of the OIDC server.
     *
     * @return target the endpoint is on
     * @see Builder#tokenEndpointUri(URI)
     * @deprecated Please use {@link #appWebClient()} and {@link #tokenEndpointUri()} instead; result of moving to
     *      reactive webclient from JAX-RS client
     */
    @Deprecated(forRemoval = true, since = "2.4.0")
    public WebTarget tokenEndpoint() {
        return tokenEndpoint.get();
    }

    /**
     * Token endpoint URI.
     *
     * @return endpoint URI
     * @see BaseBuilder#tokenEndpointUri(java.net.URI)
     */
    public URI tokenEndpointUri() {
        return tokenEndpointUri.get();
    }

    /**
     * Whether to use query parameter to get the information from request.
     *
     * @return if query parameter should be used
     * @see BaseBuilder#useParam(Boolean)
     */
    public boolean useParam() {
        return useParam;
    }

    /**
     * Query parameter name.
     *
     * @return name of the query parameter to use
     * @see BaseBuilder#paramName(String)
     */
    public String paramName() {
        return paramName;
    }

    /**
     * Whether to use HTTP header to get the information from request.
     *
     * @return if header should be used
     * @see BaseBuilder#useHeader(Boolean)
     */
    public boolean useHeader() {
        return useHeader;
    }

    /**
     * {@link TokenHandler} to extract header information from request.
     *
     * @return handler to extract header
     * @see BaseBuilder#headerTokenHandler(TokenHandler)
     */
    public TokenHandler headerHandler() {
        return headerHandler;
    }

    /**
     * Whether to use cooke to get the information from request.
     *
     * @return if cookie should be used
     * @see OidcConfig.Builder#useCookie(Boolean)
     */
    public boolean useCookie() {
        return useCookie;
    }

    /**
     * Cookie name.
     *
     * @return name of the cookie to use
     * @see OidcConfig.Builder#cookieName(String)
     * @deprecated use {@link #tokenCookieHandler()} instead
     */
    @Deprecated(forRemoval = true, since = "2.4.0")
    public String cookieName() {
        return tokenCookieHandler.cookieName();
    }

    /**
     * Additional options of the cookie to use.
     *
     * @return cookie options to use in cookie string
     * @see OidcConfig.Builder#cookieHttpOnly(Boolean)
     * @see OidcConfig.Builder#cookieDomain(String)
     * @deprecated please use {@link #tokenCookieHandler()} instead
     */
    @Deprecated(forRemoval = true, since = "2.4.0")
    public String cookieOptions() {
        return tokenCookieHandler.createCookieOptions();
    }

    /**
     * Cookie handler to create cookies or unset cookies for token.
     *
     * @return a new cookie handler
     */
    public OidcCookieHandler tokenCookieHandler() {
        return tokenCookieHandler;
    }

    /**
     * Cookie handler to create cookies or unset cookies for id token.
     *
     * @return a new cookie handler
     */
    public OidcCookieHandler idTokenCookieHandler() {
        return idTokenCookieHandler;
    }

    /**
     * Prefix of a cookie header formed by name and "=".
     *
     * @return prefix of cookie value
     * @see OidcConfig.Builder#cookieName(String)
     * @deprecated use {@link io.helidon.security.providers.oidc.common.OidcCookieHandler} instead, this method
     *      will no longer be avilable
     */
    @Deprecated(forRemoval = true, since = "2.4.0")
    public String cookieValuePrefix() {
        return tokenCookieHandler.cookieValuePrefix();
    }

    /**
     * Client id of this client.
     *
     * @return client id
     * @see BaseBuilder#clientId(String)
     */
    public String clientId() {
        return clientId;
    }


    /**
     * Base scopes to require from OIDC server.
     *
     * @return base scopes
     * @see OidcConfig.Builder#baseScopes(String)
     */
    public String baseScopes() {
        return baseScopes;
    }

    /**
     * Whether to validate JWT with JWK information (e.g. verify signatures locally).
     *
     * @return if we should validate JWT with JWK
     * @see OidcConfig.Builder#validateJwtWithJwk(Boolean)
     */
    public boolean validateJwtWithJwk() {
        return validateJwtWithJwk;
    }

    /**
     * Token introspection endpoint.
     *
     * @return introspection endpoint
     * @see OidcConfig.Builder#introspectEndpointUri(URI)
     *@deprecated Please use {@link #appWebClient()} and {@link #introspectUri()} instead; result of moving to
     *      reactive webclient from JAX-RS client
     */
    @Deprecated(forRemoval = true, since = "2.4.0")
    public WebTarget introspectEndpoint() {
        return introspectEndpoint.get();
    }

    /**
     * Introspection endpoint URI.
     *
     * @return introspection endpoint URI
     * @see OidcConfig.Builder#introspectEndpointUri(java.net.URI)
     */
    public URI introspectUri() {
        URI uri = introspectUri.get();
        if (uri == null) {
            throw new SecurityException("Introspect URI is not configured when using validate with JWK.");
        }
        return uri;
    }

    /**
     * Token issuer.
     *
     * @return token issuer
     * @see OidcConfig.Builder#issuer(String)
     */
    public String issuer() {
        return issuer.get();
    }

    /**
     * Expected token audience.
     *
     * @return audience
     * @see OidcConfig.Builder#audience(String)
     */
    public String audience() {
        return audience;
    }

    /**
     * Audience URI of custom scopes.
     *
     * @return scope audience
     * @see OidcConfig.Builder#scopeAudience(String)
     */
    public String scopeAudience() {
        return scopeAudience;
    }

    /**
     * Identity server URI.
     *
     * @return identity server URI
     * @see OidcConfig.Builder#identityUri(URI)
     */
    public URI identityUri() {
        return identityUri;
    }

    /**
     * Client with configured proxy with no security.
     *
     * @return client for general use.
     * @deprecated Use {@link #generalWebClient()} instead
     */
    @Deprecated(forRemoval = true, since = "2.4.0")
    public Client generalClient() {
        return generalClient;
    }

    /**
     * Client with configured proxy with no security.
     *
     * @return client for general use.
     */
    public WebClient generalWebClient() {
        return webClient;
    }

    /**
     * Client with configured proxy and security of this OIDC client.
     *
     * @return client for communication with OIDC server
     * @deprecated Use {@link #appWebClient()}
     */
    @Deprecated(forRemoval = true, since = "2.4.0")
    public Client appClient() {
        return appClient;
    }

    /**
     * Client with configured proxy and security.
     *
     * @return client for communicating with OIDC identity server
     */
    public WebClient appWebClient() {
        return appWebClient;
    }

    /**
     * Realm to use for WWW-Authenticate response (if needed).
     *
     * @return realm name
     */
    public String realm() {
        return realm;
    }

    /**
     * Type of authentication mechanism used for token endpoint.
     *
     * @return client authentication type
     */
    public OidcConfig.ClientAuthentication tokenEndpointAuthentication() {
        return tokenEndpointAuthentication;
    }

    /**
     * Update request that uses form params with authentication.
     *
     * @param type type of the request
     * @param request request builder
     * @param form form params builder
     */
    public void updateRequest(OidcConfig.RequestType type, WebClientRequestBuilder request, FormParams.Builder form) {
        if (type == OidcConfig.RequestType.CODE_TO_TOKEN
                && tokenEndpointAuthentication == OidcConfig.ClientAuthentication.CLIENT_SECRET_POST) {
            form.add("client_id", clientId);
            form.add("client_secret", clientSecret);
        }
    }

    /**
     * Expected timeout of HTTP client operations.
     *
     * @return client timeout
     */
    public Duration clientTimeout() {
        return clientTimeout;
    }


    public static final class Builder extends BaseBuilder<Builder, TenantConfig> {

        private Builder() {
        }

        @Override
        public TenantConfig build() {
            buildConfiguration();
            return new TenantConfig(this);
        }
    }
}
