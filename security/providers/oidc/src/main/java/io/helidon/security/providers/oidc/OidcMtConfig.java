package io.helidon.security.providers.oidc;

import java.net.URI;
import java.time.Duration;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.WebTarget;

import io.helidon.common.http.FormParams;
import io.helidon.security.jwt.jwk.JwkKeys;
import io.helidon.security.providers.oidc.common.OidcConfig;
import io.helidon.security.providers.oidc.common.OidcCookieHandler;
import io.helidon.security.util.TokenHandler;
import io.helidon.webclient.WebClient;
import io.helidon.webclient.WebClientRequestBuilder;
import io.helidon.webserver.cors.CrossOriginConfig;

/**
 * TODO javadoc
 */
class OidcMtConfig implements OidcConfig {

    private final OidcConfig defaultConfig;
    private final OidcConfig tenantConfig;

    private OidcMtConfig(OidcConfig defaultConfig, OidcConfig tenantConfig) {
        this.defaultConfig = defaultConfig;
        this.tenantConfig = tenantConfig;
    }

    static OidcMtConfig create(OidcConfig defaultConfig, OidcConfig tenantConfig) {
        return new OidcMtConfig(defaultConfig, tenantConfig);
    }

    @Override
    public JwkKeys signJwk() {
        return value(tenantConfig.signJwk(), defaultConfig.signJwk());
    }

    @Override
    public String redirectUri() {
        return value(tenantConfig.redirectUri(), defaultConfig.redirectUri());
    }

    @Override
    public boolean forceHttpsRedirects() {
        return value(tenantConfig.forceHttpsRedirects(), defaultConfig.forceHttpsRedirects());
    }

    @Override
    public boolean logoutEnabled() {
        return value(tenantConfig.logoutEnabled(), defaultConfig.logoutEnabled());
    }

    @Override
    public String logoutUri() {
        return value(tenantConfig.logoutUri(), defaultConfig.logoutUri());
    }

    @Override
    public URI postLogoutUri() {
        return value(tenantConfig.postLogoutUri(), defaultConfig.postLogoutUri());
    }

    @Override
    public WebTarget tokenEndpoint() {
        return value(tenantConfig.tokenEndpoint(), defaultConfig.tokenEndpoint());
    }

    @Override
    public URI tokenEndpointUri() {
        return value(tenantConfig.tokenEndpointUri(), defaultConfig.tokenEndpointUri());
    }

    @Override
    public boolean useParam() {
        return value(tenantConfig.useParam(), defaultConfig.useParam());
    }

    @Override
    public String paramName() {
        return value(tenantConfig.paramName(), defaultConfig.paramName());
    }

    @Override
    public boolean useCookie() {
        return value(tenantConfig.useCookie(), defaultConfig.useCookie());
    }

    @Override
    public String cookieName() {
        return value(tenantConfig.cookieName(), defaultConfig.cookieName());
    }

    @Override
    public String cookieOptions() {
        return value(tenantConfig.cookieOptions(), defaultConfig.cookieOptions());
    }

    @Override
    public OidcCookieHandler tokenCookieHandler() {
        return value(tenantConfig.tokenCookieHandler(), defaultConfig.tokenCookieHandler());
    }

    @Override
    public OidcCookieHandler idTokenCookieHandler() {
        return value(tenantConfig.idTokenCookieHandler(), defaultConfig.idTokenCookieHandler());
    }

    @Override
    public boolean useHeader() {
        return value(tenantConfig.useHeader(), defaultConfig.useHeader());
    }

    @Override
    public TokenHandler headerHandler() {
        return value(tenantConfig.headerHandler(), defaultConfig.headerHandler());
    }

    @Override
    public String cookieValuePrefix() {
        return value(tenantConfig.cookieValuePrefix(), defaultConfig.cookieValuePrefix());
    }

    @Override
    public String scopeAudience() {
        return value(tenantConfig.scopeAudience(), defaultConfig.scopeAudience());
    }

    @Override
    public String authorizationEndpointUri() {
        return value(tenantConfig.authorizationEndpointUri(), defaultConfig.authorizationEndpointUri());
    }

    @Override
    public URI logoutEndpointUri() {
        return value(tenantConfig.logoutEndpointUri(), defaultConfig.logoutEndpointUri());
    }

    @Override
    public String clientId() {
        return value(tenantConfig.clientId(), defaultConfig.clientId());
    }

    @Override
    public String redirectUriWithHost() {
        return value(tenantConfig.redirectUriWithHost(), defaultConfig.redirectUriWithHost());
    }

    @Override
    public String redirectUriWithHost(String frontendUri) {
        //TADY UPRAVIT??
        String tenantUriWithHost = tenantConfig.redirectUriWithHost(frontendUri);
        return tenantUriWithHost.equals(frontendUri) ? defaultConfig.redirectUriWithHost(frontendUri) : tenantUriWithHost;
    }

    @Override
    public String baseScopes() {
        return value(tenantConfig.baseScopes(), defaultConfig.baseScopes());
    }

    @Override
    public boolean validateJwtWithJwk() {
        //TADY UPRAVIT??
        return tenantConfig.validateJwtWithJwk();
    }

    @Override
    public WebTarget introspectEndpoint() {
        return value(tenantConfig.introspectEndpoint(), defaultConfig.introspectEndpoint());
    }

    @Override
    public URI introspectUri() {
        return value(tenantConfig.introspectUri(), defaultConfig.introspectUri());
    }

    @Override
    public String issuer() {
        return value(tenantConfig.issuer(), defaultConfig.issuer());
    }

    @Override
    public String audience() {
        return value(tenantConfig.audience(), defaultConfig.audience());
    }

    @Override
    public URI identityUri() {
        return value(tenantConfig.identityUri(), defaultConfig.identityUri());
    }

    @Override
    public Client generalClient() {
        return value(tenantConfig.generalClient(), defaultConfig.generalClient());
    }

    @Override
    public WebClient generalWebClient() {
        return value(tenantConfig.generalWebClient(), defaultConfig.generalWebClient());
    }

    @Override
    public Client appClient() {
        return value(tenantConfig.appClient(), defaultConfig.appClient());
    }

    @Override
    public WebClient appWebClient() {
        return value(tenantConfig.appWebClient(), defaultConfig.appWebClient());
    }

    @Override
    public boolean shouldRedirect() {
        //TADY UPRAVIT??
        return value(tenantConfig.shouldRedirect(), defaultConfig.shouldRedirect());
    }

    @Override
    public String realm() {
        return value(tenantConfig.realm(), defaultConfig.realm());
    }

    @Override
    public String redirectAttemptParam() {
        return value(tenantConfig.redirectAttemptParam(), defaultConfig.redirectAttemptParam());
    }

    @Override
    public int maxRedirects() {
        return tenantConfig.maxRedirects() <= 0 ? defaultConfig.maxRedirects() : tenantConfig.maxRedirects();
    }

    @Override
    public ClientAuthentication tokenEndpointAuthentication() {
        return value(tenantConfig.tokenEndpointAuthentication(), defaultConfig.tokenEndpointAuthentication());
    }

    @Override
    public void updateRequest(RequestType type, WebClientRequestBuilder request, FormParams.Builder form) {
        //TADY UPRAVIT
    }

    @Override
    public Duration clientTimeout() {
        return value(tenantConfig.clientTimeout(), defaultConfig.clientTimeout());
    }

    @Override
    public CrossOriginConfig crossOriginConfig() {
        return value(tenantConfig.crossOriginConfig(), defaultConfig.crossOriginConfig());
    }

    @Override
    public Duration tokenRefreshSkew() {
        return value(tenantConfig.tokenRefreshSkew(), defaultConfig.tokenRefreshSkew());
    }

    private <T> T value(T tenant, T defaultValue) {
        return tenant == null ? defaultValue : tenant;
    }
}
