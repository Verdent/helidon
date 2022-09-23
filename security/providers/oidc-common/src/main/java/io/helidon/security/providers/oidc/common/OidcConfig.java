package io.helidon.security.providers.oidc.common;

import java.net.URI;
import java.time.Duration;
import java.util.Collections;
import java.util.Locale;
import java.util.Optional;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.logging.Logger;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReaderFactory;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;

import io.helidon.common.Errors;
import io.helidon.common.configurable.Resource;
import io.helidon.common.http.FormParams;
import io.helidon.common.http.Http;
import io.helidon.common.http.SetCookie;
import io.helidon.common.reactive.Single;
import io.helidon.config.Config;
import io.helidon.config.metadata.Configured;
import io.helidon.config.metadata.ConfiguredOption;
import io.helidon.security.Security;
import io.helidon.security.SecurityException;
import io.helidon.security.jwt.jwk.JwkKeys;
import io.helidon.security.providers.common.OutboundTarget;
import io.helidon.security.providers.httpauth.HttpBasicAuthProvider;
import io.helidon.security.providers.httpauth.HttpBasicOutboundConfig;
import io.helidon.security.util.TokenHandler;
import io.helidon.webclient.WebClient;
import io.helidon.webclient.WebClientRequestBuilder;
import io.helidon.webclient.security.WebClientSecurity;
import io.helidon.webserver.cors.CrossOriginConfig;

import org.glassfish.jersey.client.authentication.HttpAuthenticationFeature;

/**
 * TODO javadoc
 */
public interface OidcConfig {

    /**
     * Default name of the header we expect JWT in.
     */
    String PARAM_HEADER_NAME = "X_OIDC_TOKEN_HEADER";

    /**
     * Create a builder to programmatically construct OIDC configuration.
     *
     * @return a new builder instance usable for fluent API
     */
    static Builder builder() {
        return new Builder();
    }

    /**
     * Create a new instance from {@link Config}.
     * The config instance has to be on the node containing keys used by this class (e.g. client-id).
     *
     * @param config configuration used to obtain OIDC integration values
     * @return a new instance of this class configured from provided config
     */
    static OidcConfig create(Config config) {
        return OidcConfig.builder()
                .config(config)
                .build();
    }

    /**
     * Processing of {@link WebClient} submit using a POST method.
     * This is a helper method to handle possible cases (success, failure with readable entity, failure).
     *
     * @param requestBuilder       WebClient request builder
     * @param toSubmit             object to submit (such as {@link io.helidon.common.http.FormParams}
     * @param jsonProcessor        processor of successful JSON response
     * @param errorEntityProcessor processor of an error that has an entity, to fail the single
     * @param errorProcessor       processor of an error that does not have an entity
     * @param <T>                  type of the result the call
     * @return a future that completes successfully if processed from json, or if an error processor returns a non-empty value,
     * completes with error otherwise
     */
    static <T> Single<T> postJsonResponse(WebClientRequestBuilder requestBuilder,
                                          Object toSubmit,
                                          Function<JsonObject, T> jsonProcessor,
                                          BiFunction<Http.ResponseStatus, String, Optional<T>> errorEntityProcessor,
                                          BiFunction<Throwable, String, Optional<T>> errorProcessor) {
        return requestBuilder.submit(toSubmit)
                .flatMapSingle(response -> {
                    if (response.status().family() == Http.ResponseStatus.Family.SUCCESSFUL) {
                        return response.content()
                                .as(JsonObject.class)
                                .map(jsonProcessor)
                                .onErrorResumeWithSingle(t -> errorProcessor.apply(t, "Failed to read JSON from response")
                                        .map(Single::just)
                                        .orElseGet(() -> Single.error(t)));
                    } else {
                        return response.content()
                                .as(String.class)
                                .flatMapSingle(it -> errorEntityProcessor.apply(response.status(), it)
                                        .map(Single::just)
                                        .orElseGet(() -> Single.error(new SecurityException("Failed to process request: " + it))))
                                .onErrorResumeWithSingle(t -> errorProcessor.apply(t, "Failed to process error entity")
                                        .map(Single::just)
                                        .orElseGet(() -> Single.error(t)));
                    }
                })
                .onErrorResumeWithSingle(t -> errorProcessor.apply(t, "Failed to invoke request")
                        .map(Single::just)
                        .orElseGet(() -> Single.error(t)));

    }

    JwkKeys signJwk();

    String redirectUri();

    boolean forceHttpsRedirects();

    boolean logoutEnabled();

    String logoutUri();

    URI postLogoutUri();

    @Deprecated(forRemoval = true, since = "2.4.0")
    WebTarget tokenEndpoint();

    URI tokenEndpointUri();

    boolean useParam();

    String paramName();

    boolean useCookie();

    @Deprecated(forRemoval = true, since = "2.4.0")
    String cookieName();

    @Deprecated(forRemoval = true, since = "2.4.0")
    String cookieOptions();

    OidcCookieHandler tokenCookieHandler();

    OidcCookieHandler idTokenCookieHandler();

    boolean useHeader();

    TokenHandler headerHandler();

    @Deprecated(forRemoval = true, since = "2.4.0")
    String cookieValuePrefix();

    String scopeAudience();

    String authorizationEndpointUri();

    URI logoutEndpointUri();

    String clientId();

    String redirectUriWithHost();

    String redirectUriWithHost(String frontendUri);

    String baseScopes();

    boolean validateJwtWithJwk();

    @Deprecated(forRemoval = true, since = "2.4.0")
    WebTarget introspectEndpoint();

    URI introspectUri();

    String issuer();

    String audience();

    URI identityUri();

    @Deprecated(forRemoval = true, since = "2.4.0")
    Client generalClient();

    /**
     * Client with configured proxy with no security.
     *
     * @return client for general use.
     */
    WebClient generalWebClient();

    /**
     * Client with configured proxy and security of this OIDC client.
     *
     * @return client for communication with OIDC server
     * @deprecated Use {@link #appWebClient()}
     */
    @Deprecated(forRemoval = true, since = "2.4.0")
    Client appClient();

    /**
     * Client with configured proxy and security.
     *
     * @return client for communicating with OIDC identity server
     */
    WebClient appWebClient();

    boolean shouldRedirect();

    String realm();

    String redirectAttemptParam();

    int maxRedirects();

    ClientAuthentication tokenEndpointAuthentication();

    void updateRequest(RequestType type, WebClientRequestBuilder request, FormParams.Builder form);

    Duration clientTimeout();

    CrossOriginConfig crossOriginConfig();

    Duration tokenRefreshSkew();

    /**
     * Client Authentication methods that are used by Clients to authenticate to the Authorization
     * Server when using the Token Endpoint.
     */
    public enum ClientAuthentication {
        /**
         * Clients that have received a client_secret value from the Authorization Server authenticate with the Authorization
         * Server in accordance with Section 2.3.1 of OAuth 2.0 [RFC6749] using the HTTP Basic authentication scheme.
         * This is the default client authentication.
         */
        CLIENT_SECRET_BASIC,
        /**
         * Clients that have received a client_secret value from the Authorization Server, authenticate with the Authorization
         * Server in accordance with Section 2.3.1 of OAuth 2.0 [RFC6749] by including the Client Credentials in the request body.
         */
        CLIENT_SECRET_POST,
        /**
         * Clients that have received a client_secret value from the Authorization Server create a JWT using an HMAC SHA
         * algorithm, such as HMAC SHA-256. The HMAC (Hash-based Message Authentication Code) is calculated using the octets of
         * the UTF-8 representation of the client_secret as the shared key.
         * The Client authenticates in accordance with JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and
         * Authorization Grants [OAuth.JWT] and Assertion Framework for OAuth 2.0 Client Authentication and Authorization
         * Grants [OAuth.Assertions].
         * <p>
         * The JWT MUST contain the following REQUIRED Claim Values and MAY contain the following
         * OPTIONAL Claim Values.
         * <p>
         * Required:
         * {@code iss, sub, aud, jti, exp}
         * <p>
         * Optional:
         * {@code iat}
         */
        CLIENT_SECRET_JWT,
        /**
         * Clients that have registered a public key sign a JWT using that key. The Client authenticates in accordance with
         * JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants [OAuth.JWT] and Assertion
         * Framework for OAuth 2.0 Client Authentication and Authorization Grants [OAuth.Assertions].
         * <p>
         * The JWT MUST contain the following REQUIRED Claim Values and MAY contain the following
         * OPTIONAL Claim Values.
         * <p>
         * Required:
         * {@code iss, sub, aud, jti, exp}
         * <p>
         * Optional:
         * {@code iat}
         */
        PRIVATE_KEY_JWT,
        /**
         * The Client does not authenticate itself at the Token Endpoint, either because it uses only the Implicit Flow (and so
         * does not use the Token Endpoint) or because it is a Public Client with no Client Secret or other authentication
         * mechanism.
         */
        NONE
    }

    /**
     * Types of requests to identity provider.
     */
    public enum RequestType {
        /**
         * Request to exchange code for a token issued against the token endpoint.
         */
        CODE_TO_TOKEN,
        /**
         * Request to validate a JWT against an introspection endpoint.
         */
        INTROSPECT_JWT;
    }

    /**
     * A fluent API {@link io.helidon.common.Builder} to build instances of {@link OidcConfig}.
     */
    @Configured(description = "Open ID Connect configuration")
    final class Builder implements io.helidon.common.Builder<OidcConfig> {

        static final int DEFAULT_PROXY_PORT = 80;
        static final String DEFAULT_REDIRECT_URI = "/oidc/redirect";
        static final String DEFAULT_LOGOUT_URI = "/oidc/logout";
        static final String DEFAULT_COOKIE_NAME = "JSESSIONID";
        static final boolean DEFAULT_COOKIE_USE = true;
        static final String DEFAULT_PARAM_NAME = "accessToken";
        static final boolean DEFAULT_PARAM_USE = false;
        static final boolean DEFAULT_HEADER_USE = false;
        static final String DEFAULT_PROXY_PROTOCOL = "http";
        static final String DEFAULT_BASE_SCOPES = "openid";
        static final boolean DEFAULT_JWT_VALIDATE_JWK = true;
        static final boolean DEFAULT_REDIRECT = true;
        static final String DEFAULT_REALM = "helidon";
        static final String DEFAULT_ATTEMPT_PARAM = "h_ra";
        static final int DEFAULT_MAX_REDIRECTS = 5;
        static final int DEFAULT_TIMEOUT_SECONDS = 30;
        static final boolean DEFAULT_FORCE_HTTPS_REDIRECTS = false;
        static final Duration DEFAULT_TOKEN_REFRESH_SKEW = Duration.ofSeconds(5);

        static final String DEFAULT_SERVER_TYPE = "@default";


        private static final Logger LOGGER = Logger.getLogger(OidcConfig.class.getName());
        private static final JsonReaderFactory JSON = Json.createReaderFactory(Collections.emptyMap());

        final OidcCookieHandler.Builder tokenCookieBuilder = OidcCookieHandler.builder()
                .cookieName(DEFAULT_COOKIE_NAME);
        final OidcCookieHandler.Builder idTokenCookieBuilder = OidcCookieHandler.builder()
                .cookieName(DEFAULT_COOKIE_NAME + "_2");

        String issuer;
        String audience;
        String baseScopes = DEFAULT_BASE_SCOPES;
        // mandatory properties
        URI identityUri;
        String clientId;
        String clientSecret;
        String redirectUri = DEFAULT_REDIRECT_URI;
        String logoutUri = DEFAULT_LOGOUT_URI;
        boolean logoutEnabled = false;
        boolean useCookie = DEFAULT_COOKIE_USE;
        boolean useParam = DEFAULT_PARAM_USE;
        String paramName = DEFAULT_PARAM_NAME;
        // optional properties
        String proxyProtocol = DEFAULT_PROXY_PROTOCOL;
        String proxyHost;
        int proxyPort = DEFAULT_PROXY_PORT;
        String scopeAudience;
        OidcMetadata.Builder oidcMetadata = OidcMetadata.builder();
        String frontendUri;
        boolean useHeader = DEFAULT_HEADER_USE;
        TokenHandler headerHandler = TokenHandler.builder()
                .tokenHeader("Authorization")
                .tokenPrefix("bearer ")
                .build();
        URI tokenEndpointUri;
        ClientAuthentication tokenEndpointAuthentication = ClientAuthentication.CLIENT_SECRET_BASIC;
        URI authorizationEndpointUri;
        URI logoutEndpointUri;
        JwkKeys signJwk;
        boolean oidcMetadataWellKnown = true;
        boolean validateJwtWithJwk = DEFAULT_JWT_VALIDATE_JWK;
        URI introspectUri;
        boolean redirect = DEFAULT_REDIRECT;
        String realm = DEFAULT_REALM;
        String redirectAttemptParam = DEFAULT_ATTEMPT_PARAM;
        int maxRedirects = DEFAULT_MAX_REDIRECTS;
        boolean cookieSameSiteDefault = true;
        String serverType;
        @Deprecated
        Client generalClient;
        @Deprecated
        WebTarget tokenEndpoint;
        @Deprecated
        Client appClient;
        WebClient appWebClient;
        WebClient webClient;
        Duration clientTimeout = Duration.ofSeconds(DEFAULT_TIMEOUT_SECONDS);
        URI postLogoutUri;
        CrossOriginConfig crossOriginConfig;
        boolean forceHttpsRedirects = DEFAULT_FORCE_HTTPS_REDIRECTS;
        Duration tokenRefreshSkew = DEFAULT_TOKEN_REFRESH_SKEW;

        private Builder() {
        }

        @Override
        public OidcConfig build() {
            this.serverType = OidcUtil.fixServerType(serverType);

            Errors.Collector collector = Errors.collector();

            OidcUtil.validateExists(collector, clientId, "Client Id", "client-id");
            OidcUtil.validateExists(collector, clientSecret, "Client Secret", "client-secret");
            OidcUtil.validateExists(collector, identityUri, "Identity URI", "identity-uri");

            // first set of validations
            collector.collect().checkValid();
            collector = Errors.collector();

            WebClient.Builder webClientBuilder = OidcUtil.webClientBaseBuilder(proxyHost,
                                                                               proxyPort,
                                                                               clientTimeout);
            ClientBuilder clientBuilder = OidcUtil.clientBaseBuilder(proxyProtocol, proxyHost, proxyPort);

            this.generalClient = clientBuilder.build();
            this.webClient = webClientBuilder.build();

            OidcMetadata oidcMetadata = this.oidcMetadata.webClient(webClient)
                    .remoteEnabled(oidcMetadataWellKnown)
                    .identityUri(identityUri)
                    .collector(collector)
                    .build();

            this.tokenEndpointUri = oidcMetadata.getOidcEndpoint(collector,
                                                                 tokenEndpointUri,
                                                                 "token_endpoint",
                                                                 "/oauth2/v1/token");

            this.authorizationEndpointUri = oidcMetadata.getOidcEndpoint(collector,
                                                                         authorizationEndpointUri,
                                                                         "authorization_endpoint",
                                                                         "/oauth2/v1/authorize");

            this.logoutEndpointUri = oidcMetadata.getOidcEndpoint(collector,
                                                                  logoutEndpointUri,
                                                                  "end_session_endpoint",
                                                                  "oauth2/v1/userlogout");

            if (issuer == null) {
                oidcMetadata.getString("issuer").ifPresent(it -> issuer = it);
            }

            if ((audience == null) && (identityUri != null)) {
                this.audience = identityUri.toString();
            }

            if (useCookie && logoutEnabled) {
                if (postLogoutUri == null) {
                    collector.fatal("post-logout-uri must be defined when logout is enabled.");
                }
            }

            // second set of validations
            collector.collect().checkValid();

            if (cookieSameSiteDefault && useCookie) {
                // compare frontend and oidc endpoints to see if
                // we should use lax or strict by default
                if (identityUri != null) {
                    String identityHost = identityUri.getHost();
                    if (frontendUri != null) {
                        String frontendHost = URI.create(frontendUri).getHost();
                        if (identityHost.equals(frontendHost)) {
                            LOGGER.info("As frontend host and identity host are equal, setting Same-Site policy to Strict"
                                            + " this can be overridden using configuration option of OIDC: "
                                            + "\"cookie-same-site\"");
                            this.tokenCookieBuilder.sameSite(SetCookie.SameSite.STRICT);
                            this.idTokenCookieBuilder.sameSite(SetCookie.SameSite.STRICT);
                        }
                    }
                }
            }

            if (tokenEndpointAuthentication == ClientAuthentication.CLIENT_SECRET_BASIC) {
                HttpAuthenticationFeature basicAuth = HttpAuthenticationFeature.basicBuilder()
                        .credentials(clientId, clientSecret)
                        .build();
                clientBuilder.register(basicAuth);

                HttpBasicAuthProvider httpBasicAuth = HttpBasicAuthProvider.builder()
                        .addOutboundTarget(OutboundTarget.builder("oidc")
                                                   .addHost("*")
                                                   .customObject(HttpBasicOutboundConfig.class,
                                                                 HttpBasicOutboundConfig.create(clientId, clientSecret))
                                                   .build())
                        .build();
                Security tokenOutboundSecurity = Security.builder()
                        .addOutboundSecurityProvider(httpBasicAuth)
                        .build();

                webClientBuilder.addService(WebClientSecurity.create(tokenOutboundSecurity));
            }

            appClient = clientBuilder.build();
            appWebClient = webClientBuilder.build();
            tokenEndpoint = appClient.target(tokenEndpointUri);

            if (validateJwtWithJwk) {
                if (signJwk == null) {
                    // not configured - use default location
                    URI jwkUri = oidcMetadata.getOidcEndpoint(collector,
                                                              null,
                                                              "jwks_uri",
                                                              null);
                    if (jwkUri != null) {
                        if ("idcs".equals(serverType)) {
                            this.signJwk = IdcsSupport.signJwk(appWebClient, webClient, tokenEndpointUri, jwkUri, clientTimeout);
                        } else {
                            this.signJwk = JwkKeys.builder()
                                    .json(webClient.get()
                                                  .uri(jwkUri)
                                                  .request(JsonObject.class)
                                                  .await())
                                    .build();
                        }
                    }
                }
            } else {
                this.introspectUri = oidcMetadata.getOidcEndpoint(collector,
                                                                  introspectUri,
                                                                  "introspection_endpoint",
                                                                  "/oauth2/v1/introspect");
            }

            return new OidcConfigImpl(this);
        }

        /**
         * Update this builder with values from configuration.
         *
         * @param config configuration located on node with OIDC configuration keys (e.g. client-id)
         * @return updated builder instance
         */
        public Builder config(Config config) {
            // mandatory configuration
            config.get("client-id").asString().ifPresent(this::clientId);
            config.get("client-secret").asString().ifPresent(this::clientSecret);
            config.get("identity-uri").as(URI.class).ifPresent(this::identityUri);
            config.get("frontend-uri").asString().ifPresent(this::frontendUri);

            // environment
            config.get("proxy-protocol")
                    .asString()
                    .ifPresent(this::proxyProtocol);
            config.get("proxy-host").asString().ifPresent(this::proxyHost);
            config.get("proxy-port").asInt().ifPresent(this::proxyPort);

            // our application
            config.get("redirect-uri").asString().ifPresent(this::redirectUri);
            config.get("scope-audience").asString().ifPresent(this::scopeAudience);

            // token handling
            config.get("cookie-use").asBoolean().ifPresent(this::useCookie);
            config.get("cookie-name").asString().ifPresent(this::cookieName);
            config.get("cookie-name-id-token").asString().ifPresent(this::cookieNameIdToken);
            config.get("cookie-domain").asString().ifPresent(this::cookieDomain);
            config.get("cookie-path").asString().ifPresent(this::cookiePath);
            config.get("cookie-max-age-seconds").asLong().ifPresent(this::cookieMaxAgeSeconds);
            config.get("cookie-http-only").asBoolean().ifPresent(this::cookieHttpOnly);
            config.get("cookie-secure").asBoolean().ifPresent(this::cookieSecure);
            config.get("cookie-same-site").asString().ifPresent(this::cookieSameSite);
            config.get("query-param-use").asBoolean().ifPresent(this::useParam);
            config.get("query-param-name").asString().ifPresent(this::paramName);
            config.get("header-use").asBoolean().ifPresent(this::useHeader);
            config.get("header-token").as(TokenHandler.class).ifPresent(this::headerTokenHandler);
            // encryption of cookies
            config.get("cookie-encryption-enabled").asBoolean().ifPresent(this::cookieEncryptionEnabled);
            config.get("cookie-encryption-password").as(String.class)
                    .map(String::toCharArray)
                    .ifPresent(this::cookieEncryptionPassword);
            config.get("cookie-encryption-name").asString().ifPresent(this::cookieEncryptionName);

            // OIDC server configuration
            config.get("base-scopes").asString().ifPresent(this::baseScopes);
            config.get("oidc-metadata.resource").as(Resource::create).ifPresent(this::oidcMetadata);
            // backward compatibility
            Resource.create(config, "oidc-metadata").ifPresent(this::oidcMetadata);
            config.get("oidc-metadata-well-known").asBoolean().ifPresent(this::oidcMetadataWellKnown);
            config.get("sign-jwk.resource").as(Resource::create).ifPresent(this::signJwk);
            Resource.create(config, "sign-jwk").ifPresent(this::signJwk);
            config.get("token-endpoint-uri").as(URI.class).ifPresent(this::tokenEndpointUri);
            config.get("token-endpoint-auth").asString()
                    .map(String::toUpperCase)
                    .map(ClientAuthentication::valueOf)
                    .ifPresent(this::tokenEndpointAuthentication);
            config.get("authorization-endpoint-uri").as(URI.class).ifPresent(this::authorizationEndpointUri);
            config.get("logout-endpoint-uri").as(URI.class).ifPresent(this::logoutEndpointUri);
            config.get("post-logout-uri").as(URI.class).ifPresent(this::postLogoutUri);
            config.get("logout-enabled").asBoolean().ifPresent(this::logoutEnabled);

            config.get("introspect-endpoint-uri").as(URI.class).ifPresent(this::introspectEndpointUri);
            config.get("validate-with-jwk").asBoolean().ifPresent(this::validateJwtWithJwk);
            config.get("issuer").asString().ifPresent(this::issuer);
            config.get("audience").asString().ifPresent(this::audience);

            config.get("redirect").asBoolean().ifPresent(this::redirect);
            config.get("redirect-attempt-param").asString().ifPresent(this::redirectAttemptParam);
            config.get("max-redirects").asInt().ifPresent(this::maxRedirects);
            config.get("force-https-redirects").asBoolean().ifPresent(this::forceHttpsRedirects);

            // type of the identity server
            // now uses hardcoded switch - should change to service loader eventually
            config.get("server-type").asString().ifPresent(this::serverType);

            config.get("client-timeout-millis").asLong().ifPresent(this::clientTimeoutMillis);

            config.get("cors").as(CrossOriginConfig::create).ifPresent(this::crossOriginConfig);

            config.get("token-refresh-before-expiration").as(Duration.class).ifPresent(this::tokenRefreshSkew);

            return this;
        }

        /**
         * Amount of time access token should be refreshed before its expiration time.
         * Default is 5 seconds.
         *
         * @param tokenRefreshSkew time to refresh token before expiration
         * @return updated builder
         */
        public Builder tokenRefreshSkew(Duration tokenRefreshSkew) {
            this.tokenRefreshSkew = tokenRefreshSkew;
            return this;
        }

        /**
         * Name of the encryption configuration available through {@link Security#encrypt(String, byte[])} and
         * {@link Security#decrypt(String, String)}.
         * If configured and encryption is enabled for any cookie,
         * Security MUST be configured in global or current {@code io.helidon.common.context.Context} (this
         * is done automatically in Helidon MP).
         *
         * @param cookieEncryptionName name of the encryption configuration in security used to encrypt/decrypt cookies
         * @return updated builder
         */
        public Builder cookieEncryptionName(String cookieEncryptionName) {
            this.tokenCookieBuilder.encryptionName(cookieEncryptionName);
            this.idTokenCookieBuilder.encryptionName(cookieEncryptionName);
            return this;
        }

        /**
         * Master password for encryption/decryption of cookies. This must be configured to the same value on each microservice
         * using the cookie.
         *
         * @param cookieEncryptionPassword encryption password
         * @return updated builder
         */
        public Builder cookieEncryptionPassword(char[] cookieEncryptionPassword) {
            this.tokenCookieBuilder.encryptionPassword(cookieEncryptionPassword);
            this.idTokenCookieBuilder.encryptionPassword(cookieEncryptionPassword);

            return this;
        }

        /**
         * Whether to encrypt token cookie created by this microservice.
         * Defaults to {@code false}.
         *
         * @param cookieEncryptionEnabled whether cookie should be encrypted {@code true}, or as obtained from
         *                                OIDC server {@code false}
         * @return updated builder instance
         */
        public Builder cookieEncryptionEnabled(boolean cookieEncryptionEnabled) {
            this.tokenCookieBuilder.encryptionEnabled(cookieEncryptionEnabled);
            return this;
        }

        /**
         * Whether to encrypt id token cookie created by this microservice.
         * Defaults to {@code true}.
         *
         * @param cookieEncryptionEnabled whether cookie should be encrypted {@code true}, or as obtained from
         *                                OIDC server {@code false}
         * @return updated builder instance
         */
        public Builder cookieEncryptionEnabledIdToken(boolean cookieEncryptionEnabled) {
            this.idTokenCookieBuilder.encryptionEnabled(cookieEncryptionEnabled);
            return this;
        }

        /**
         * Assign cross-origin resource sharing settings.
         *
         * @param crossOriginConfig cross-origin settings to apply to the redirect endpoint
         * @return updated builder instance
         */
        public Builder crossOriginConfig(CrossOriginConfig crossOriginConfig) {
            this.crossOriginConfig = crossOriginConfig;
            return this;
        }

        /**
         * Whether to enable logout support.
         * When logout is enabled, we use two cookies (User token and user ID token) and we expose
         * an endpoint {@link #logoutUri(String)} that can be used to log the user out from Helidon session
         * and also from OIDC session (uses {@link #logoutEndpointUri(URI)} on OIDC server).
         * Logout support is disabled by default.
         *
         * @param logoutEnabled whether to enable logout
         * @return updated builder instance
         */
        public Builder logoutEnabled(Boolean logoutEnabled) {
            this.logoutEnabled = logoutEnabled;
            return this;
        }

        /**
         * By default the client should redirect to the identity server for the user to log in.
         * This behavior can be overridden by setting redirect to false. When token is not present in the request, the client
         * will not redirect and just return appropriate error response code.
         *
         * @param redirect Whether to redirect to OIDC server in case the request does not contain sufficient information to
         *                 authenticate the user, defaults to true
         * @return updated builder instance
         */
        @ConfiguredOption("true")
        public Builder redirect(boolean redirect) {
            this.redirect = redirect;
            return this;
        }

        /**
         * Realm to return when not redirecting and an error occurs that sends back WWW-Authenticate header.
         *
         * @param realm realm name
         * @return updated builder instance
         */
        public Builder realm(String realm) {
            this.realm = realm;
            return this;
        }

        /**
         * Audience of issued tokens.
         *
         * @param audience audience to validate
         * @return updated builder instance
         */
        @ConfiguredOption
        public Builder audience(String audience) {
            this.audience = audience;
            return this;
        }

        /**
         * Issuer of issued tokens.
         *
         * @param issuer expected issuer to validate
         * @return updated builder instance
         */
        @ConfiguredOption
        public Builder issuer(String issuer) {
            this.issuer = issuer;
            return this;
        }

        /**
         * Use JWK (a set of keys to validate signatures of JWT) to validate tokens.
         * Use this method when you want to use default values for JWK or introspection endpoint URI.
         *
         * @param useJwk when set to true, jwk is used, when set to false, introspect endpoint is used
         * @return updated builder instance
         */
        @ConfiguredOption("true")
        public Builder validateJwtWithJwk(Boolean useJwk) {
            this.validateJwtWithJwk = useJwk;
            return this;
        }

        /**
         * Endpoint to use to validate JWT.
         * Either use this or set {@link #signJwk(JwkKeys)} or {@link #signJwk(Resource)}.
         *
         * @param uri URI of introspection endpoint
         * @return updated builder instance
         */
        @ConfiguredOption
        public Builder introspectEndpointUri(URI uri) {
            validateJwtWithJwk(false);
            this.introspectUri = uri;
            return this;
        }

        /**
         * Configure base scopes.
         * By default this is {@value DEFAULT_BASE_SCOPES}.
         * If scope has a qualifier, it must be used here.
         *
         * @param scopes Space separated scopes to be required by default from OIDC server
         * @return updated builder instance
         */
        @ConfiguredOption(value = DEFAULT_BASE_SCOPES)
        public Builder baseScopes(String scopes) {
            this.baseScopes = scopes;
            return this;
        }

        /**
         * If set to true, metadata will be loaded from default (well known)
         * location, unless it is explicitly defined using oidc-metadata-resource. If set to false, it would not be loaded
         * even if oidc-metadata-resource is not defined. In such a case all URIs must be explicitly defined (e.g.
         * token-endpoint-uri).
         *
         * @param useWellKnown whether to use well known location for OIDC metadata
         * @return updated builder instance
         */
        @ConfiguredOption("true")
        public Builder oidcMetadataWellKnown(Boolean useWellKnown) {
            this.oidcMetadataWellKnown = useWellKnown;
            return this;
        }

        /**
         * A resource pointing to JWK with public keys of signing certificates used
         * to validate JWT.
         *
         * @param resource Resource pointing to the JWK
         * @return updated builder instance
         */
        @ConfiguredOption(key = "sign-jwk.resource")
        public Builder signJwk(Resource resource) {
            validateJwtWithJwk(true);
            this.signJwk = JwkKeys.builder().resource(resource).build();
            return this;
        }

        /**
         * Set {@link JwkKeys} to use for JWT validation.
         *
         * @param jwk JwkKeys instance to get public keys used to sign JWT
         * @return updated builder instance
         */
        public Builder signJwk(JwkKeys jwk) {
            validateJwtWithJwk(true);
            this.signJwk = jwk;
            return this;
        }

        /**
         * Resource configuration for OIDC Metadata
         * containing endpoints to various identity services, as well as information about the identity server.
         *
         * @param resource resource pointing to the JSON structure
         * @return updated builder instance
         */
        @ConfiguredOption(key = "oidc-metadata.resource")
        public Builder oidcMetadata(Resource resource) {
            this.oidcMetadata.json(JSON.createReader(resource.stream()).readObject());
            return this;
        }

        /**
         * JsonObject with the OIDC Metadata.
         *
         * @param metadata metadata JSON
         * @return updated builder instance
         * @see #oidcMetadata(Resource)
         */
        public Builder oidcMetadata(JsonObject metadata) {
            this.oidcMetadata.json(metadata);
            return this;
        }

        /**
         * A {@link TokenHandler} to
         * process header containing a JWT.
         * Default is "Authorization" header with a prefix "bearer ".
         *
         * @param tokenHandler token handler to use
         * @return updated builder instance
         */
        @ConfiguredOption(key = "header-token")
        public Builder headerTokenHandler(TokenHandler tokenHandler) {
            this.headerHandler = tokenHandler;
            return this;
        }

        /**
         * Whether to expect JWT in a header field.
         *
         * @param useHeader set to true to use a header extracted with {@link #headerTokenHandler(TokenHandler)}
         * @return updated builder instance
         */
        @ConfiguredOption(key = "header-use", value = "false")
        public Builder useHeader(Boolean useHeader) {
            this.useHeader = useHeader;
            return this;
        }

        /**
         * Audience of the scope required by this application. This is prefixed to
         * the scope name when requesting scopes from the identity server.
         * Defaults to empty string.
         *
         * @param audience audience, if provided, end with "/" to append the scope correctly
         * @return updated builder instance
         */
        @ConfiguredOption
        public Builder scopeAudience(String audience) {
            this.scopeAudience = audience;
            return this;
        }

        /**
         * When using cookie, used to set the SameSite cookie value. Can be
         * "Strict" or "Lax"
         *
         * @param sameSite SameSite cookie attribute value
         * @return updated builder instance
         */
        public Builder cookieSameSite(String sameSite) {
            return cookieSameSite(SetCookie.SameSite.valueOf(sameSite.toUpperCase(Locale.ROOT)));
        }

        /**
         * When using cookie, used to set the SameSite cookie value. Can be
         * "Strict" or "Lax".
         *
         * @param sameSite SameSite cookie attribute
         * @return updated builder instance
         */
        @ConfiguredOption(value = "LAX")
        public Builder cookieSameSite(SetCookie.SameSite sameSite) {
            this.tokenCookieBuilder.sameSite(sameSite);
            this.idTokenCookieBuilder.sameSite(sameSite);
            this.cookieSameSiteDefault = false;
            return this;
        }

        /**
         * When using cookie, if set to true, the Secure attribute will be configured.
         * Defaults to false.
         *
         * @param secure whether the cookie should be secure (true) or not (false)
         * @return updated builder instance
         */
        @ConfiguredOption("false")
        public Builder cookieSecure(Boolean secure) {
            this.tokenCookieBuilder.secure(secure);
            this.idTokenCookieBuilder.secure(secure);
            return this;
        }

        /**
         * When using cookie, if set to true, the HttpOnly attribute will be configured.
         * Defaults to {@value OidcCookieHandler.Builder#DEFAULT_HTTP_ONLY}.
         *
         * @param httpOnly whether the cookie should be HttpOnly (true) or not (false)
         * @return updated builder instance
         */
        @ConfiguredOption("true")
        public Builder cookieHttpOnly(Boolean httpOnly) {
            this.tokenCookieBuilder.httpOnly(httpOnly);
            this.idTokenCookieBuilder.httpOnly(httpOnly);
            return this;
        }

        /**
         * When using cookie, used to set MaxAge attribute of the cookie, defining how long
         * the cookie is valid.
         * Not used by default.
         *
         * @param age age in seconds
         * @return updated builder instance
         */
        @ConfiguredOption
        public Builder cookieMaxAgeSeconds(long age) {
            this.tokenCookieBuilder.maxAge(age);
            this.idTokenCookieBuilder.maxAge(age);
            return this;
        }

        /**
         * Path the cookie is valid for.
         * Defaults to "/".
         *
         * @param path the path to use as value of cookie "Path" attribute
         * @return updated builder instance
         */
        @ConfiguredOption(value = OidcCookieHandler.Builder.DEFAULT_PATH)
        public Builder cookiePath(String path) {
            this.tokenCookieBuilder.path(path);
            this.idTokenCookieBuilder.path(path);
            return this;
        }

        /**
         * Domain the cookie is valid for.
         * Not used by default.
         *
         * @param domain domain to use as value of cookie "Domain" attribute
         * @return updated builder instance
         */
        @ConfiguredOption
        public Builder cookieDomain(String domain) {
            this.tokenCookieBuilder.domain(domain);
            this.idTokenCookieBuilder.domain(domain);
            return this;
        }

        /**
         * Full URI of this application that is visible from user browser.
         * Used to redirect request back from identity server after successful login.
         *
         * @param uri the frontend URI, such as "http://my.server.com/myApp
         * @return updated builder instance
         */
        @ConfiguredOption
        public Builder frontendUri(String uri) {
            this.frontendUri = uri;
            return this;
        }

        /**
         * URI of a token endpoint used to obtain a JWT based on the authentication
         * code.
         * If not defined, it is obtained from {@link #oidcMetadata(Resource)}, if that is not defined
         * an attempt is made to use {@link #identityUri(URI)}/oauth2/v1/token.
         *
         * @param uri URI to use for token endpoint
         * @return updated builder instance
         */
        @ConfiguredOption
        public Builder tokenEndpointUri(URI uri) {
            this.tokenEndpointUri = uri;
            return this;
        }

        /**
         * Type of authentication to use when invoking the token endpoint.
         * Current supported options:
         * <ul>
         *     <li>{@link ClientAuthentication#CLIENT_SECRET_BASIC}</li>
         *     <li>{@link ClientAuthentication#CLIENT_SECRET_POST}</li>
         *     <li>{@link ClientAuthentication#NONE}</li>
         * </ul>
         *
         * @param tokenEndpointAuthentication authentication type
         * @return updated builder
         */
        @ConfiguredOption(key = "token-endpoint-auth", value = "CLIENT_SECRET_BASIC")
        public Builder tokenEndpointAuthentication(ClientAuthentication tokenEndpointAuthentication) {

            switch (tokenEndpointAuthentication) {
            case CLIENT_SECRET_BASIC:
            case CLIENT_SECRET_POST:
            case NONE:
                break;
            default:
                throw new IllegalArgumentException("Token endpoint authentication type " + tokenEndpointAuthentication
                                                           + " is not supported.");
            }
            this.tokenEndpointAuthentication = tokenEndpointAuthentication;
            return this;
        }

        /**
         * URI of an authorization endpoint used to redirect users to for logging-in.
         *
         * If not defined, it is obtained from {@link #oidcMetadata(Resource)}, if that is not defined
         * an attempt is made to use {@link #identityUri(URI)}/oauth2/v1/authorize.
         *
         * @param uri URI to use for token endpoint
         * @return updated builder instance
         */
        @ConfiguredOption
        public Builder authorizationEndpointUri(URI uri) {
            this.authorizationEndpointUri = uri;
            return this;
        }

        /**
         * URI of a logout endpoint used to redirect users to for logging-out.
         * If not defined, it is obtained from {@link #oidcMetadata(Resource)}, if that is not defined
         * an attempt is made to use {@link #identityUri(URI)}/oauth2/v1/userlogout.
         *
         * @param logoutEndpointUri URI to use to log out
         * @return updated builder instance
         */
        public Builder logoutEndpointUri(URI logoutEndpointUri) {
            this.logoutEndpointUri = logoutEndpointUri;
            return this;
        }

        /**
         * Name of the cookie to use.
         * Defaults to {@value #DEFAULT_COOKIE_NAME}.
         *
         * @param cookieName name of a cookie
         * @return updated builder instance
         */
        @ConfiguredOption(value = DEFAULT_COOKIE_NAME)
        public Builder cookieName(String cookieName) {
            this.tokenCookieBuilder.cookieName(cookieName);
            return this;
        }

        /**
         * Name of the cookie to use for id token.
         * Defaults to {@value #DEFAULT_COOKIE_NAME}_2.
         *
         * This cookie is only used when logout is enabled, as otherwise it is not needed.
         * Content of this cookie is encrypted.
         *
         * @param cookieName name of a cookie
         * @return updated builder instance
         */
        public Builder cookieNameIdToken(String cookieName) {
            this.idTokenCookieBuilder.cookieName(cookieName);
            return this;
        }

        /**
         * Whether to use cookie to store JWT between requests.
         * Defaults to {@value #DEFAULT_COOKIE_USE}.
         *
         * @param useCookie whether to use cookie to store JWT (true) or not (false))
         * @return updated builder instance
         */
        @ConfiguredOption(key = "cookie-use", value = "true")
        public Builder useCookie(Boolean useCookie) {
            this.useCookie = useCookie;
            return this;
        }

        /**
         * Force HTTPS for redirects to identity provider.
         * Defaults to {@code false}.
         *
         * @param forceHttpsRedirects flag to redirect with https
         * @return updated builder instance
         */
        @ConfiguredOption("false")
        public Builder forceHttpsRedirects(boolean forceHttpsRedirects) {
            this.forceHttpsRedirects = forceHttpsRedirects;
            return this;
        }

        /**
         * Name of a query parameter that contains the JWT token when parameter is used.
         *
         * @param paramName name of the query parameter to expect
         * @return updated builder instance
         */
        @ConfiguredOption(key = "query-param-name", value = DEFAULT_PARAM_NAME)
        public Builder paramName(String paramName) {
            this.paramName = paramName;
            return this;
        }

        /**
         * Whether to use a query parameter to send JWT token from application to this
         * server.
         *
         * @param useParam whether to use a query parameter (true) or not (false)
         * @return updated builder instance
         * @see #paramName(String)
         */
        @ConfiguredOption(key = "query-param-use", value = "false")
        public Builder useParam(Boolean useParam) {
            this.useParam = useParam;
            return this;
        }

        /**
         * URI of the identity server, base used to retrieve OIDC metadata.
         *
         * @param uri full URI of an identity server (such as "http://tenantid.identity.oraclecloud.com")
         * @return updated builder instance
         */
        @ConfiguredOption
        public Builder identityUri(URI uri) {
            this.identityUri = uri;
            return this;
        }

        /**
         * Proxy protocol to use when proxy is used.
         * Defaults to {@value #DEFAULT_PROXY_PROTOCOL}.
         *
         * @param protocol protocol to use (such as https)
         * @return updated builder instance
         */
        @ConfiguredOption(value = DEFAULT_PROXY_PROTOCOL)
        public Builder proxyProtocol(String protocol) {
            this.proxyProtocol = protocol;
            return this;
        }

        /**
         * Proxy host to use. When defined, triggers usage of proxy for HTTP requests.
         * Setting to empty String has the same meaning as setting to null - disables proxy.
         *
         * @param proxyHost host of the proxy
         * @return updated builder instance
         * @see #proxyProtocol(String)
         * @see #proxyPort(int)
         */
        @ConfiguredOption
        public Builder proxyHost(String proxyHost) {
            if ((proxyHost == null) || proxyHost.isEmpty()) {
                this.proxyHost = null;
            } else {
                this.proxyHost = proxyHost;
            }
            return this;
        }

        /**
         * Proxy port.
         * Defaults to {@value #DEFAULT_PROXY_PORT}
         *
         * @param proxyPort port of the proxy server to use
         * @return updated builder instance
         */
        @ConfiguredOption("80")
        public Builder proxyPort(int proxyPort) {
            this.proxyPort = proxyPort;
            return this;
        }

        /**
         * Client ID as generated by OIDC server.
         *
         * @param clientId the client id of this application.
         * @return updated builder instance
         */
        @ConfiguredOption
        public Builder clientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        /**
         * Client secret as generated by OIDC server.
         * Used to authenticate this application with the server when requesting
         * JWT based on a code.
         *
         * @param clientSecret secret to use
         * @return updated builder instance
         */
        @ConfiguredOption
        public Builder clientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
            return this;
        }

        /**
         * URI to register web server component on, used by the OIDC server to
         * redirect authorization requests to after a user logs in or approves
         * scopes.
         * Note that usually the redirect URI configured here must be the
         * same one as configured on OIDC server.
         *
         * <p>
         * Defaults to {@value #DEFAULT_REDIRECT_URI}
         *
         * @param redirectUri the URI (path without protocol, host and port) used to redirect requests back to us
         * @return updated builder instance
         */
        @ConfiguredOption(value = DEFAULT_REDIRECT_URI)
        public Builder redirectUri(String redirectUri) {
            this.redirectUri = redirectUri;
            return this;
        }

        /**
         * Path to register web server for logout link.
         * This should be used by application to redirect user to logout the current user
         * from Helidon based session (when using cookies and redirection).
         * This endpoint will logout user from Helidon session (remove Helidon cookies) and redirect user to
         * logout screen of the OIDC server.
         *
         * @param logoutUri URI path for logout component
         * @return updated builder instance
         */
        public Builder logoutUri(String logoutUri) {
            this.logoutUri = logoutUri;
            return this;
        }

        /**
         * URI to redirect to once the logout process is done.
         * The endpoint should not be protected by OIDC (as this would serve no purpose, just to log the user in again).
         * This endpoint usually must be registered with the application as the allowed post-logout redirect URI.
         * Note that the URI should not contain any query parameters. You can obtain state using the
         * state query parameter that must be provided to {@link #logoutUri(String)}.
         *
         * @param uri this will be used by the OIDC server to redirect user to once logout is done, can define just path,
         *            in which case the scheme, host and port will be taken from request.
         * @return updated builder instance
         */
        public Builder postLogoutUri(URI uri) {
            this.postLogoutUri = uri;
            return this;
        }

        /**
         * Configure the parameter used to store the number of attempts in redirect.
         * <p>
         * Defaults to {@value #DEFAULT_ATTEMPT_PARAM}
         *
         * @param paramName name of the parameter used in the state parameter
         * @return updated builder instance
         */
        @ConfiguredOption(value = DEFAULT_ATTEMPT_PARAM)
        public Builder redirectAttemptParam(String paramName) {
            this.redirectAttemptParam = paramName;
            return this;
        }

        /**
         * Configure maximal number of redirects when redirecting to an OIDC provider within a single authentication
         * attempt.
         * <p>
         * Defaults to {@value #DEFAULT_MAX_REDIRECTS}
         *
         * @param maxRedirects maximal number of redirects from Helidon to OIDC provider
         * @return updated builder instance
         */
        @ConfiguredOption("5")
        public Builder maxRedirects(int maxRedirects) {
            this.maxRedirects = maxRedirects;
            return this;
        }

        /**
         * Configure one of the supported types of identity servers.
         *
         * If the type does not have an explicit mapping, a warning is logged and the default implementation is used.
         *
         * @param type Type of identity server. Currently supported is {@code idcs} or not configured (for default).
         * @return updated builder instance
         */
        @ConfiguredOption(value = DEFAULT_SERVER_TYPE)
        public Builder serverType(String type) {
            this.serverType = type;
            return this;
        }

        /**
         * Timeout of calls using web client.
         *
         * @param duration timeout
         * @return updated builder
         */
        @ConfiguredOption(key = "client-timeout-millis", value = "30000")
        public Builder clientTimeout(Duration duration) {
            this.clientTimeout = duration;
            return this;
        }

        private void clientTimeoutMillis(long millis) {
            this.clientTimeout(Duration.ofMillis(millis));
        }
    }
}
