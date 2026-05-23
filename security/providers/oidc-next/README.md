# OIDC Provider User Guide

This document describes the current `oidc-next` security provider implementation.

The provider is tenant based. Even a single-tenant application configures one tenant under `tenants`, but when exactly
one tenant is configured the provider automatically uses it as the default tenant.

## Supported Use Cases

The current implementation supports:

- Protected Resource Bearer Token authentication.
- Access-token validation by local JWT validation against an explicit JWKS URI or a JWKS URI from well-known metadata.
- Access-token validation by OAuth 2.0 Token Introspection.
- OpenID Connect Authorization Code Flow.
- PKCE with `S256`, enabled by default.
- Token Endpoint exchange using Helidon WebClient.
- Token Endpoint client authentication with `CLIENT_SECRET_BASIC`, `CLIENT_SECRET_POST`, or `NONE`.
- ID Token validation for Authorization Code Flow.
- Local authentication result storage in protected cookies.
- Local OIDC logout endpoint that removes OIDC cookies.
- RP-Initiated Logout redirect to the OpenID Provider End Session Endpoint.
- Refresh-token based local authentication renewal.
- Validation of refreshed access tokens when token validation is configured.
- Validation of refreshed ID Tokens when the Token Endpoint returns a new ID Token.
- Optional UserInfo requests for Authorization Code Flow with exact `sub` matching before claim merge.
- Configurable subject mapping for principal id, principal name, roles, and scope grants.
- Tenant WebClient configuration for OpenID Provider and Authorization Server requests.
- Multi-tenant selection by default tenant, header, path segment, path template, or host template.
- Outbound Token Propagation to configured outbound targets.
- Outbound Client Credentials Grant token acquisition and caching.

The current implementation does not yet support:

- Provider profiles or flow-step customizer SPI.
- DPoP, mTLS sender-constrained tokens, or token binding.
- Signed or encrypted JWT UserInfo responses. UserInfo responses must be JSON objects.
- Loading the introspection endpoint URI from well-known metadata for Protected Resource introspection. Configure
  `endpoints.introspection-endpoint-uri` explicitly.
- Refresh single-flight coordination for refresh-token rotation races.

## Configuration Shape

The provider config key is `oidc-next`.

```yaml
security:
  providers:
    - oidc-next:
        tenants:
          main:
            issuer: "https://issuer.example"
```

For a single tenant, `default-tenant` is optional. The only configured tenant is selected automatically.
`protected-resource` and `authorization-code` are not configured by default. Adding either block enables that part of the
provider unless the block explicitly sets `enabled: false`.

```yaml
security:
  providers:
    - oidc-next:
        tenants:
          main:
            issuer: "https://issuer.example"
            endpoints:
              jwks-uri: "https://issuer.example/jwks"
            protected-resource:
              token-validation:
                method: JWT
                audience: "api://orders"
```

For multiple tenants, configure `default-tenant` or tenant resolution.

```yaml
security:
  providers:
    - oidc-next:
        default-tenant: tenant-a
        tenants:
          tenant-a:
            issuer: "https://issuer-a.example"
          tenant-b:
            issuer: "https://issuer-b.example"
```

## Programmatic Configuration

All configuration options are also available through generated builders.

Common imports used by the examples:

```java
import java.net.URI;
import java.time.Duration;
import java.util.List;

import io.helidon.security.Security;
import io.helidon.security.providers.common.OutboundTarget;
import io.helidon.security.providers.oidc.next.OidcClientAuthenticationMethod;
import io.helidon.security.providers.oidc.next.OidcFeature;
import io.helidon.security.providers.oidc.next.OidcOutboundTargetConfig;
import io.helidon.security.providers.oidc.next.OidcProvider;
import io.helidon.security.providers.oidc.next.OidcProviderConfig;
import io.helidon.security.providers.oidc.next.OidcTenantConfig;
import io.helidon.security.providers.oidc.next.OidcTokenValidationMethod;
import io.helidon.webclient.api.Proxy;
import io.helidon.webclient.api.WebClientConfig;
import io.helidon.webserver.WebServer;
import io.helidon.webserver.security.SecurityFeature;
```

Create a JWT Protected Resource provider:

```java
OidcProviderConfig config = OidcProviderConfig.builder()
        .putTenant("main", OidcTenantConfig.builder()
                .issuer(URI.create("https://issuer.example"))
                .endpoints(endpoints -> endpoints
                        .jwksUri(URI.create("https://issuer.example/jwks")))
                .protectedResource(protectedResource -> protectedResource
                        .tokenValidation(tokenValidation -> tokenValidation
                                .method(OidcTokenValidationMethod.JWT)
                                .audience("api://orders")
                                .allowedAlgorithms(List.of("RS256"))))
                .buildPrototype())
        .buildPrototype();

OidcProvider provider = OidcProvider.create(config);
```

Create an introspection Protected Resource provider:

```java
OidcProviderConfig config = OidcProviderConfig.builder()
        .putTenant("main", OidcTenantConfig.builder()
                .issuer(URI.create("https://issuer.example"))
                .clientId(System.getenv("OIDC_CLIENT_ID"))
                .clientSecret(System.getenv("OIDC_CLIENT_SECRET"))
                .endpoints(endpoints -> endpoints
                        .introspectionEndpointUri(URI.create("https://issuer.example/oauth2/introspect")))
                .protectedResource(protectedResource -> protectedResource
                        .tokenValidation(tokenValidation -> tokenValidation
                                .method(OidcTokenValidationMethod.INTROSPECTION)
                                .audience("api://orders")))
                .buildPrototype())
        .buildPrototype();

OidcProvider provider = OidcProvider.create(config);
```

Create an Authorization Code Flow provider:

```java
OidcProviderConfig config = OidcProviderConfig.builder()
        .putTenant("web", OidcTenantConfig.builder()
                .issuer(URI.create("https://issuer.example"))
                .clientId(System.getenv("OIDC_CLIENT_ID"))
                .clientSecret(System.getenv("OIDC_CLIENT_SECRET"))
                .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationCode(authorizationCode -> authorizationCode
                        .redirectionEndpointUri(URI.create("https://app.example/oidc/callback"))
                        .scopes(List.of("openid", "profile", "email")))
                .logout(logout -> logout
                        .localEndpointUri(URI.create("/oidc/logout")))
                .cookies(cookies -> cookies
                        .encryptionSecret(System.getenv("OIDC_COOKIE_SECRET")))
                .buildPrototype())
        .buildPrototype();

OidcProvider provider = OidcProvider.create(config);
```

When Authorization Code Flow or logout is enabled, register `OidcFeature` with WebServer routing so the local routes are
installed:

```java
OidcProviderConfig config = OidcProviderConfig.builder()
        .putTenant("web", OidcTenantConfig.builder()
                .issuer(URI.create("https://issuer.example"))
                .clientId(System.getenv("OIDC_CLIENT_ID"))
                .clientSecret(System.getenv("OIDC_CLIENT_SECRET"))
                .authorizationCode(authorizationCode -> authorizationCode
                        .redirectionEndpointUri(URI.create("https://app.example/oidc/callback"))
                        .scopes(List.of("openid", "profile")))
                .logout(logout -> logout
                        .localEndpointUri(URI.create("/oidc/logout")))
                .cookies(cookies -> cookies
                        .encryptionSecret(System.getenv("OIDC_COOKIE_SECRET")))
                .buildPrototype())
        .buildPrototype();

Security security = Security.builder()
        .addProvider(OidcProvider.create(config), config.providerName())
        .build();

WebServer.builder()
        .addFeature(SecurityFeature.builder()
                .security(security)
                .build())
        .routing(routing -> routing.addFeature(OidcFeature.create(config)))
        .build();
```

Programmatic subject mapping uses the same claim path names as YAML:

```java
OidcTenantConfig tenant = OidcTenantConfig.builder()
        .issuer(URI.create("https://issuer.example"))
        .endpoints(endpoints -> endpoints
                .jwksUri(URI.create("https://issuer.example/jwks")))
        .protectedResource(protectedResource -> protectedResource
                .tokenValidation(tokenValidation -> tokenValidation
                        .method(OidcTokenValidationMethod.JWT)
                        .audience("api://orders")))
        .subjectMapping(subjectMapping -> subjectMapping
                .principalIdClaimPaths(List.of("sub"))
                .principalNameClaimPaths(List.of("preferred_username", "email"))
                .roleClaimPaths(List.of("realm_access.roles", "groups"))
                .scopeClaimPaths(List.of("scope", "scp"))
                .scopeGrantsEnabled(true))
        .buildPrototype();
```

## WebClient Configuration

Each tenant has one `webclient` configuration used for outbound requests to the OpenID Provider or Authorization Server:
well-known metadata requests, JWKS loading, Token Endpoint requests, introspection, and UserInfo requests.

```yaml
security:
  providers:
    - oidc-next:
        tenants:
          main:
            issuer: "https://issuer.example"
            webclient:
              connect-timeout: "PT3S"
              read-timeout: "PT10S"
              proxy:
                type: HTTP
                host: "proxy.example.com"
                port: 8080
              tls:
                protocols: [ "TLSv1.3" ]
                cipher-suite: [ "TLS_AES_128_GCM_SHA256" ]
```

Use this for HTTP client behavior such as proxy, no-proxy, private trust material, mTLS, TLS protocols/ciphers, DNS,
keep-alive, and timeouts. When no WebClient read timeout is configured, OIDC uses a 10 second read timeout for its
tenant WebClient.

Token Endpoint requests, introspection requests, and UserInfo requests disable redirect following per request because
those requests carry client credentials or access tokens. This remains true even if `webclient.follow-redirects` is
enabled.

Programmatic WebClient configuration:

```java
OidcTenantConfig tenant = OidcTenantConfig.builder()
        .issuer(URI.create("https://issuer.example"))
        .webClient(WebClientConfig.builder()
                .connectTimeout(Duration.ofSeconds(3))
                .readTimeout(Duration.ofSeconds(10))
                .proxy(Proxy.builder()
                        .type(Proxy.ProxyType.HTTP)
                        .host("proxy.example.com")
                        .port(8080)
                        .build())
                .buildPrototype())
        .buildPrototype();
```

## Endpoint Configuration

`endpoints` contains OpenID Provider or Authorization Server endpoints.

```yaml
endpoints:
  well-known-uri: "https://issuer.example/.well-known/openid-configuration"
  authorization-endpoint-uri: "https://issuer.example/authorize"
  token-endpoint-uri: "https://issuer.example/token"
  jwks-uri: "https://issuer.example/jwks"
  introspection-endpoint-uri: "https://issuer.example/oauth2/introspect"
  user-info-endpoint-uri: "https://issuer.example/userinfo"
  end-session-endpoint-uri: "https://issuer.example/logout"
```

`user-info-endpoint-uri` and `end-session-endpoint-uri` can be loaded from well-known metadata. UserInfo can use
`user-info-endpoint-uri` directly or load `userinfo_endpoint` from well-known metadata. RP-Initiated Logout can use
`end-session-endpoint-uri` directly or load `end_session_endpoint` from well-known metadata.
`user-info-endpoint-uri` must use HTTPS unless `endpoints.tls-required` is disabled, and must not contain a fragment.
`end-session-endpoint-uri` must use HTTPS unless `endpoints.tls-required` is disabled, and must not contain a fragment.

If `issuer` is configured and `endpoints.well-known-uri` is omitted, the provider derives the well-known URI by appending
`/.well-known/openid-configuration` to the issuer URI after removing trailing `/` characters.

Well-known metadata is used by Authorization Code Flow when provider endpoint URIs are missing, by Client Credentials
Grant when `endpoints.token-endpoint-uri` is not configured, and by Protected Resource JWT validation when
`endpoints.jwks-uri` is not configured. It is also used by RP-Initiated Logout when `endpoints.end-session-endpoint-uri`
is not configured, and by UserInfo when `endpoints.user-info-endpoint-uri` is not configured. It can provide
`authorization_endpoint`, `token_endpoint`, `jwks_uri`, `userinfo_endpoint`, and `end_session_endpoint`.
When Authorization Code Flow is configured with explicit Authorization and Token Endpoint URIs instead of loading
well-known metadata, configure `endpoints.jwks-uri` as well so ID Token signatures can be verified.

Protected Resource introspection still requires explicit `endpoints.introspection-endpoint-uri`.

`authorization-code.redirection-endpoint-uri` is not under `endpoints` because it is the client callback endpoint, not
an OpenID Provider endpoint.

## Protected Resource With JWT Validation

Use `method: JWT` to validate Bearer access tokens locally as signed JWTs against configured JWKS material.

```yaml
security:
  providers:
    - oidc-next:
        tenants:
          main:
            issuer: "https://issuer.example"
            endpoints:
              jwks-uri: "https://issuer.example/jwks"
            protected-resource:
              token-validation:
                method: JWT
                audience: "api://orders"
                allowed-algorithms: [ "RS256" ]
                clock-skew: "PT1M"
```

`issuer` or `endpoints.well-known-uri` is required. `endpoints.jwks-uri` can be configured explicitly; otherwise the
provider loads well-known metadata and uses its `jwks_uri`. `audience` is required when audience validation is enabled.

Audience validation is enabled by default. Disable it only when the deployment intentionally accepts tokens without a
local audience check.

```yaml
protected-resource:
  token-validation:
    method: JWT
    audience-validation-enabled: false
```

## Protected Resource With Introspection

Use `method: INTROSPECTION` for opaque tokens or when the Authorization Server is responsible for access-token
validation.

```yaml
security:
  providers:
    - oidc-next:
        tenants:
          main:
            issuer: "https://issuer.example"
            client-id: "${OIDC_CLIENT_ID}"
            client-secret: "${OIDC_CLIENT_SECRET}"
            endpoints:
              introspection-endpoint-uri: "https://issuer.example/oauth2/introspect"
            protected-resource:
              token-validation:
                method: INTROSPECTION
                audience: "api://orders"
```

Introspection currently uses HTTP Basic client authentication and requires `client-id`, `client-secret`, and
`endpoints.introspection-endpoint-uri`.

Audience validation is enabled by default. Introspection responses with an `aud` claim must contain the configured
expected audience. If the Authorization Server omits `aud` from introspection responses, disable audience validation
explicitly.

```yaml
protected-resource:
  token-validation:
    method: INTROSPECTION
    audience-validation-enabled: false
```

## Bearer Token Transport

The provider accepts Bearer tokens from the `Authorization` header by default.

```yaml
token-transport:
  authorization-header-enabled: true
  query-parameter-enabled: false
```

Enable query parameter transport only for compatibility cases that require it.

```yaml
token-transport:
  authorization-header-enabled: true
  query-parameter-enabled: true
```

If a request contains multiple Bearer token sources, authentication fails instead of guessing which token to use.

## Authorization Code Flow

Enable Authorization Code Flow for browser login and local authentication cookies.

```yaml
security:
  providers:
    - oidc-next:
        tenants:
          web:
            issuer: "https://issuer.example"
            client-id: "${OIDC_CLIENT_ID}"
            client-secret: "${OIDC_CLIENT_SECRET}"
            authorization-code:
              redirection-endpoint-uri: "https://app.example/oidc/callback"
              scopes: [ "openid", "profile", "email" ]
            cookies:
              encryption-secret: "${OIDC_COOKIE_SECRET}"
```

When `authorization-code` is configured and not explicitly disabled:

- `client-id` is required.
- `authorization-code.redirection-endpoint-uri` is required.
- `authorization-code.scopes` must contain `openid`.
- `cookies.encryption-secret` is required.
- An Authorization Endpoint and Token Endpoint are required, either explicitly or from well-known metadata.
- An issuer or well-known URI is required.

PKCE is enabled by default and uses `S256`.

```yaml
authorization-code:
  redirection-endpoint-uri: "https://app.example/oidc/callback"
  scopes: [ "openid", "profile" ]
  pkce-required: true
  pkce-method: S256
```

PKCE can be disabled for compatibility with providers that cannot process it.

```yaml
authorization-code:
  redirection-endpoint-uri: "https://app.example/oidc/callback"
  scopes: [ "openid", "profile" ]
  pkce-required: false
```

## UserInfo

Configure `user-info` to request UserInfo after Authorization Code Flow token exchange and ID Token validation.

```yaml
security:
  providers:
    - oidc-next:
        tenants:
          web:
            issuer: "https://issuer.example"
            client-id: "${OIDC_CLIENT_ID}"
            client-secret: "${OIDC_CLIENT_SECRET}"
            endpoints:
              user-info-endpoint-uri: "https://issuer.example/userinfo"
            authorization-code:
              redirection-endpoint-uri: "https://app.example/oidc/callback"
              scopes: [ "openid", "profile", "email" ]
            user-info:
              enabled: true
            cookies:
              encryption-secret: "${OIDC_COOKIE_SECRET}"
```

When `user-info` is configured and not explicitly disabled:

- Authorization Code Flow must be configured and enabled.
- A UserInfo Endpoint is required, either explicitly or from well-known metadata.
- The provider calls the UserInfo Endpoint with the access token returned by the Token Endpoint.
- The UserInfo response must be a successful JSON object response with `Content-Type: application/json`.
- The UserInfo response must contain `sub`, and it must exactly match the ID Token `sub`.

UserInfo claims are stored in the protected local authentication result cookie and merged into subject attributes on
later requests. The full UserInfo JSON object is stored client-side in the protected cookie, so avoid returning large
claims or unnecessary personal data from the UserInfo Endpoint. UserInfo claims override ID Token claims with the same
name for principal attributes, principal name, and roles, except ID Token protocol and authentication claims remain
ID Token sourced. Principal id still comes from the validated ID Token claim mapping.

Refresh-token renewal re-requests UserInfo when `user-info` is enabled and stores the refreshed UserInfo claims only
after the refreshed UserInfo `sub` matches the ID Token `sub`.

Programmatic configuration:

```java
OidcTenantConfig tenant = OidcTenantConfig.builder()
        .issuer(URI.create("https://issuer.example"))
        .clientId("client-id")
        .clientSecret("client-secret")
        .endpoints(endpoints -> endpoints
                .userInfoEndpointUri(URI.create("https://issuer.example/userinfo")))
        .authorizationCode(authorizationCode -> authorizationCode
                .redirectionEndpointUri(URI.create("https://app.example/oidc/callback"))
                .scopes(List.of("openid", "profile", "email")))
        .userInfo(userInfo -> { })
        .cookies(cookies -> cookies.encryptionSecret(System.getenv("OIDC_COOKIE_SECRET")))
        .buildPrototype();
```

## Local Logout Endpoint

Configure `logout` to register the local `POST` logout endpoint in `OidcFeature`.

```yaml
security:
  providers:
    - oidc-next:
        tenants:
          web:
            issuer: "https://issuer.example"
            client-id: "${OIDC_CLIENT_ID}"
            client-secret: "${OIDC_CLIENT_SECRET}"
            authorization-code:
              redirection-endpoint-uri: "https://app.example/oidc/callback"
              scopes: [ "openid", "profile" ]
            logout:
              local-endpoint-uri: "/oidc/logout"
            cookies:
              encryption-secret: "${OIDC_COOKIE_SECRET}"
```

When `logout` is configured and not explicitly disabled, `logout.local-endpoint-uri` defaults to `/oidc/logout`.
The endpoint requires a same-origin `Origin` or `Referer` header, removes the local authentication result cookie and the
Authentication Request cookie. For local-only logout, the endpoint then returns `204 No Content`. The endpoint resolves
the tenant from the local authentication result cookie when possible; otherwise it removes the configured logout tenant
cookie names for the requested logout path.

Add `logout.end-session` to redirect the User Agent to the OpenID Provider End Session Endpoint after local cookies are
removed.

```yaml
security:
  providers:
    - oidc-next:
        tenants:
          web:
            issuer: "https://issuer.example"
            client-id: "${OIDC_CLIENT_ID}"
            endpoints:
              end-session-endpoint-uri: "https://issuer.example/logout"
            authorization-code:
              redirection-endpoint-uri: "https://app.example/oidc/callback"
            logout:
              local-endpoint-uri: "/oidc/logout"
              end-session:
                post-logout-redirect-uri: "https://app.example/logged-out"
                allowed-post-logout-redirect-uris:
                  - "https://app.example/signed-out"
            cookies:
              encryption-secret: "${OIDC_COOKIE_SECRET}"
```

If `endpoints.end-session-endpoint-uri` is omitted, well-known metadata must be available from `issuer` or
`endpoints.well-known-uri` and must contain `end_session_endpoint`.

By default, the End Session request includes `id_token_hint` from the local authentication result cookie and fails with
`403 Forbidden` when the ID Token is not available. Set `logout.end-session.id-token-hint-required: false` to allow an
End Session request without `id_token_hint`; in that case `client-id` is required and the provider sends `client_id`
when `id_token_hint` is omitted.

The default `id-token-hint-required: true` mode requires Authorization Code Flow because the ID Token comes from local
authentication result storage.

The configured `post-logout-redirect-uri` is sent by default. A logout request may provide
`post_logout_redirect_uri`; the provider accepts it only when it exactly matches the configured default URI or one of
`allowed-post-logout-redirect-uris`. If `post_logout_redirect_uri` is accepted and the request contains `state`, the
provider includes `state` in the End Session request.

`endpoints.end-session-endpoint-uri`, `post-logout-redirect-uri`, and `allowed-post-logout-redirect-uris` must use
HTTPS unless `endpoints.tls-required` is disabled, and must not contain fragments.

If several tenants share a logout path and the request does not identify exactly one tenant through a local
authentication result cookie, the endpoint only clears local cookies for the matching path tenants and returns
`204 No Content`; it does not guess which OpenID Provider End Session Endpoint to use.

Programmatic configuration:

```java
OidcTenantConfig tenant = OidcTenantConfig.builder()
        .issuer(URI.create("https://issuer.example"))
        .clientId("client-id")
        .clientSecret("client-secret")
        .endpoints(endpoints -> endpoints
                .endSessionEndpointUri(URI.create("https://issuer.example/logout")))
        .authorizationCode(authorizationCode -> authorizationCode
                .redirectionEndpointUri(URI.create("https://app.example/oidc/callback")))
        .logout(logout -> logout
                .localEndpointUri(URI.create("/oidc/logout"))
                .endSession(endSession -> endSession
                        .postLogoutRedirectUri(URI.create("https://app.example/logged-out"))
                        .addAllowedPostLogoutRedirectUri(URI.create("https://app.example/signed-out"))))
        .cookies(cookies -> cookies.encryptionSecret(System.getenv("OIDC_COOKIE_SECRET")))
        .buildPrototype();
```

## Token Endpoint Client Authentication

`token-endpoint-auth-method` controls how the client authenticates to the Token Endpoint for Authorization Code Flow,
refresh-token requests, and Client Credentials Grant.

```yaml
token-endpoint-auth-method: CLIENT_SECRET_BASIC
```

Available values:

- `CLIENT_SECRET_BASIC`: send `client_id` and `client_secret` using HTTP Basic authentication.
- `CLIENT_SECRET_POST`: send `client_id` and `client_secret` in the form body.
- `NONE`: send only `client_id`; use for public clients.

When omitted, the provider uses:

- `CLIENT_SECRET_BASIC` if `client-secret` is configured.
- `NONE` if `client-secret` is not configured.

Example using `client_secret_post`:

```yaml
security:
  providers:
    - oidc-next:
        tenants:
          web:
            issuer: "https://issuer.example"
            client-id: "${OIDC_CLIENT_ID}"
            client-secret: "${OIDC_CLIENT_SECRET}"
            token-endpoint-auth-method: CLIENT_SECRET_POST
            endpoints:
              authorization-endpoint-uri: "https://issuer.example/authorize"
              token-endpoint-uri: "https://issuer.example/token"
              jwks-uri: "https://issuer.example/jwks"
            authorization-code:
              redirection-endpoint-uri: "https://app.example/oidc/callback"
              scopes: [ "openid", "profile" ]
            cookies:
              encryption-secret: "${OIDC_COOKIE_SECRET}"
```

Example public client:

```yaml
security:
  providers:
    - oidc-next:
        tenants:
          web:
            issuer: "https://issuer.example"
            client-id: "${OIDC_CLIENT_ID}"
            token-endpoint-auth-method: NONE
            authorization-code:
              redirection-endpoint-uri: "https://app.example/oidc/callback"
              scopes: [ "openid", "profile" ]
            cookies:
              encryption-secret: "${OIDC_COOKIE_SECRET}"
```

## Outbound Token Propagation And Client Credentials

Outbound target selection uses Helidon's common `OutboundTarget` model. Configure targets at provider level with
`outbound`. A target can match by transport, host, path, and method.

Token Propagation sends the current user `TokenCredential` as `Authorization: Bearer <access-token>`. It is never applied
tenant-wide without a matching outbound target.

```yaml
security:
  providers:
    - oidc-next:
        outbound:
          - name: orders-api
            transports: [ "https" ]
            hosts: [ "orders.internal.example" ]
            paths: [ "/orders/.*" ]
        tenants:
          web:
            outbound:
              token-propagation-enabled: true
```

Target configuration can select the OIDC outbound strategy directly and can restrict propagated tokens by audience. If an
audience is configured, the current JWT or introspection-backed access token must contain that `aud` value, otherwise the
provider abstains. A target can also configure only `audience` when Token Propagation is enabled on the tenant; the
matching target then supplies the audience restriction for that tenant-level propagation policy.

```yaml
security:
  providers:
    - oidc-next:
        outbound:
          - name: orders-api
            transports: [ "https" ]
            hosts: [ "orders.internal.example" ]
            paths: [ "/orders/.*" ]
            token-propagation-enabled: true
            audience: "api://orders"
        tenants:
          web:
            issuer: "https://issuer.example"
```

Client Credentials Grant obtains an access token from the Token Endpoint with `grant_type=client_credentials` and applies
the same Token Endpoint client authentication settings as Authorization Code Flow and refresh-token requests. The token is
cached until it is close to expiration, then reacquired.

Client Credentials Grant is only valid for confidential clients. Configure `client-id`, `client-secret`, and either
`endpoints.token-endpoint-uri` or well-known metadata that provides the Token Endpoint. `token-endpoint-auth-method: NONE`
is rejected for this grant.

If any `outbound` entry enables Client Credentials Grant directly, every enabled tenant in the provider must meet
these Client Credentials prerequisites. Tenant resolution can select any enabled tenant for a matching outbound request,
so unrelated tenants that should not be used for Client Credentials Grant should be disabled or moved to a separate
provider configuration.

```yaml
security:
  providers:
    - oidc-next:
        outbound:
          - name: inventory-api
            transports: [ "https" ]
            hosts: [ "inventory.internal.example" ]
            client-credentials-grant-enabled: true
        tenants:
          service:
            client-id: "${OIDC_CLIENT_ID}"
            client-secret: "${OIDC_CLIENT_SECRET}"
            token-endpoint-auth-method: CLIENT_SECRET_BASIC
            endpoints:
              token-endpoint-uri: "https://issuer.example/token"
```

If `client-credentials-grant-enabled` is configured on a tenant and no provider-level `outbound` targets are configured,
the provider can
apply Client Credentials Grant tenant-wide. Configure targets when outbound tokens must be limited to specific
downstream services.

Programmatic outbound target configuration:

```java
OidcOutboundTargetConfig targetPolicy = OidcOutboundTargetConfig.builder()
        .tokenPropagationEnabled(true)
        .audience("api://orders")
        .buildPrototype();

OutboundTarget ordersApi = OutboundTarget.builder("orders-api")
        .addTransport("https")
        .addHost("orders.internal.example")
        .addPath("/orders/.*")
        .customObject(OidcOutboundTargetConfig.class, targetPolicy)
        .build();

OidcProviderConfig config = OidcProviderConfig.builder()
        .addOutboundTarget(ordersApi)
        .putTenant("web", OidcTenantConfig.builder()
                .issuer(URI.create("https://issuer.example"))
                .buildPrototype())
        .buildPrototype();
```

## Local Authentication Cookies

Authorization Code Flow stores the authenticated result in a protected local authentication cookie.

```yaml
cookies:
  authentication-request-cookie-name: "__Host-helidon-oidc-state"
  local-authentication-cookie-name: "__Host-helidon-oidc-auth"
  authentication-request-lifetime: "PT5M"
  local-authentication-lifetime: "PT1H"
  encryption-secret: "${OIDC_COOKIE_SECRET}"
```

The local authentication result lifetime is capped by the configured `local-authentication-lifetime` and by token
expiration. The provider uses the ID Token as the authentication source and exposes the access token through
`TokenCredential`.

If a refresh token is available, the provider can refresh the local authentication result before the access token
expires. A terminal refresh failure, such as `invalid_grant`, removes the local authentication cookie.

## Validating Refreshed Tokens

If `protected-resource.token-validation.method` is configured, the same validation policy is used for refreshed access
tokens before a refreshed token is stored in the local authentication cookie.
Set `protected-resource.enabled: false` when the tenant should use the validation policy only for refreshed access tokens
and should not accept Bearer Token Protected Resource requests.

```yaml
security:
  providers:
    - oidc-next:
        tenants:
          web:
            issuer: "https://issuer.example"
            client-id: "${OIDC_CLIENT_ID}"
            client-secret: "${OIDC_CLIENT_SECRET}"
            endpoints:
              jwks-uri: "https://issuer.example/jwks"
            authorization-code:
              redirection-endpoint-uri: "https://app.example/oidc/callback"
              scopes: [ "openid", "profile" ]
            protected-resource:
              enabled: false
              token-validation:
                method: JWT
                audience: "api://orders"
            cookies:
              encryption-secret: "${OIDC_COOKIE_SECRET}"
```

Refreshed ID Tokens are validated before storage. The provider rejects refreshed ID Tokens that unexpectedly change
issuer, subject, audience, authorized party, nonce, or authentication time.

## Subject Mapping

Subject mapping controls how token claims become the Helidon Security principal and grants.

Defaults:

```yaml
subject-mapping:
  principal-id-claim-paths: [ "sub", "username", "client_id" ]
  principal-name-claim-paths: [ "preferred_username", "username" ]
  role-claim-paths: [ "groups" ]
  scope-claim-paths: [ "scope" ]
  scope-grants-enabled: true
```

Principal id and principal name claim paths are tried in order. Role and scope claim paths are aggregated from all
configured paths and duplicate grant names are ignored. Dotted paths read nested objects, for example
`realm_access.roles`.

Principal id and principal name claims must be strings. Role and scope claims may be strings or string arrays. Scope
strings are split on whitespace.

For Authorization Code Flow local authentication, scope grants come from the Token Endpoint scope value stored in the
local authentication result. ID Token scope claims are not promoted to Helidon scope grants.

Example for a Keycloak-style token:

```yaml
subject-mapping:
  principal-id-claim-paths: [ "sub" ]
  principal-name-claim-paths: [ "preferred_username", "email" ]
  role-claim-paths: [ "realm_access.roles", "groups" ]
  scope-claim-paths: [ "scope", "scp" ]
  scope-grants-enabled: true
```

Disable scope grants when the application wants scopes to remain claims only.

```yaml
subject-mapping:
  scope-grants-enabled: false
```

## Combining Browser Login And API Bearer Tokens

A tenant may enable Authorization Code Flow and Protected Resource authentication at the same time.

```yaml
security:
  providers:
    - oidc-next:
        tenants:
          main:
            issuer: "https://issuer.example"
            client-id: "${OIDC_CLIENT_ID}"
            client-secret: "${OIDC_CLIENT_SECRET}"
            endpoints:
              jwks-uri: "https://issuer.example/jwks"
            authorization-code:
              redirection-endpoint-uri: "https://app.example/oidc/callback"
              scopes: [ "openid", "profile" ]
            protected-resource:
              token-validation:
                method: JWT
                audience: "api://orders"
            cookies:
              encryption-secret: "${OIDC_COOKIE_SECRET}"
```

When Bearer token evidence is present, the provider treats the request as Bearer Token authentication. Otherwise it can
reuse local authentication cookies or start Authorization Code Flow.

## Tenant Resolution

For one tenant, no `default-tenant` or `tenant-resolution` is required.

For multiple tenants, configure a default tenant:

```yaml
security:
  providers:
    - oidc-next:
        default-tenant: tenant-a
        tenants:
          tenant-a:
            issuer: "https://issuer-a.example"
          tenant-b:
            issuer: "https://issuer-b.example"
```

Or resolve tenants from requests:

```yaml
tenant-resolution:
  header-name: "X-Tenant"
```

```yaml
tenant-resolution:
  path-segment: 1
```

```yaml
tenant-resolution:
  path-template: "/tenants/{tenant}/orders"
```

```yaml
tenant-resolution:
  host-template: "{tenant}.example.com"
```

Tenant resolution order is:

1. Header.
2. Path segment.
3. Path template.
4. Host template.
5. Default tenant.

## TLS Requirements

Endpoint URIs are required to use HTTPS by default. The same switch also prevents OIDC outbound support from attaching
Bearer tokens to non-HTTPS outbound target URIs.

```yaml
endpoints:
  tls-required: true
```

For isolated tests, the TLS requirement can be disabled.

```yaml
endpoints:
  tls-required: false
  jwks-uri: "http://localhost:8081/jwks"
```

Do not disable TLS in production. Disabling TLS can expose access tokens, client credentials, and token signature
verification keys. Outbound targets that carry tokens should normally be constrained with `transports: [ "https" ]` even
though HTTPS is enforced by default.

## Configuration Reference

Provider options:

| Key | Description |
| --- | --- |
| `provider-name` | Provider name used by Helidon Security. Defaults to `oidc-next`. |
| `optional` | Whether authentication failures may be treated as optional by the provider. Defaults to `false`. |
| `default-tenant` | Tenant id used when no tenant is resolved from the request. Auto-filled when exactly one tenant is configured. |
| `tenant-resolution` | Tenant resolution rules. |
| `outbound` | Provider-level outbound target list. Targets can match transport, host, path, and method, and may select Token Propagation or Client Credentials Grant. |
| `tenants` | Map of tenant id to tenant configuration. |

Tenant options:

| Key | Description |
| --- | --- |
| `enabled` | Whether this tenant is enabled. Defaults to `true`. |
| `issuer` | Expected Issuer Identifier. |
| `client-id` | OAuth 2.0 client identifier. |
| `client-secret` | OAuth 2.0 client secret. |
| `token-endpoint-auth-method` | Token Endpoint client authentication method: `CLIENT_SECRET_BASIC`, `CLIENT_SECRET_POST`, or `NONE`. |
| `webclient` | WebClient configuration for well-known metadata, JWKS, Token Endpoint, introspection, and UserInfo requests. |
| `endpoints` | OpenID Provider and Authorization Server endpoint configuration. |
| `protected-resource` | Bearer Token Protected Resource configuration. |
| `authorization-code` | Authorization Code Flow configuration. |
| `logout` | OIDC logout endpoint configuration. |
| `user-info` | UserInfo request configuration for Authorization Code Flow local authentication. |
| `token-transport` | Bearer Token transport configuration. |
| `subject-mapping` | Claim-to-subject mapping configuration. |
| `cookies` | Cookie configuration used by stateful OIDC flows. |
| `outbound` | Tenant outbound configuration. Enables Token Propagation or Client Credentials Grant. |

Tenant outbound options:

| Key | Description |
| --- | --- |
| `token-propagation-enabled` | Enables Token Propagation for this tenant. This is applied only through matching `outbound`. |
| `client-credentials-grant-enabled` | Enables Client Credentials Grant for this tenant. Without `outbound`, this can apply tenant-wide. |

Tenant-wide Token Propagation and Client Credentials Grant cannot both be enabled without target selection.

UserInfo options:

| Key | Description |
| --- | --- |
| `enabled` | Whether UserInfo requests are enabled when `user-info` is configured. Defaults to `true`. |

Logout options:

| Key | Description |
| --- | --- |
| `enabled` | Whether local logout endpoint handling is enabled when `logout` is configured. Defaults to `true`. |
| `local-endpoint-uri` | Local logout endpoint URI registered by `OidcFeature`. Defaults to `/oidc/logout`. |
| `end-session` | RP-Initiated Logout End Session request configuration. If omitted, logout is local-only. |

End Session options:

| Key | Description |
| --- | --- |
| `enabled` | Whether End Session redirects are enabled when `end-session` is configured. Defaults to `true`. |
| `id-token-hint-required` | Whether `id_token_hint` must be available from the local authentication result. Defaults to `true`. |
| `post-logout-redirect-uri` | Default `post_logout_redirect_uri` sent to the OpenID Provider. |
| `allowed-post-logout-redirect-uris` | Additional exact `post_logout_redirect_uri` values accepted from the local logout request. |

When `id-token-hint-required` is `false`, `client-id` is required and sent as `client_id` if `id_token_hint` is omitted.
Post-logout redirect URI values must use HTTPS unless `endpoints.tls-required` is disabled and must not contain
fragments.

Common outbound target options:

| Key | Description |
| --- | --- |
| `name` | Required unique target name. |
| `transports` | Transport list, for example `[ "https" ]`. Empty means all transports. |
| `hosts` | Host list. Empty or `*` means all hosts; `*` can be used as a wildcard inside a host pattern. |
| `paths` | Path list. Empty or `*` means all paths; values are also treated as regular expressions. |
| `methods` | HTTP method list. Empty means all methods. |

OIDC outbound target options:

| Key | Description |
| --- | --- |
| `token-propagation-enabled` | Use Token Propagation for this outbound target. |
| `client-credentials-grant-enabled` | Use Client Credentials Grant for this outbound target. |
| `audience` | Expected `aud` claim for Token Propagation to this outbound target. |

Token validation options:

| Key | Description |
| --- | --- |
| `method` | `JWT` or `INTROSPECTION`. |
| `audience` | Expected access-token audience when audience validation is enabled. |
| `audience-validation-enabled` | Whether audience validation is enabled. Defaults to `true`. |
| `allowed-algorithms` | Allowed JWS algorithms for JWT access tokens. Defaults to `[ "RS256" ]`. |
| `clock-skew` | Allowed token time validation clock skew. Defaults to `PT1M`. |
