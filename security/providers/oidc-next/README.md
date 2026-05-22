# OIDC Provider User Guide

This document describes the current `oidc-next` security provider implementation.

The provider is tenant based. Even a single-tenant application configures one tenant under `tenants`, but when exactly
one tenant is configured the provider automatically uses it as the default tenant.

## Supported Use Cases

The current implementation supports:

- Protected Resource Bearer Token authentication.
- Access-token validation by local JWT validation against a JWKS URI.
- Access-token validation by OAuth 2.0 Token Introspection.
- OpenID Connect Authorization Code Flow.
- PKCE with `S256`, enabled by default.
- Token Endpoint exchange using Helidon WebClient.
- Token Endpoint client authentication with `CLIENT_SECRET_BASIC`, `CLIENT_SECRET_POST`, or `NONE`.
- ID Token validation for Authorization Code Flow.
- Local authentication result storage in protected cookies.
- Refresh-token based local authentication renewal.
- Validation of refreshed access tokens when token validation is configured.
- Validation of refreshed ID Tokens when the Token Endpoint returns a new ID Token.
- Configurable subject mapping for principal id, principal name, roles, and scope grants.
- Multi-tenant selection by default tenant, header, path segment, path template, or host template.

The current implementation does not yet support:

- UserInfo requests and UserInfo claim merge.
- RP-Initiated Logout.
- Outbound token propagation.
- Client Credentials Grant token acquisition.
- Provider profiles or flow-step customizer SPI.
- DPoP, mTLS sender-constrained tokens, or token binding.
- Discovery-backed JWKS resolution for Protected Resource JWT validation. Configure `endpoints.jwks-uri` explicitly
  for `protected-resource.token-validation.method: JWT`.
- Discovery-backed introspection endpoint resolution for Protected Resource introspection. Configure
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
              enabled: true
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
import java.util.List;

import io.helidon.security.Security;
import io.helidon.security.providers.oidc.next.OidcClientAuthenticationMethod;
import io.helidon.security.providers.oidc.next.OidcFeature;
import io.helidon.security.providers.oidc.next.OidcProvider;
import io.helidon.security.providers.oidc.next.OidcProviderConfig;
import io.helidon.security.providers.oidc.next.OidcTenantConfig;
import io.helidon.security.providers.oidc.next.OidcTokenValidationMethod;
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
                        .enabled(true)
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
                        .enabled(true)
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
                        .enabled(true)
                        .redirectionEndpointUri(URI.create("https://app.example/oidc/callback"))
                        .scopes(List.of("openid", "profile", "email")))
                .cookies(cookies -> cookies
                        .encryptionSecret(System.getenv("OIDC_COOKIE_SECRET")))
                .buildPrototype())
        .buildPrototype();

OidcProvider provider = OidcProvider.create(config);
```

When Authorization Code Flow is enabled, register `OidcFeature` with WebServer routing so the callback route is
installed:

```java
OidcProviderConfig config = OidcProviderConfig.builder()
        .putTenant("web", OidcTenantConfig.builder()
                .issuer(URI.create("https://issuer.example"))
                .clientId(System.getenv("OIDC_CLIENT_ID"))
                .clientSecret(System.getenv("OIDC_CLIENT_SECRET"))
                .authorizationCode(authorizationCode -> authorizationCode
                        .enabled(true)
                        .redirectionEndpointUri(URI.create("https://app.example/oidc/callback"))
                        .scopes(List.of("openid", "profile")))
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
                .enabled(true)
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

## Endpoint Configuration

`endpoints` contains OpenID Provider or Authorization Server endpoints.

```yaml
endpoints:
  discovery-uri: "https://issuer.example/.well-known/openid-configuration"
  authorization-endpoint-uri: "https://issuer.example/authorize"
  token-endpoint-uri: "https://issuer.example/token"
  jwks-uri: "https://issuer.example/jwks"
  introspection-endpoint-uri: "https://issuer.example/oauth2/introspect"
  user-info-endpoint-uri: "https://issuer.example/userinfo"
  end-session-endpoint-uri: "https://issuer.example/logout"
```

`user-info-endpoint-uri` and `end-session-endpoint-uri` are represented in metadata but their flows are not implemented
yet.

If `issuer` is configured and `endpoints.discovery-uri` is omitted, the provider derives the discovery URI by appending
`/.well-known/openid-configuration` to the issuer URI after removing trailing `/` characters.

Discovery is currently used by Authorization Code Flow when provider endpoint metadata is missing. The discovered
metadata can provide `authorization_endpoint`, `token_endpoint`, and `jwks_uri`. When Authorization Code Flow is
configured with explicit Authorization and Token Endpoint URIs instead of discovery, configure `endpoints.jwks-uri` as
well so ID Token signatures can be verified.

Protected Resource JWT validation still requires explicit `endpoints.jwks-uri`, and Protected Resource introspection
still requires explicit `endpoints.introspection-endpoint-uri`.

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
              enabled: true
              token-validation:
                method: JWT
                audience: "api://orders"
                allowed-algorithms: [ "RS256" ]
                clock-skew: "PT1M"
```

`issuer` and `endpoints.jwks-uri` are required. `audience` is required when audience validation is enabled.

Audience validation is enabled by default. Disable it only when the deployment intentionally accepts tokens without a
local audience check.

```yaml
protected-resource:
  enabled: true
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
              enabled: true
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
  enabled: true
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
              enabled: true
              redirection-endpoint-uri: "https://app.example/oidc/callback"
              scopes: [ "openid", "profile", "email" ]
            cookies:
              encryption-secret: "${OIDC_COOKIE_SECRET}"
```

When `authorization-code.enabled` is `true`:

- `client-id` is required.
- `authorization-code.redirection-endpoint-uri` is required.
- `authorization-code.scopes` must contain `openid`.
- `cookies.encryption-secret` is required.
- An Authorization Endpoint and Token Endpoint are required, either explicitly or from discovery.
- An issuer or discovery URI is required.

PKCE is enabled by default and uses `S256`.

```yaml
authorization-code:
  enabled: true
  redirection-endpoint-uri: "https://app.example/oidc/callback"
  scopes: [ "openid", "profile" ]
  pkce-required: true
  pkce-method: S256
```

PKCE can be disabled for compatibility with providers that cannot process it.

```yaml
authorization-code:
  enabled: true
  redirection-endpoint-uri: "https://app.example/oidc/callback"
  scopes: [ "openid", "profile" ]
  pkce-required: false
```

## Token Endpoint Client Authentication

`token-endpoint-auth-method` controls how the client authenticates to the Token Endpoint for Authorization Code Flow and
refresh-token requests.

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
              enabled: true
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
              enabled: true
              redirection-endpoint-uri: "https://app.example/oidc/callback"
              scopes: [ "openid", "profile" ]
            cookies:
              encryption-secret: "${OIDC_COOKIE_SECRET}"
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
              enabled: true
              redirection-endpoint-uri: "https://app.example/oidc/callback"
              scopes: [ "openid", "profile" ]
            protected-resource:
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
              enabled: true
              redirection-endpoint-uri: "https://app.example/oidc/callback"
              scopes: [ "openid", "profile" ]
            protected-resource:
              enabled: true
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

Endpoint URIs are required to use HTTPS by default.

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
verification keys.

## Configuration Reference

Provider options:

| Key | Description |
| --- | --- |
| `provider-name` | Provider name used by Helidon Security. Defaults to `oidc-next`. |
| `optional` | Whether authentication failures may be treated as optional by the provider. Defaults to `false`. |
| `default-tenant` | Tenant id used when no tenant is resolved from the request. Auto-filled when exactly one tenant is configured. |
| `tenant-resolution` | Tenant resolution rules. |
| `tenants` | Map of tenant id to tenant configuration. |

Tenant options:

| Key | Description |
| --- | --- |
| `enabled` | Whether this tenant is enabled. Defaults to `true`. |
| `issuer` | Expected Issuer Identifier. |
| `client-id` | OAuth 2.0 client identifier. |
| `client-secret` | OAuth 2.0 client secret. |
| `token-endpoint-auth-method` | Token Endpoint client authentication method: `CLIENT_SECRET_BASIC`, `CLIENT_SECRET_POST`, or `NONE`. |
| `endpoints` | OpenID Provider and Authorization Server endpoint configuration. |
| `protected-resource` | Bearer Token Protected Resource configuration. |
| `authorization-code` | Authorization Code Flow configuration. |
| `token-transport` | Bearer Token transport configuration. |
| `subject-mapping` | Claim-to-subject mapping configuration. |
| `cookies` | Cookie configuration used by stateful OIDC flows. |
| `outbound` | Outbound configuration. Token propagation and client credentials token acquisition are classified but not implemented yet. |

Token validation options:

| Key | Description |
| --- | --- |
| `method` | `JWT` or `INTROSPECTION`. |
| `audience` | Expected access-token audience when audience validation is enabled. |
| `audience-validation-enabled` | Whether audience validation is enabled. Defaults to `true`. |
| `allowed-algorithms` | Allowed JWS algorithms for JWT access tokens. Defaults to `[ "RS256" ]`. |
| `clock-skew` | Allowed token time validation clock skew. Defaults to `PT1M`. |
