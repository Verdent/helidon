# OIDC Next Provider User Guide

This document describes the current `oidc-next` security provider implementation.

Single-tenant applications configure tenant options directly under `oidc-next`. Multi-tenant applications configure
named tenants under `tenants` and use `default-tenant` or `tenant-resolution` to select one for each request.

## Supported Use Cases

The current implementation supports:

- Protected Resource Bearer Token authentication.
- Access-token validation by local JWT validation against an explicit JWKS URI or a JWKS URI from well-known metadata.
- Access-token validation by OAuth 2.0 Token Introspection.
- Introspection Endpoint authentication with separate protected-resource credentials when needed.
- RFC 8705 certificate-bound access-token validation for Protected Resource Bearer Token requests.
- OpenID Connect Authorization Code Flow.
- RFC 9126 Pushed Authorization Requests for Authorization Code Flow.
- RFC 9101 signed by-value Request Objects for Authorization Code Flow.
- PKCE with `S256` by default and `plain` for compatibility.
- Token Endpoint exchange using Helidon WebClient.
- Token Endpoint client authentication with `CLIENT_SECRET_BASIC`, `CLIENT_SECRET_POST`, `CLIENT_SECRET_JWT`,
  `PRIVATE_KEY_JWT`, `TLS_CLIENT_AUTH`, `SELF_SIGNED_TLS_CLIENT_AUTH`, or `NONE`.
- ID Token validation for Authorization Code Flow.
- Encrypted ID Token decryption before normal signed ID Token validation.
- Local authentication result storage in protected cookies.
- Local OIDC logout endpoint that removes OIDC cookies.
- RP-Initiated Logout redirect to the OpenID Provider End Session Endpoint.
- Refresh-token based local authentication renewal.
- Validation of refreshed access tokens when token validation is configured.
- Validation of refreshed ID Tokens when the Token Endpoint returns a new ID Token.
- Optional UserInfo requests for Authorization Code Flow with exact `sub` matching and configurable claim storage.
- Configurable subject mapping for principal id, principal name, roles, and scope grants.
- Tenant WebClient configuration for OpenID Provider and Authorization Server requests.
- Multi-tenant selection by default tenant, header, path segment, path template, or host template.
- Outbound Token Propagation to configured outbound targets.
- Outbound Client Credentials Grant token acquisition and caching.
- Outbound RFC 8693 Token Exchange token acquisition and subject-token-aware caching.

The current implementation does not yet support:

- DPoP or token binding other than RFC 8705 certificate-bound access-token validation.
- Encrypted JWT UserInfo responses.
- Hosted Request Objects through client-hosted `request_uri`, unsigned Request Objects, or encrypted Request Objects.

## Supported Standards Boundary

`oidc-next` implements client-side and resource-server-side OAuth/OIDC behavior. It is an OpenID Connect Relying Party,
an OAuth client, and an OAuth Protected Resource provider. It is not an OpenID Provider, OAuth Authorization Server,
Dynamic Client Registration server, Device Flow client, CIBA client, or browser session-management implementation.

The supported standards surface is intentionally scoped:

- OpenID Connect Core 1.0: Authorization Code Flow, Authentication Request construction, ID Token validation, encrypted
  ID Token decryption before validation, JSON and signed JWT UserInfo retrieval, offline access prompt handling, and JWT
  client authentication. Implicit Flow, Hybrid Flow, OP behavior, and encrypted JWT UserInfo responses are not
  implemented.
- OpenID Connect Discovery 1.0 and OAuth 2.0 Authorization Server Metadata, RFC 8414: metadata loading and validation for
  issuer, endpoint, JWKS, client-authentication, PKCE, PAR, JAR, Token Exchange, mTLS aliases, logout, and UserInfo
  capabilities. The provider derives the OpenID Connect discovery URI from `issuer`; configure an OAuth authorization
  server metadata URI explicitly when needed.
- OAuth 2.0, RFC 6749: Authorization Code token exchange, refresh-token exchange, Client Credentials Grant, token
  endpoint error parsing, scopes, and client authentication. Authorization Server behavior is not implemented.
- OAuth 2.0 Bearer Token Usage, RFC 6750: Protected Resource Bearer authentication from the Authorization header and,
  when explicitly enabled, the query parameter. Ambiguous or insecure Bearer token requests are rejected.
- PKCE, RFC 7636: `S256` is the default. `plain` is available only for confidential-client compatibility; public clients
  must use PKCE with `S256`.
- Token Introspection, RFC 7662: Protected Resource access-token validation with authenticated introspection requests.
  Introspection response caching is not enabled by default.
- Token Exchange, RFC 8693: outbound Bearer access-token to Bearer access-token exchange. SAML, ID Token exchange,
  actor-token, delegation-chain, `act`, and `may_act` semantics are not implemented.
- Mutual TLS, RFC 8705: Token Endpoint mTLS client authentication, mTLS endpoint aliases, and certificate-bound
  access-token validation. Certificate-bound token validation applies to Protected Resource Bearer requests.
- Resource Indicators, RFC 8707: `resource` parameters for Authorization Code Flow, refresh requests, Client Credentials
  Grant, and Token Exchange where configured.
- JWT Access Token Profile, RFC 9068: signed JWT access-token validation. Disabling audience validation is a compatibility
  relaxation, not full RFC 9068 conformance.
- JWT-Secured Authorization Request, RFC 9101: signed by-value Request Objects. Unsigned, encrypted, and hosted
  `request_uri` Request Objects are not implemented.
- Pushed Authorization Requests, RFC 9126: PAR request and response handling, including metadata-driven enforcement.
- Authorization Server Issuer Identification, RFC 9207: authorization response `iss` validation when present or when
  metadata advertises support.
- DPoP, RFC 9449: DPoP is not implemented. DPoP-bound access tokens with `cnf.jkt` are rejected when presented as Bearer
  tokens, but DPoP proof validation, DPoP Token Endpoint behavior, nonce handling, replay protection, and outbound DPoP
  proof generation are not supported.

## Provider Coverage Matrix

The matrix below describes current interoperability coverage. It is a test coverage map, not a conformance claim.
Keycloak is the always-runnable Testcontainers baseline. The synthetic local IDP is still required for deterministic
negative cases, strict protocol variants, and features that real providers do not expose predictably.

| Capability | Keycloak CI coverage | Synthetic and unit coverage | Remaining provider gap |
| --- | --- | --- | --- |
| Discovery and OAuth metadata | Yes: discovery metadata and endpoint loading. | Metadata parsing, endpoint override, and startup validation. | Cloud metadata quirks. |
| Authorization Code Flow | Yes: browser login, callback, mixed browser/API use. | Callback state, issuer, nonce, PKCE, cookie, and error boundaries. | Cloud redirect and cookie policies. |
| Pushed Authorization Requests | Yes: PAR endpoint discovered from Keycloak. | PAR request/response and metadata enforcement. | Providers that require PAR. |
| Signed Request Objects | No Keycloak CI path. | Signed by-value JAR request construction and metadata checks. | FAPI-style providers requiring JAR. |
| Refresh-token renewal | Yes: Keycloak refresh flow. | Refresh response parsing, token validation, rotation, and resource parameters. | Provider-specific refresh policies. |
| JSON and JWT UserInfo | Yes: Keycloak JSON UserInfo. | Subject matching, signed JWS, direct JWE, nested JWS-in-JWE, and claim storage. | Real provider emitting signed or encrypted JWT UserInfo. |
| RP-Initiated Logout | Yes: Keycloak end-session redirect. | Local logout, cookie clearing, redirect validation, and endpoint discovery. | Provider-specific logout parameters. |
| Bearer introspection | Yes: valid, inactive, wrong-audience, and unknown tokens. | Response parsing, errors, issuer/audience/time validation, and endpoint failures. | Opaque-token cloud providers. |
| JWT access tokens | Keycloak default JWT is covered as rejected because it is not RFC 9068. | Strict RFC 9068 JWT success and negative validation. | Real provider issuing RFC 9068-style tokens. |
| mTLS and certificate-bound tokens | No Keycloak CI path. | Token Endpoint mTLS config and certificate-bound access-token validation. | Real mTLS provider setup. |
| Token Propagation | Yes: validated Keycloak token propagated through WebClient. | Audience validation, abstain/failure paths, and target matching. | Downstream audience policy variations. |
| Client Credentials Grant | Yes: Keycloak token endpoint and outbound WebClient use. | Request shape, caching, auth methods, resources, and metadata checks. | Non-basic client authentication with real providers. |
| Token Exchange | Yes: Keycloak standard token exchange. | RFC 8693 request shape, response validation, caching, and failures. | Provider-specific OBO/token-exchange variants. |
| Multi-tenant routing | No dedicated Keycloak multi-issuer CI path. | Tenant resolution, tenant lifecycle, and route behavior. | Multi-provider deployments. |
| Security-negative boundaries | Real providers are not used for most negative cases. | Bearer ambiguity, DPoP-bound rejection, state replay, malformed tokens, and endpoint errors. | Keep synthetic by design. |
| Unsupported specs | No CI path. | Rejection or config guardrails where security-sensitive. | DPoP, JARM, RAR, revocation, and back-channel logout remain queued. |

Manual or credentialed smoke tests should be added only when they prove a behavior Keycloak cannot cover. Good candidates
are OCI IAM, Auth0, Okta, Microsoft Entra ID, or another provider required by Helidon users. Each smoke test should record
metadata quirks, token endpoint authentication methods, token formats, UserInfo format, PAR/JAR/DPoP/JARM/RAR support,
logout behavior, and mTLS or certificate-bound token support.

## Configuration Shape

The provider config key is `oidc-next`.

```yaml
security:
  providers:
    - oidc-next:
        issuer: "https://issuer.example"
```

The `issuer` value is the exact OpenID Connect Issuer Identifier string used for issuer comparisons. It must be a valid
Issuer URL: absolute, HTTPS unless `endpoints.tls-required` is disabled, and without query or fragment. The provider
parses it as a URI only for syntax validation, HTTPS checks, and well-known metadata URI derivation.

For a single tenant, no `tenants` or `default-tenant` block is required.
`protected-resource` and `authorization-code` are not configured by default. Adding either block enables that part of the
provider unless the block explicitly sets `enabled: false`.

```yaml
security:
  providers:
    - oidc-next:
        issuer: "https://issuer.example"
        endpoints:
          jwks-uri: "https://issuer.example/jwks"
        jwk-set:
          unknown-key-id-refresh-interval: "PT30S"
          refresh-interval: "PT1H"
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

import io.helidon.common.configurable.Resource;
import io.helidon.security.EndpointConfig;
import io.helidon.security.Security;
import io.helidon.security.Subject;
import io.helidon.security.providers.common.OutboundTarget;
import io.helidon.security.providers.oidc.next.OidcAuthenticationFailureResponse;
import io.helidon.security.providers.oidc.next.OidcClientAuthenticationMethod;
import io.helidon.security.providers.oidc.next.OidcEndpointCredential;
import io.helidon.security.providers.oidc.next.OidcEndpointPolicyConfig;
import io.helidon.security.providers.oidc.next.OidcFeature;
import io.helidon.security.providers.oidc.next.OidcOutboundPolicy;
import io.helidon.security.providers.oidc.next.OidcOutboundTargetConfig;
import io.helidon.security.providers.oidc.next.OidcPrincipalIdMode;
import io.helidon.security.providers.oidc.next.OidcProvider;
import io.helidon.security.providers.oidc.next.OidcProviderConfig;
import io.helidon.security.providers.oidc.next.OidcRequestObjectMode;
import io.helidon.security.providers.oidc.next.OidcTokenValidationMethod;
import io.helidon.security.providers.oidc.next.OidcUserInfoStoragePolicy;
import io.helidon.webclient.api.Proxy;
import io.helidon.webclient.api.WebClientConfig;
import io.helidon.webserver.WebServer;
import io.helidon.webserver.security.SecurityFeature;
```

Create a JWT Protected Resource provider:

```java
OidcProviderConfig config = OidcProviderConfig.builder()
        .issuer("https://issuer.example")
        .endpoints(endpoints -> endpoints
                .jwksUri(URI.create("https://issuer.example/jwks")))
        .protectedResource(protectedResource -> protectedResource
                .tokenValidation(tokenValidation -> tokenValidation
                        .method(OidcTokenValidationMethod.JWT)
                        .audience("api://orders")
                        .allowedAlgorithms(List.of("RS256"))))
        .buildPrototype();

OidcProvider provider = OidcProvider.create(config);
```

Configure JWK Set reload policy programmatically:

```java
OidcProviderConfig config = OidcProviderConfig.builder()
        .issuer("https://issuer.example")
        .endpoints(endpoints -> endpoints
                .jwksUri(URI.create("https://issuer.example/jwks")))
        .jwkSet(jwkSet -> jwkSet
                .unknownKeyIdRefreshInterval(Duration.ofSeconds(30))
                .refreshInterval(Duration.ofHours(1))
                .staleOnError(true))
        .protectedResource(protectedResource -> protectedResource
                .tokenValidation(tokenValidation -> tokenValidation
                        .method(OidcTokenValidationMethod.JWT)
                        .audience("api://orders")))
        .buildPrototype();
```

Create an introspection Protected Resource provider:

```java
OidcProviderConfig config = OidcProviderConfig.builder()
        .issuer("https://issuer.example")
        .clientId(System.getenv("OIDC_CLIENT_ID"))
        .clientSecret(System.getenv("OIDC_CLIENT_SECRET"))
        .endpoints(endpoints -> endpoints
                .introspectionEndpointUri(URI.create("https://issuer.example/oauth2/introspect")))
        .protectedResource(protectedResource -> protectedResource
                .tokenValidation(tokenValidation -> tokenValidation
                        .method(OidcTokenValidationMethod.INTROSPECTION)
                        .audience("api://orders")))
        .buildPrototype();

OidcProvider provider = OidcProvider.create(config);
```

Create an Authorization Code Flow provider:

```java
OidcProviderConfig config = OidcProviderConfig.builder()
        .issuer("https://issuer.example")
        .clientId(System.getenv("OIDC_CLIENT_ID"))
        .clientSecret(System.getenv("OIDC_CLIENT_SECRET"))
        .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .authorizationCode(authorizationCode -> authorizationCode
                .scopes(List.of("openid", "profile", "email")))
        .logout(logout -> logout
                .localEndpointUri(URI.create("/oidc/logout")))
        .cookies(cookies -> cookies
                .encryptionSecret(System.getenv("OIDC_COOKIE_SECRET")))
        .buildPrototype();

OidcProvider provider = OidcProvider.create(config);
```

Configure signed Request Objects programmatically:

```java
OidcProviderConfig config = OidcProviderConfig.builder()
        .issuer("https://issuer.example")
        .clientId(System.getenv("OIDC_CLIENT_ID"))
        .clientSecret(System.getenv("OIDC_CLIENT_SECRET"))
        .authorizationCode(authorizationCode -> authorizationCode
                .scopes(List.of("openid", "profile"))
                .requestObject(requestObject -> requestObject
                        .mode(OidcRequestObjectMode.REQUIRED)
                        .jwk(jwk -> jwk.resourcePath("private-request-object-jwks.json"))
                        .keyId("request-object-signing-key")
                        .algorithm("RS256")
                        .lifetime(Duration.ofMinutes(1))))
        .cookies(cookies -> cookies
                .encryptionSecret(System.getenv("OIDC_COOKIE_SECRET")))
        .buildPrototype();
```

When Authorization Code Flow or logout is enabled, register `OidcFeature` as a WebServer feature so the local routes are
installed. This registration form also applies the configured `socket`:

```java
OidcProviderConfig config = OidcProviderConfig.builder()
        .issuer("https://issuer.example")
        .clientId(System.getenv("OIDC_CLIENT_ID"))
        .clientSecret(System.getenv("OIDC_CLIENT_SECRET"))
        .authorizationCode(authorizationCode -> authorizationCode
                .scopes(List.of("openid", "profile")))
        .logout(logout -> logout
                .localEndpointUri(URI.create("/oidc/logout")))
        .cookies(cookies -> cookies
                .encryptionSecret(System.getenv("OIDC_COOKIE_SECRET")))
        .buildPrototype();

Security security = Security.builder()
        .addProvider(OidcProvider.create(config), config.providerName())
        .build();

WebServer.builder()
        .addFeature(SecurityFeature.builder()
                .security(security)
                .build())
        .addFeature(OidcFeature.create(config))
        .build();
```

To register the local OIDC routes on a named WebServer socket, configure `socket` on the provider and register
`OidcFeature` as a WebServer feature. The socket name must match a configured `server.sockets[].name`.

```yaml
server:
  port: 8080
  sockets:
    - name: public
      port: 8443

security:
  providers:
    - oidc-next:
        socket: public
        socket-required: true
        issuer: "https://issuer.example"
        client-id: "${OIDC_CLIENT_ID}"
        client-secret: "${OIDC_CLIENT_SECRET}"
        authorization-code:
          scopes: [ "openid", "profile" ]
        cookies:
          encryption-secret: "${OIDC_COOKIE_SECRET}"
```

`socket-required` defaults to `true` for named OIDC sockets. Set it to `false` only if the feature may fall back to the
default WebServer socket when the named socket is absent.

Programmatic subject mapping uses the same claim path names as YAML:

```java
OidcProviderConfig config = OidcProviderConfig.builder()
        .issuer("https://issuer.example")
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
OidcProviderConfig config = OidcProviderConfig.builder()
        .issuer("https://issuer.example")
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
  pushed-authorization-request-endpoint-uri: "https://issuer.example/par"
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
This is the OpenID Connect Discovery location. The provider does not automatically derive the RFC 8414
`/.well-known/oauth-authorization-server` location; configure `endpoints.well-known-uri` explicitly when an OAuth
Authorization Server metadata endpoint must be used instead.

Well-known metadata is used by Authorization Code Flow when the issuer, Authorization Endpoint, or Token Endpoint is
missing, by Client Credentials Grant when `endpoints.token-endpoint-uri` is not configured, by Protected Resource JWT
validation when `endpoints.jwks-uri` is not configured, and by Protected Resource introspection when
`endpoints.introspection-endpoint-uri` is not configured. It is also used by RP-Initiated Logout when
`endpoints.end-session-endpoint-uri` is not configured, and by UserInfo when `endpoints.user-info-endpoint-uri` is not
configured. It can provide `authorization_endpoint`, `token_endpoint`, `jwks_uri`, `introspection_endpoint`,
`response_types_supported`, `grant_types_supported`, `code_challenge_methods_supported`,
`token_endpoint_auth_methods_supported`, `token_endpoint_auth_signing_alg_values_supported`,
`introspection_endpoint_auth_methods_supported`, `introspection_endpoint_auth_signing_alg_values_supported`,
`id_token_signing_alg_values_supported`, `id_token_encryption_alg_values_supported`,
`id_token_encryption_enc_values_supported`, `userinfo_endpoint`, `end_session_endpoint`,
`mtls_endpoint_aliases.token_endpoint`, `pushed_authorization_request_endpoint`,
`require_pushed_authorization_requests`, `request_parameter_supported`,
`request_object_signing_alg_values_supported`, `request_object_encryption_alg_values_supported`,
`request_object_encryption_enc_values_supported`, `require_signed_request_object`, and
`authorization_response_iss_parameter_supported`.
For mutual TLS Token Endpoint client authentication, the provider uses `mtls_endpoint_aliases.token_endpoint` only when
the Token Endpoint URI itself is loaded from well-known metadata. An explicit `endpoints.token-endpoint-uri` is treated
as the configured Token Endpoint and is not replaced by the alias.
When Authorization Code Flow is configured with explicit Authorization and Token Endpoint URIs instead of loading
well-known metadata, configure `endpoints.jwks-uri` as well so ID Token signatures can be verified.
When present in well-known metadata, `id_token_encryption_alg_values_supported` and
`id_token_encryption_enc_values_supported` must include at least one algorithm allowed by the local `id-token` JWE
policy.
When Authorization Code Flow loads well-known metadata, the metadata must advertise `response_types_supported`
containing `code`. If `grant_types_supported` is present, it must contain `authorization_code`; if it is omitted, the
Discovery default includes `authorization_code`. When PKCE is enabled, `code_challenge_methods_supported` must be present
and include the configured PKCE method. The provider also validates the configured Token Endpoint authentication method
against `token_endpoint_auth_methods_supported`; if that metadata is omitted, the Discovery default is
`client_secret_basic`. For `client_secret_jwt` and `private_key_jwt`, well-known metadata must include
`token_endpoint_auth_signing_alg_values_supported` with the configured assertion signing algorithm.
When signed Request Objects are enabled and well-known metadata is loaded, `request_parameter_supported` must be `true`
unless the Authentication Request is pushed through PAR. If
`request_object_signing_alg_values_supported` is present, it must include the configured Request Object signing
algorithm. If `require_signed_request_object` is `true`, the provider rejects `request-object.mode: DISABLED` and
requires local Request Object signing key material.
The metadata endpoint is loaded with a GET request, redirects are not followed, and the response must be `200 OK` with an
`application/json` content type. Metadata member names are matched exactly as specified by OpenID Connect Discovery and
RFC 8414; they are case-sensitive JSON names.
When `endpoints.well-known-uri` is configured without `issuer`, the provider trusts that metadata URL to identify the
issuer and then validates the metadata `issuer` URI shape before using it. Prefer configuring `issuer` as well when the
expected issuer identity is known in advance.

`authorization-code.redirection-endpoint-uri` is not under `endpoints` because it is the client callback endpoint, not
an OpenID Provider endpoint. It defaults to `/oidc/callback`; local paths are resolved from the incoming request origin
before they are sent to the OpenID Provider as `redirect_uri`.

## Protected Resource With JWT Validation

Use `method: JWT` to validate Bearer access tokens locally as signed JWTs against configured JWKS material.

```yaml
security:
  providers:
    - oidc-next:
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
provider loads well-known metadata and uses its `jwks_uri`. RFC 9068 JWT access-token validation expects `audience` to
identify this resource server.
When the JWK Set URI comes from well-known metadata, the provider treats it as the OpenID Provider's published public
key set and rejects JWK Sets containing private or symmetric key values. Explicit local/private JWK resources for client
assertion signing and ID Token decryption are configured separately under `client-assertion.jwk` and
`id-token.decryption-jwk`.

Audience validation is enabled by default. For JWT access tokens, disabling it relaxes RFC 9068 validation, logs a warning
during configuration, and should be used only for testing, local development, or legacy non-RFC9068 tokens. Without a
local audience check, this resource server can accept tokens meant for a different resource server.

```yaml
protected-resource:
  token-validation:
    method: JWT
    audience-validation-enabled: false
```

JWT access-token claims are used to build the Helidon Security subject according to `subject-mapping`. The validated
`Jwt` and `SignedJwt` are also available through the subject's public `TokenCredential`. Treat access-token claims as
authorization data visible to application code, and configure the Authorization Server to issue access tokens for this
resource with only the claims this resource needs.

### JWK Set Reload Policy

The `jwk-set` block configures how the provider reloads the JSON Web Key Set used for ID Token and JWT access-token
signature validation. This is tenant configuration, so single-tenant applications place it directly under `oidc-next`;
multi-tenant applications place it under each tenant that needs a custom policy.

```yaml
security:
  providers:
    - oidc-next:
        issuer: "https://issuer.example"
        endpoints:
          jwks-uri: "https://issuer.example/jwks"
        jwk-set:
          unknown-key-id-refresh-enabled: true
          unknown-key-id-refresh-interval: "PT30S"
          refresh-interval: "PT1H"
          stale-on-error: true
        protected-resource:
          token-validation:
            method: JWT
            audience: "api://orders"
```

`unknown-key-id-refresh-enabled` reloads the JWK Set when a token uses a `kid` that is not present in the cached keys.
This supports Authorization Server key rotation. `unknown-key-id-refresh-interval` rate-limits those reload attempts;
the default is `PT5M`.

`refresh-interval` enables lazy periodic refresh. No background thread is started. The provider checks the cache age
during token validation and refreshes only when a request needs keys after the interval has elapsed.

Refreshes are coordinated as single-flight operations for concurrent requests. The cached-key fast path does not take
the refresh lock. When many virtual threads hit a cold cache, expired cache, or unknown `kid` at the same time, only one
thread loads the JWK Set from the remote endpoint for that refresh opportunity. With `stale-on-error: true`, requests
may continue to use cached keys when a reload fails. With `stale-on-error: false`, a failed scheduled reload causes
requests to fail until the next configured refresh interval permits another reload attempt.

## Protected Resource With Introspection

Use `method: INTROSPECTION` for opaque tokens or when the Authorization Server is responsible for access-token
validation.

```yaml
security:
  providers:
    - oidc-next:
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

Introspection requires authentication to the Introspection Endpoint. RFC 7662 says the Authorization Server "MUST
require authentication of protected resources" and can require credentials that are separate from the client credentials
used at the Token Endpoint. By default, introspection uses `CLIENT_SECRET_BASIC` with the tenant `client-id` and
`client-secret`. Configure `protected-resource.token-validation.introspection` when the Introspection Endpoint requires
a different method or separate protected-resource credentials.

```yaml
protected-resource:
  token-validation:
    method: INTROSPECTION
    audience: "api://orders"
    introspection:
      auth-method: CLIENT_SECRET_POST
      client-id: "${OIDC_INTROSPECTION_CLIENT_ID}"
      client-secret: "${OIDC_INTROSPECTION_CLIENT_SECRET}"
```

Supported introspection authentication methods are `CLIENT_SECRET_BASIC`, `CLIENT_SECRET_POST`, `CLIENT_SECRET_JWT`,
`PRIVATE_KEY_JWT`, `TLS_CLIENT_AUTH`, and `SELF_SIGNED_TLS_CLIENT_AUTH`. `NONE` is rejected for introspection. For
`CLIENT_SECRET_JWT` and `PRIVATE_KEY_JWT`, the assertion `aud` is the Introspection Endpoint URI. If well-known metadata
contains `introspection_endpoint_auth_methods_supported` or
`introspection_endpoint_auth_signing_alg_values_supported`, the configured method and assertion algorithm must be
included in those metadata values.

Introspection requires `client-id`, authentication credentials for the selected method, and either
`endpoints.introspection-endpoint-uri` or well-known metadata that provides `introspection_endpoint`.

Audience validation is enabled by default. Introspection responses with an `aud` claim must contain the configured
expected audience. If the Authorization Server omits `aud` from introspection responses, disable audience validation
explicitly.

```yaml
protected-resource:
  token-validation:
    method: INTROSPECTION
    audience-validation-enabled: false
```

RFC 7662 describes introspection responses as token metadata for protected-resource authorization decisions and says an
Authorization Server "MAY limit which scopes from a given token are returned" for each protected resource. `oidc-next`
maps selected introspection claims to principal attributes and grants according to `subject-mapping`, and also exposes
the full introspection response `JsonObject` through the subject's public `TokenCredential`. Configure the Authorization
Server introspection policy to return only claims this resource needs. `oidc-next` does not cache introspection responses
by default, so each Bearer Token validation uses the current Authorization Server response.

## RFC 8705 Certificate-Bound Access Tokens

RFC 8705 certificate-bound access tokens bind an access token to the client certificate used with mutual TLS. The
protected resource must validate both the access token and the request TLS client certificate. RFC 8705 says the
protected resource "MUST obtain" the client certificate from the TLS layer and "MUST verify" that it matches the token.
For JWT access tokens, the certificate SHA-256 thumbprint is carried in the JWT `cnf.x5t#S256` claim. For introspection,
the same `cnf.x5t#S256` object is returned as a top-level introspection response member.

Configure this only on endpoints where the WebServer TLS listener asks for client certificates. A dedicated mTLS socket
with `client-auth: REQUIRED` is the simplest deployment model:

```yaml
server:
  sockets:
    - name: "mtls"
      port: 8443
      tls:
        client-auth: "REQUIRED"
        trust:
          keystore:
            trust-store: true
            resource:
              resource-path: "trust.p12"
        private-key:
          keystore:
            resource:
              resource-path: "server.p12"

security:
  providers:
    - oidc-next:
        issuer: "https://issuer.example"
        endpoints:
          jwks-uri: "https://issuer.example/jwks"
        protected-resource:
          token-validation:
            method: JWT
            audience: "api://orders"
            certificate-bound-access-tokens:
              mode: REQUIRED
```

For a listener that serves both mTLS and non-mTLS resources, use WebServer `client-auth: OPTIONAL` and configure
`mode: IF_PRESENT` or endpoint routing so only the intended resources require certificate-bound tokens.

```yaml
server:
  tls:
    client-auth: "OPTIONAL"

security:
  providers:
    - oidc-next:
        issuer: "https://issuer.example"
        client-id: "${OIDC_INTROSPECTION_CLIENT_ID}"
        client-secret: "${OIDC_INTROSPECTION_CLIENT_SECRET}"
        protected-resource:
          token-validation:
            method: INTROSPECTION
            audience: "api://orders"
            certificate-bound-access-tokens:
              mode: IF_PRESENT
```

Modes:

- `DISABLED`: default. Certificate-bound access tokens are rejected on Bearer Token validation paths.
- `IF_PRESENT`: unbound access tokens are accepted normally; tokens or introspection responses with `cnf.x5t#S256`
  require a matching TLS client certificate.
- `REQUIRED`: every Protected Resource Bearer Token request must have `cnf.x5t#S256` and a matching TLS client
  certificate.

The certificate is propagated by the Helidon WebServer security integration through the request `SecurityEnvironment`.
`oidc-next` reads the `remotePeer` `PeerInfo` attribute and uses the first certificate from `PeerInfo.tlsCertificates()`.
It does not trust forwarded certificate headers. The thumbprint is computed as SHA-256 over the DER certificate bytes and
base64url-encoded without padding, matching the RFC 8705 `x5t#S256` definition.

When well-known metadata is loaded and certificate-bound validation is enabled, the metadata must advertise
`tls_client_certificate_bound_access_tokens: true`. RFC 8705 defines this metadata member as optional and says the
default is `false` when it is omitted.

This option applies to Protected Resource Bearer Token validation. Refreshed Authorization Code Flow access-token
validation continues to reject sender-constrained access tokens because the inbound browser TLS certificate is not the
OAuth client certificate used at the Token Endpoint.

## Bearer Token Transport

The provider accepts Bearer tokens from the `Authorization` header by default.

```yaml
token-transport:
  authorization-header-enabled: true
  query-parameter-enabled: false
  secure-transport-required: true
```

Enable query parameter transport only for compatibility cases that require it.

```yaml
token-transport:
  authorization-header-enabled: true
  query-parameter-enabled: true
  secure-transport-required: true
```

If a request contains multiple Bearer token sources, authentication fails instead of guessing which token to use.
When `secure-transport-required` is enabled, inbound Bearer token requests must use an effective HTTPS request URI or
transport as exposed by Helidon WebServer. Disable it only for isolated tests or equivalent non-production deployments.

Bearer `WWW-Authenticate` challenges include a `realm` auth-param. The default realm is `helidon`; override it on the
Protected Resource configuration when clients should see an application-specific protection space.

```yaml
protected-resource:
  challenge-realm: "orders-api"
```

## Authorization Code Flow

Enable Authorization Code Flow for browser login and local authentication cookies.

```yaml
security:
  providers:
    - oidc-next:
        issuer: "https://issuer.example"
        client-id: "${OIDC_CLIENT_ID}"
        client-secret: "${OIDC_CLIENT_SECRET}"
        authorization-code:
          scopes: [ "openid", "profile", "email" ]
        cookies:
          encryption-secret: "${OIDC_COOKIE_SECRET}"
```

When `authorization-code` is configured and not explicitly disabled:

- `client-id` is required.
- `authorization-code.redirection-endpoint-uri` defaults to `/oidc/callback`.
- `authorization-code.scopes` must contain `openid` and each value must be one RFC 6749 `scope-token`.
- `authorization-code.prompts`, when configured, are sent as the OIDC Authentication Request `prompt` parameter.
- `authorization-code.resources`, when configured, are sent as repeated RFC 8707 Authentication Request `resource`
  parameters.
- `cookies.encryption-secret` is required.
- An Authorization Endpoint and Token Endpoint are required, either explicitly or from well-known metadata.
- An issuer or well-known URI is required.

Authorization Response `iss` validation is automatic. If the callback contains `iss`, the provider requires an exact
string match with the issuer stored in the protected Authentication Request state. If well-known metadata advertises
`authorization_response_iss_parameter_supported: true`, callbacks without `iss` are rejected.

The default local callback path is resolved from the incoming request origin before it is sent as the OIDC
`redirect_uri`. When `endpoints.tls-required` is enabled, the resolved URI must use `https`. Configure
`authorization-code.redirection-endpoint-uri` only when the callback path or absolute callback URI must differ.

Pushed Authorization Requests (PAR) are enabled in `AUTO` mode by default for Authorization Code Flow. With PAR, the
provider POSTs the Authentication Request parameters directly to the Authorization Server using the tenant WebClient,
receives a short `request_uri`, and redirects the browser with only `client_id` and that `request_uri`. RFC 9126 says
the pushed request body "MUST NOT" include `request_uri`, the successful response uses HTTP `201`, and the client
"MUST only use a `request_uri` value once."

`AUTO` uses PAR when a static `endpoints.pushed-authorization-request-endpoint-uri` is configured or when already-loaded
well-known metadata advertises `pushed_authorization_request_endpoint`. `AUTO` does not load well-known metadata only to
discover optional PAR support. If loaded metadata sets `require_pushed_authorization_requests: true`, `AUTO` requires PAR
and fails tenant initialization unless a PAR endpoint is available. `REQUIRED` always requires a PAR endpoint from static
config or metadata, and may load well-known metadata to discover it. `DISABLED` never sends PAR; if loaded metadata says
PAR is required, tenant initialization fails clearly instead of attempting a normal authorization redirect.

```yaml
authorization-code:
  pushed-authorization-requests: AUTO
```

For static Authorization Server configuration, configure the PAR endpoint under `endpoints`.

```yaml
endpoints:
  authorization-endpoint-uri: "https://issuer.example/authorize"
  token-endpoint-uri: "https://issuer.example/token"
  pushed-authorization-request-endpoint-uri: "https://issuer.example/par"

authorization-code:
  pushed-authorization-requests: REQUIRED
```

PAR uses the same Token Endpoint client authentication method configured by `token-endpoint-auth-method`. For
`CLIENT_SECRET_JWT` and `PRIVATE_KEY_JWT`, RFC 9126 says the Authorization Server issuer identifier should be used as the
client assertion audience; the provider uses the issuer when available and otherwise falls back to the PAR endpoint URI.

Signed Request Objects use RFC 9101 JWT-Secured Authorization Requests (JAR). RFC 9101 says the Request Object contains
the authorization request parameters as JWT claims, excludes `request` and `request_uri`, and signs the JWT claims set.
OpenID Connect Core also requires `response_type`, `client_id`, and `scope` to remain in the outer OAuth request syntax
when the by-value `request` parameter is used. `oidc-next` therefore sends only outer `response_type`, `client_id`,
`scope`, and `request` for normal by-value JAR redirects; the full request, including `redirect_uri`, `state`, `nonce`,
PKCE, prompts, and resource indicators, is inside the signed Request Object.

Configure Request Object signing under `authorization-code.request-object`.

```yaml
authorization-code:
  scopes: [ "openid", "profile" ]
  request-object:
    mode: REQUIRED
    jwk:
      resource-path: "private-request-object-jwks.json"
    key-id: "request-object-signing-key"
    algorithm: RS256
    lifetime: "PT1M"
```

Modes:

- `DISABLED`: never sends Request Objects. If loaded metadata has `require_signed_request_object: true`, tenant
  initialization fails.
- `AUTO`: default. Signs when `request-object.jwk` is configured, and requires signing when loaded metadata has
  `require_signed_request_object: true`. Without local signing key material and without a metadata requirement, the
  normal Authorization Code request is unchanged.
- `REQUIRED`: every Authentication Request uses a signed Request Object. `request-object.jwk` is required.

The Request Object signing key is local client private key material. It must correspond to a public key registered at the
Authorization Server for Request Object validation. It is separate from the provider `jwks-uri`, which is the OP public
key set used to verify ID Tokens or access tokens, and separate from `client-assertion.jwk`, which is used for
`private_key_jwt` endpoint authentication. Supported Request Object signing keys are RSA and EC private JWKs using the
same JWS algorithms as `PRIVATE_KEY_JWT`, such as `RS256` or `ES256`. `alg=none`, unsigned Request Objects, encrypted
Request Objects, and hosted client `request_uri` are not supported. URI-backed `request-object.jwk` resources are
rejected before the resource is created; use classpath, file, or configured content resources for this local private key
material.

Request Objects can be combined with PAR. In that mode the PAR body contains the signed `request` parameter plus any
client-authentication parameters required by the selected client authentication method; authorization request parameters
remain inside the signed JWT claims. The browser redirect remains the PAR redirect with only `client_id` and the
server-generated `request_uri`.

PKCE is enabled by default and uses `S256`.
When Authorization Code Flow loads well-known metadata, `code_challenge_methods_supported` must include the configured
method. RFC 8414 says that when this metadata is omitted, the authorization server does not support PKCE.

```yaml
authorization-code:
  scopes: [ "openid", "profile" ]
  pkce-required: true
  pkce-method: S256
```

Use `authorization-code.prompts` for explicit OpenID Connect prompt behavior such as reauthentication, consent, or account
selection. Provider-specific prompt values are allowed when they use the same visible ASCII token format.

```yaml
authorization-code:
  scopes: [ "openid", "profile" ]
  prompts: [ "login" ]
```

The `none` prompt value cannot be combined with any other prompt value. If `authorization-code.scopes` contains
`offline_access`, the provider ensures the request contains `prompt=consent`, because OpenID Connect Core requires
consent when offline access is requested unless other processing conditions permit it. A configured `prompt: none` is
therefore rejected with `offline_access`.

```yaml
authorization-code:
  scopes: [ "openid", "profile", "offline_access" ]
```

Use `authorization-code.resources` when the Authorization Server requires RFC 8707 resource indicators during browser
login or when the login access token must be issued for a specific protected resource. RFC 8707 defines `resource` as the
target service "to which access is being requested" and says the value "MUST be an absolute URI" and "MUST NOT include a
fragment component." The provider validates those URI rules, rejects blanks, padded values, and duplicates, and sends one
`resource` query parameter per configured value.

Resources are not emitted by default and are not derived from the incoming browser URL. The browser URL is the RP page
that initiated login; the RFC 8707 resource is the protected resource or API where the resulting access token will be
used. Configure the value explicitly and prefer one resource when possible. Multiple resources are allowed by the spec,
but they can produce multi-audience bearer tokens that require strong trust between the protected resources.

```yaml
authorization-code:
  scopes: [ "openid", "profile" ]
  resources:
    - "https://api.example.com"
```

The provider sends the same configured `resources` on the front-channel Authentication Request, the back-channel
authorization-code Token Endpoint exchange, and refresh-token requests. RFC 8707 says a Token Endpoint `resource`
parameter applies "for all grant types" and that, for `authorization_code` and `refresh_token`, the Authorization Server
can limit acceptable resources to those originally granted or a subset. `oidc-next` does not currently expose separate
subset configuration for the token exchange or refresh, because a static login config cannot identify which
resource-specific token an application needs later at runtime.

Use `pkce-method: plain` only for compatibility with a legacy authorization server that cannot process `S256`.
Public clients, where `token-endpoint-auth-method` is `NONE`, must use `S256`; the provider rejects `plain` in that
mode.

```yaml
client-secret: "${OIDC_CLIENT_SECRET}"
authorization-code:
  scopes: [ "openid", "profile" ]
  pkce-method: plain
```

PKCE can be disabled only for confidential-client compatibility with providers that cannot process it. Public clients,
where `token-endpoint-auth-method` is `NONE`, must use PKCE; the provider rejects `pkce-required: false` in that mode.

```yaml
client-secret: "${OIDC_CLIENT_SECRET}"
authorization-code:
  scopes: [ "openid", "profile" ]
  pkce-required: false
```

### ID Token Audience Trust

ID Tokens must list this provider's `client-id` in the `aud` claim. If the ID Token contains additional `aud` values,
OpenID Connect Core requires those additional audiences to be trusted by the client. The provider rejects additional
audiences by default. Configure `id-token.trusted-additional-audiences` only for other audience values that this client
registration is expected to receive and trust.

When `aud` contains more than one value, the provider also requires `azp` to equal `client-id`.

```yaml
id-token:
  trusted-additional-audiences:
    - "api://shared"
```

### Encrypted ID Tokens

The `id-token` block controls ID Token validation policy. By default, signed ID Tokens must use `RS256`, encrypted ID
Tokens must use JWE `alg` `RSA-OAEP-256` or `RSA-OAEP`, encrypted ID Tokens must use JWE `enc` `A256GCM` or
`A128CBC-HS256`, signed-only ID Tokens are accepted, and decryption keys are not configured.

If the OpenID Provider returns encrypted ID Tokens, configure `id-token.decryption-jwk` with the private JWK Set resource
used to decrypt them. Set `id-token.encryption-required: true` only when your client registration requires encrypted ID
Tokens and signed-only ID Tokens should fail.

```yaml
security:
  providers:
    - oidc-next:
        issuer: "https://issuer.example"
        client-id: "${OIDC_CLIENT_ID}"
        client-secret: "${OIDC_CLIENT_SECRET}"
        id-token:
          allowed-algorithms: [ "RS256" ]
          allowed-encryption-algorithms: [ "RSA-OAEP-256", "RSA-OAEP" ]
          allowed-content-encryption-algorithms: [ "A256GCM", "A128CBC-HS256" ]
          decryption-jwk:
            resource-path: "rp-id-token-decryption-jwks.json"
          encryption-required: true
        authorization-code:
          redirection-endpoint-uri: "https://app.example/oidc/callback"
          scopes: [ "openid", "profile" ]
        cookies:
          encryption-secret: "${OIDC_COOKIE_SECRET}"
```

The provider requires encrypted ID Tokens to be nested JWTs (`cty=JWT`), decrypts the outer JWE, and then validates the
inner signed JWT with the normal ID Token validation rules and the OpenID Provider JWK Set. Signed ID Tokens remain
accepted when decryption keys are configured unless `encryption-required` is enabled; decryption keys mean that encrypted
ID Tokens can be processed.

The decryption JWK Set should contain private client/RP encryption keys. If more than one decryption key is configured,
the encrypted ID Token JWE header must contain `kid`. When a JWK declares `use`, the value must be `enc`; when it
declares `key_ops`, it must allow `unwrapKey` or `decrypt`. `RSA1_5` is not allowed by default because RFC 7516
describes downgrade and oracle risks for it. It can still be added to `allowed-encryption-algorithms` for a legacy
OpenID Provider that cannot use RSA-OAEP.

The protected local authentication cookie stores the original ID Token value. When that value is encrypted, the provider
decrypts it again when the local authentication result is restored. RP-Initiated Logout also sends the original OpenID
Provider-issued ID Token as `id_token_hint`; if that hint is encrypted, the provider includes `client_id` as well.

This option applies only to ID Tokens. It does not enable encrypted access-token validation.

Programmatic configuration:

```java
OidcProviderConfig config = OidcProviderConfig.builder()
        .issuer("https://issuer.example")
        .clientId(System.getenv("OIDC_CLIENT_ID"))
        .clientSecret(System.getenv("OIDC_CLIENT_SECRET"))
        .idToken(idToken -> idToken
                .allowedAlgorithms(List.of("RS256"))
                .allowedEncryptionAlgorithms(List.of("RSA-OAEP-256", "RSA-OAEP"))
                .allowedContentEncryptionAlgorithms(List.of("A256GCM", "A128CBC-HS256"))
                .decryptionJwk(Resource.create("rp-id-token-decryption-jwks.json"))
                .encryptionRequired(true))
        .authorizationCode(authorizationCode -> authorizationCode
                .redirectionEndpointUri(URI.create("https://app.example/oidc/callback"))
                .scopes(List.of("openid", "profile")))
        .cookies(cookies -> cookies.encryptionSecret(System.getenv("OIDC_COOKIE_SECRET")))
        .buildPrototype();
```

### Reverse Proxies

When Authorization Code Flow runs behind a reverse proxy, configure Helidon WebServer requested URI discovery so the
provider sees the external request URI. The provider stores only the local path and query in Authentication Request state
and uses a root-relative redirect after the Authorization Response is processed. The default local redirection endpoint
path is still resolved from the discovered external origin before it is sent to the OpenID Provider as `redirect_uri`.

```yaml
server:
  requested-uri-discovery:
    types: x-forwarded
    trusted-proxies:
      allow:
        exact: "traefik.internal"
```

For path-prefix deployments, the proxy should send `X-Forwarded-Host`, `X-Forwarded-Proto`,
`X-Forwarded-Prefix`, and `X-Forwarded-For`. Configure `trusted-proxies` for the proxy hosts or addresses that are
allowed to provide those headers.

## UserInfo

Configure `user-info` to request UserInfo after Authorization Code Flow token exchange and ID Token validation.

```yaml
security:
  providers:
    - oidc-next:
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
          storage-policy: mapped
          attribute-claim-paths: [ "email", "department" ]
        cookies:
          encryption-secret: "${OIDC_COOKIE_SECRET}"
```

When `user-info` is configured and not explicitly disabled:

- Authorization Code Flow must be configured and enabled.
- A UserInfo Endpoint is required, either explicitly or from well-known metadata.
- The provider calls the UserInfo Endpoint with the access token returned by the Token Endpoint.
- Without `user-info.jwt`, the registered/default response format is JSON and the response must use
  `Content-Type: application/json`.
- With `user-info.jwt`, the response must use `Content-Type: application/jwt`. The configured registration algorithms
  determine whether the response must be signed, encrypted, or signed and then encrypted.
- Signed JWT UserInfo responses are verified with the OpenID Provider JWK Set. The JWT `iss` must match the issuer,
  `aud` must include the tenant `client-id`, optional time claims are validated, and `sub` must exactly match the ID
  Token `sub`.
- Encryption-only UserInfo responses are decrypted directly to a JSON Claims Set. OpenID Connect does not require
  `iss` or `aud` when the response is not signed, but `sub` remains mandatory and must exactly match the ID Token.
- The UserInfo response must contain `sub`, and it must exactly match the ID Token `sub`.

The `user-info.jwt` values must match the client metadata registered at the OpenID Provider. They are exact negotiated
algorithms, not allow-lists:

| Configuration | Registered metadata | Required response |
| --- | --- | --- |
| `user-info.jwt` omitted | No JWT response metadata | JSON object |
| `signing-algorithm` | `userinfo_signed_response_alg` | Signed JWS |
| `encryption-algorithm` | `userinfo_encrypted_response_alg` | Directly encrypted Claims Set |
| Both algorithms | Both metadata values | Signed JWS encrypted as a Nested JWT |

Signed and encrypted UserInfo:

```yaml
user-info:
  jwt:
    signing-algorithm: "RS256"
    encryption-algorithm: "RSA-OAEP-256"
    content-encryption-algorithm: "A256GCM"
    decryption-jwk:
      resource-path: "userinfo-decryption-jwks.json"
```

For encryption-only UserInfo, omit `signing-algorithm`. For signed-only UserInfo, configure only `signing-algorithm`;
decryption keys are then unnecessary. If `encryption-algorithm` is configured and `content-encryption-algorithm` is
omitted, the OpenID Connect Registration default `A128CBC-HS256` is required.

Supported JWE key management algorithms are `RSA-OAEP-256`, `RSA-OAEP`, and legacy `RSA1_5`. Supported content
encryption algorithms are `A128GCM`, `A192GCM`, `A256GCM`, `A128CBC-HS256`, `A192CBC-HS384`, and
`A256CBC-HS512`. `RSA1_5` is not recommended and emits a startup warning. UserInfo signing algorithm `none` and `HS*`
algorithms are rejected. When well-known metadata publishes UserInfo signing or encryption capabilities, the configured
registration algorithms must be advertised.

UserInfo and ID Token algorithms are separate client-registration properties. Their configuration is therefore kept
separate. Both can reference the same private JWK Set resource when the provider registration uses the same RP key, but
configuring ID Token decryption does not implicitly enable UserInfo decryption.

By default, `storage-policy: mapped` stores only the UserInfo `sub`, claims used by `subject-mapping`, and claims listed
in `attribute-claim-paths`. This follows the OpenID Connect Core privacy guidance: "Only necessary UserInfo data should
be stored at the Client". Stored UserInfo claims are kept in the protected local authentication result cookie and merged
into subject attributes on later requests. UserInfo claims override ID Token claims with the same name for principal
attributes, principal name, and roles, except ID Token protocol and authentication claims remain ID Token sourced.
Principal id still comes from the validated ID Token claim mapping.

Use `attribute-claim-paths` for additional UserInfo claims that should be exposed as principal attributes but are not
used by `subject-mapping`.

```yaml
user-info:
  storage-policy: mapped
  attribute-claim-paths: [ "email", "department", "iam.cost_center" ]
```

Use `storage-policy: all` only when the application intentionally needs the complete UserInfo JSON object stored in the
protected cookie and exposed through subject attributes.

```yaml
user-info:
  storage-policy: all
```

Use `storage-policy: none` when the provider should call UserInfo and enforce the `sub` match but should not store any
UserInfo claims in the local authentication result.

```yaml
user-info:
  storage-policy: none
```

Refresh-token renewal re-requests UserInfo when `user-info` is enabled and stores the refreshed UserInfo claims only
after the refreshed UserInfo `sub` matches the ID Token `sub`.

Programmatic configuration:

```java
OidcProviderConfig config = OidcProviderConfig.builder()
        .issuer("https://issuer.example")
        .clientId("client-id")
        .clientSecret("client-secret")
        .endpoints(endpoints -> endpoints
                .userInfoEndpointUri(URI.create("https://issuer.example/userinfo")))
        .authorizationCode(authorizationCode -> authorizationCode
                .redirectionEndpointUri(URI.create("https://app.example/oidc/callback"))
                .scopes(List.of("openid", "profile", "email")))
        .userInfo(userInfo -> userInfo
                .jwt(jwt -> jwt
                        .signingAlgorithm("RS256")
                        .encryptionAlgorithm("RSA-OAEP-256")
                        .contentEncryptionAlgorithm("A256GCM")
                        .decryptionJwk(Resource.create("userinfo-decryption-jwks.json")))
                .storagePolicy(OidcUserInfoStoragePolicy.MAPPED)
                .attributeClaimPaths(List.of("email", "department")))
        .cookies(cookies -> cookies.encryptionSecret(System.getenv("OIDC_COOKIE_SECRET")))
        .buildPrototype();
```

## Local Logout Endpoint

Configure `logout` to register the local `POST` logout endpoint in `OidcFeature`.

```yaml
security:
  providers:
    - oidc-next:
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
when `id_token_hint` is omitted. The provider also sends `client_id` when `id_token_hint` contains an encrypted ID Token.

RP-Initiated Logout says that without `id_token_hint`, the OP `MUST NOT perform post-logout redirection` unless it can
otherwise confirm the redirect target, so this mode can cause a compliant OP to ignore `post_logout_redirect_uri`.

The default `id-token-hint-required: true` mode requires Authorization Code Flow because the ID Token comes from local
authentication result storage.

The configured `post-logout-redirect-uri` is sent by default. A logout request may provide
`post_logout_redirect_uri`; the provider accepts it only when it exactly matches the configured default URI or one of
`allowed-post-logout-redirect-uris`. If `post_logout_redirect_uri` is accepted and the request contains `state`, the
provider includes `state` in the End Session request.
Every configured post-logout redirect value must also be registered with the OpenID Provider as an exact
`post_logout_redirect_uris` value.

`endpoints.end-session-endpoint-uri`, `post-logout-redirect-uri`, and `allowed-post-logout-redirect-uris` must use
HTTPS unless `endpoints.tls-required` is disabled, and must not contain fragments.

If several tenants share a logout path and the request does not identify exactly one tenant through a local
authentication result cookie, the endpoint only clears local cookies for the matching path tenants and returns
`204 No Content`; it does not guess which OpenID Provider End Session Endpoint to use.

Programmatic configuration:

```java
OidcProviderConfig config = OidcProviderConfig.builder()
        .issuer("https://issuer.example")
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

## Endpoint Client Authentication

`token-endpoint-auth-method` controls how the client authenticates to the Token Endpoint for Authorization Code Flow,
refresh-token requests, and Client Credentials Grant.

```yaml
token-endpoint-auth-method: CLIENT_SECRET_BASIC
```

Available values:

- `CLIENT_SECRET_BASIC`: send `client_id` and `client_secret` using HTTP Basic authentication.
- `CLIENT_SECRET_POST`: send `client_id` and `client_secret` in the form body.
- `CLIENT_SECRET_JWT`: send a JWT client assertion signed with `client-secret`.
- `PRIVATE_KEY_JWT`: send a JWT client assertion signed with configured private JWK material.
- `TLS_CLIENT_AUTH`: use the RFC 8705 PKI Mutual-TLS Method and send `client_id` in the form body. The certificate
  identity is matched by the Authorization Server against the client's registered subject or subject alternative name
  metadata.
- `SELF_SIGNED_TLS_CLIENT_AUTH`: use the RFC 8705 Self-Signed Certificate Mutual-TLS Method and send `client_id` in the
  form body. The certificate or public key is matched by the Authorization Server against the client's registered
  self-signed certificate metadata.
- `NONE`: send only `client_id`; use for public clients.

When omitted, the provider uses:

- `CLIENT_SECRET_BASIC` if `client-secret` is configured.
- `NONE` if `client-secret` is not configured.

Example using `client_secret_post`:

```yaml
security:
  providers:
    - oidc-next:
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

Example using `client_secret_jwt`:

```yaml
security:
  providers:
    - oidc-next:
        issuer: "https://issuer.example"
        client-id: "${OIDC_CLIENT_ID}"
        client-secret: "${OIDC_CLIENT_SECRET}"
        token-endpoint-auth-method: CLIENT_SECRET_JWT
        client-assertion:
          algorithm: HS256
          lifetime: "PT1M"
        authorization-code:
          redirection-endpoint-uri: "https://app.example/oidc/callback"
        cookies:
          encryption-secret: "${OIDC_COOKIE_SECRET}"
```

Example using `private_key_jwt`:

```yaml
security:
  providers:
    - oidc-next:
        issuer: "https://issuer.example"
        client-id: "${OIDC_CLIENT_ID}"
        token-endpoint-auth-method: PRIVATE_KEY_JWT
        client-assertion:
          jwk:
            resource-path: "private-client-jwks.json"
          key-id: "client-signing-key"
          algorithm: RS256
          lifetime: "PT1M"
        authorization-code:
          redirection-endpoint-uri: "https://app.example/oidc/callback"
        cookies:
          encryption-secret: "${OIDC_COOKIE_SECRET}"
```

`client_secret_jwt` and `private_key_jwt` send `client_assertion_type` with
`urn:ietf:params:oauth:client-assertion-type:jwt-bearer` and a signed `client_assertion` JWT. The assertion uses
`client-id` as `iss` and `sub`, the Token Endpoint URI as `aud`, and includes `iat`, `exp`, and `jti`.
For `CLIENT_SECRET_JWT`, `algorithm` defaults to `HS256`; configure `key-id` if the Authorization Server expects a
`kid` header on the assertion. For `PRIVATE_KEY_JWT`, `jwk` is required, `algorithm` must match the selected JWK
algorithm, and `key-id` is required when the configured JWK Set contains more than one key.
When well-known metadata is loaded, the configured method must be listed in `token_endpoint_auth_methods_supported`.
If the metadata omits that entry, the Discovery default is `client_secret_basic`. JWT client authentication additionally
requires `token_endpoint_auth_signing_alg_values_supported` to include the assertion signing algorithm; no default
assertion signing algorithms are assumed.

The same authentication methods can be used for Token Introspection, but introspection is configured under
`protected-resource.token-validation.introspection`. If `introspection.client-assertion` is omitted, the tenant
`client-assertion` is reused. For introspection assertions, the `aud` claim is the Introspection Endpoint URI.

Example using `tls_client_auth`:

```yaml
security:
  providers:
    - oidc-next:
        issuer: "https://issuer.example"
        client-id: "${OIDC_CLIENT_ID}"
        token-endpoint-auth-method: TLS_CLIENT_AUTH
        webclient:
          tls:
            trust:
              keystore:
                passphrase: "${OIDC_TLS_TRUST_STORE_PASSWORD}"
                trust-store: true
                resource:
                  resource-path: "issuer-trust.p12"
            private-key:
              keystore:
                passphrase: "${OIDC_TLS_CLIENT_KEY_STORE_PASSWORD}"
                resource:
                  resource-path: "oidc-client.p12"
        authorization-code:
          redirection-endpoint-uri: "https://app.example/oidc/callback"
        cookies:
          encryption-secret: "${OIDC_COOKIE_SECRET}"
```

For `TLS_CLIENT_AUTH` and `SELF_SIGNED_TLS_CLIENT_AUTH`, the OIDC provider sends `client_id` in the Token Endpoint form
and relies on enabled tenant `webclient.tls` for the mutual TLS client certificate proof. Configure private key plus
certificate chain, an SSL context, or a custom TLS manager. The `private-key` TLS block supplies the client
certificate/key used for mutual TLS. The `trust` TLS block validates the Authorization Server certificate. When
well-known metadata supplies both `token_endpoint` and `mtls_endpoint_aliases.token_endpoint`, mTLS Token Endpoint
requests use the alias unless `endpoints.token-endpoint-uri` is explicitly configured. RFC 8705 Token Endpoint client
authentication always requires an HTTPS Token Endpoint. If the Token Endpoint is loaded from well-known metadata, the
well-known URI must also use HTTPS. `endpoints.tls-required: false` does not relax these mTLS requirements.

Programmatic `private_key_jwt` configuration:

```java
OidcProviderConfig config = OidcProviderConfig.builder()
        .issuer("https://issuer.example")
        .clientId(System.getenv("OIDC_CLIENT_ID"))
        .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.PRIVATE_KEY_JWT)
        .clientAssertion(clientAssertion -> clientAssertion
                .jwk(Resource.create("private-client-jwks.json"))
                .keyId("client-signing-key")
                .algorithm("RS256"))
        .authorizationCode(authorizationCode -> authorizationCode
                .redirectionEndpointUri(URI.create("https://app.example/oidc/callback")))
        .cookies(cookies -> cookies.encryptionSecret(System.getenv("OIDC_COOKIE_SECRET")))
        .buildPrototype();
```

Example public client:

```yaml
security:
  providers:
    - oidc-next:
        issuer: "https://issuer.example"
        client-id: "${OIDC_CLIENT_ID}"
        token-endpoint-auth-method: NONE
        authorization-code:
          redirection-endpoint-uri: "https://app.example/oidc/callback"
          scopes: [ "openid", "profile" ]
        cookies:
          encryption-secret: "${OIDC_COOKIE_SECRET}"
```

## Outbound Token Propagation, Client Credentials, And Token Exchange

Outbound target selection uses Helidon's common `OutboundTarget` model. Configure targets as the provider-level
`outbound` list. A target can match by transport, host, path, and method. The matching target selects the OIDC outbound
action; the resolved tenant supplies the issuer, client credentials, Token Endpoint, and TLS settings used to perform
that action.

Token Propagation sends the current user `TokenCredential` as `Authorization: Bearer <access-token>`. It is never applied
without a matching outbound target. By default, the matching outbound target must also configure the downstream
`audience`. The provider propagates only JWT or introspection-backed access tokens whose `aud` claim contains that
audience, otherwise it abstains. This audience is the downstream resource server identifier, not the current service's
`protected-resource.token-validation.audience`.

```yaml
security:
  providers:
    - oidc-next:
        issuer: "https://issuer.example"
        outbound:
          - name: orders-api
            transports: [ "https" ]
            hosts: [ "orders.internal.example" ]
            paths: [ "/orders/.*" ]
            token-propagation-enabled: true
            audience: "api://orders"
```

Target configuration can select the OIDC outbound strategy directly and can restrict different downstream services with
different audiences.

```yaml
security:
  providers:
    - oidc-next:
        issuer: "https://issuer.example"
        outbound:
          - name: orders-api
            transports: [ "https" ]
            hosts: [ "orders.internal.example" ]
            paths: [ "/orders/.*" ]
            token-propagation-enabled: true
            audience: "api://orders"
          - name: billing-api
            transports: [ "https" ]
            hosts: [ "billing.internal.example" ]
            paths: [ "/billing/.*" ]
            token-propagation-enabled: true
            audience: "api://billing"
```

Set `audience-validation-enabled: false` on an outbound target only for testing, local development, or legacy opaque-token
deployments where this provider cannot inspect token claims. With validation disabled, matching target rules still apply,
but the provider cannot locally verify that the token was meant for the downstream resource.

Client Credentials Grant obtains an access token from the Token Endpoint with `grant_type=client_credentials` and applies
the same Token Endpoint client authentication settings as Authorization Code Flow and refresh-token requests. The token is
cached until it is close to expiration, then reacquired.

Configure Client Credentials Grant scopes on the matching outbound target. OAuth scopes describe the access requested for
the token, and for outbound calls that access is normally tied to the downstream resource API selected by the target.
Keeping scopes on the target allows least-privilege tokens for different downstream services while still using the same
tenant client credentials and Token Endpoint. For example, an orders API can request `orders.read` while a billing API
requests `billing.read`; these scoped tokens are cached separately.
The tenant describes the OAuth client and Authorization Server connection; the outbound target describes the resource API
access being requested for a specific outbound call.

Configure `client-credentials-resources` when the Authorization Server supports RFC 8707 Resource Indicators and needs
the intended downstream resource in the token request. RFC 8707 says `resource` "MUST be an absolute URI" and "MUST NOT
include a fragment component." The provider preserves the configured string value, rejects blank, padded, duplicate,
relative, and fragment-containing resource values, sends one Token Endpoint `resource` form parameter per configured
value, and caches Client Credentials tokens separately by tenant, scopes, and resources.

Resource indicators are not scopes. RFC 8707 says OAuth scope is "sometimes overloaded to convey the location or identity
of the protected resource", but scope normally describes what access is requested while `resource` identifies where the
token will be redeemed. Prefer one resource per outbound target and token. Multiple resource values ask for a token
usable at all requested resources, which requires those resources to trust each other against bearer-token replay.
Resource indicators also reveal intended downstream targets to the Authorization Server; RFC 8707 says they can allow
tracking at a "more granular and specific level" than would otherwise be possible.

Client Credentials Grant is only valid for confidential clients. Configure `client-id`, either
`endpoints.token-endpoint-uri` or well-known metadata that provides the Token Endpoint, and the prerequisites for the
selected Token Endpoint client authentication method. Secret-based methods require `client-secret`; `PRIVATE_KEY_JWT`
requires `client-assertion.jwk`; mutual TLS methods require enabled tenant `webclient.tls` with private key plus
certificate chain, an SSL context, or a custom TLS manager. The provider relies on Helidon WebClient TLS for the
certificate handshake, and the Token Endpoint must use HTTPS. `token-endpoint-auth-method: NONE` is rejected for this
grant.
When Client Credentials Grant loads well-known metadata, `grant_types_supported` must contain `client_credentials`.
If `grant_types_supported` is omitted, the RFC 8414 default does not include `client_credentials`, so the provider treats
the grant as unsupported. The configured Token Endpoint authentication method is validated the same way as for
Authorization Code Flow.

If any provider `outbound` target enables Client Credentials Grant directly, each enabled tenant must meet these Client
Credentials prerequisites because the resolved tenant supplies the Token Endpoint and client authentication settings.

```yaml
security:
  providers:
    - oidc-next:
        client-id: "${OIDC_CLIENT_ID}"
        client-secret: "${OIDC_CLIENT_SECRET}"
        token-endpoint-auth-method: CLIENT_SECRET_BASIC
        endpoints:
          token-endpoint-uri: "https://issuer.example/token"
        outbound:
          - name: inventory-api
            transports: [ "https" ]
            hosts: [ "inventory.internal.example" ]
            client-credentials-grant-enabled: true
            client-credentials-scopes: [ "inventory.read" ]
            client-credentials-resources: [ "https://inventory.example.com" ]
```

Token Exchange obtains a downstream access token from the Token Endpoint with RFC 8693
`grant_type=urn:ietf:params:oauth:grant-type:token-exchange`. It uses the current subject `TokenCredential` token as
`subject_token`, sends `subject_token_type=urn:ietf:params:oauth:token-type:access_token`, requests
`requested_token_type=urn:ietf:params:oauth:token-type:access_token`, and attaches the issued token as
`Authorization: Bearer <access-token>`. Token Exchange is only applied through matching outbound targets or an
endpoint-level `OidcOutboundPolicy`; if the current request has no subject token to exchange, the provider abstains.

Token Exchange target configuration is separate from Token Propagation audience validation:

- `token-exchange-resource` is sent to the Token Endpoint as RFC 8693 `resource`. RFC 8693 says this value "MUST be an
  absolute URI" and "MUST NOT include a fragment component."
- `token-exchange-audience` is sent to the Token Endpoint as RFC 8693 `audience`. It asks the Authorization Server for a
  token intended for that logical target.
- `audience` is not sent during Token Exchange. It is only the local Token Propagation `aud` check.
- `token-exchange-scopes` are serialized as one OAuth `scope` form parameter and apply in the context of the requested
  downstream resource or audience.

At least one of `token-exchange-resource` or `token-exchange-audience` must be configured so the provider does not ask for
an untargeted exchanged token. Token Exchange is mutually exclusive with Token Propagation and Client Credentials Grant on
the same outbound target.

Token Exchange uses the same tenant Token Endpoint, WebClient, TLS, and client authentication settings as Authorization
Code Flow and Client Credentials Grant. Configure `client-id`, either `endpoints.token-endpoint-uri` or well-known metadata
that provides the Token Endpoint, and a Token Endpoint authentication method other than `NONE`. When well-known metadata
includes `grant_types_supported`, it must include `urn:ietf:params:oauth:grant-type:token-exchange`; if that optional
metadata member is omitted, static configuration can still proceed.

The first Token Exchange implementation intentionally supports only issued Bearer access tokens. The Token Endpoint
successful response must contain `issued_token_type=urn:ietf:params:oauth:token-type:access_token` and
`token_type=Bearer`. `token_type=N_A`, issued ID Tokens, SAML assertions, refresh-token exchange, actor-token delegation,
and first-class `act` or `may_act` handling are not implemented by this outbound mode.

Exchanged tokens are cached only when the response includes a positive `expires_in`. The cache key includes the tenant id,
a SHA-256 hash of the subject token, configured scopes, resource, and audience. Raw subject tokens are not stored in cache
keys. The cache uses the tenant token-validation clock skew and does not assume that input-token revocation automatically
revokes already exchanged tokens.

```yaml
security:
  providers:
    - oidc-next:
        client-id: "${OIDC_CLIENT_ID}"
        client-secret: "${OIDC_CLIENT_SECRET}"
        token-endpoint-auth-method: CLIENT_SECRET_BASIC
        endpoints:
          token-endpoint-uri: "https://issuer.example/token"
        outbound:
          - name: orders-api
            transports: [ "https" ]
            hosts: [ "orders.internal.example" ]
            paths: [ "/orders/.*" ]
            token-exchange-enabled: true
            token-exchange-scopes: [ "orders.read" ]
            token-exchange-resource: "https://orders.example.com"
            token-exchange-audience: "api://orders"
```

Client Credentials Grant for outbound is only applied through matching `outbound` targets or an endpoint-level
`OidcOutboundPolicy`.

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
        .issuer("https://issuer.example")
        .outboundTargets(List.of(ordersApi))
        .buildPrototype();
```

Endpoint-level Token Propagation:

```java
EndpointConfig outboundEndpoint = EndpointConfig.builder()
        .customObject(OidcOutboundPolicy.class, OidcOutboundPolicy.tokenPropagation("api://orders"))
        .build();
```

Endpoint-level Token Propagation without audience validation is explicit:

```java
EndpointConfig outboundEndpoint = EndpointConfig.builder()
        .customObject(OidcOutboundPolicy.class, OidcOutboundPolicy.tokenPropagationWithoutAudienceValidation())
        .build();
```

Endpoint-level Client Credentials Grant:

```java
EndpointConfig outboundEndpoint = EndpointConfig.builder()
        .customObject(OidcOutboundPolicy.class,
                      OidcOutboundPolicy.clientCredentialsGrant(List.of("inventory.read"),
                                                                List.of("https://inventory.example.com")))
        .build();
```

Endpoint-level Token Exchange:

```java
EndpointConfig outboundEndpoint = EndpointConfig.builder()
        .customObject(OidcOutboundPolicy.class,
                      OidcOutboundPolicy.tokenExchange(List.of("orders.read"),
                                                       "https://orders.example.com",
                                                       "api://orders"))
        .build();
```

Use `OidcOutboundPolicy.tokenExchangeForResource(...)` or
`OidcOutboundPolicy.tokenExchangeForAudience(...)` when only one Token Exchange target parameter is needed.

Programmatic Client Credentials Grant target configuration with scopes and a resource indicator:

```java
OidcOutboundTargetConfig targetPolicy = OidcOutboundTargetConfig.builder()
        .clientCredentialsGrantEnabled(true)
        .addClientCredentialsScope("orders.read")
        .addClientCredentialsResource("https://orders.example.com")
        .buildPrototype();

OutboundTarget ordersApi = OutboundTarget.builder("orders-api")
        .addTransport("https")
        .addHost("orders.internal.example")
        .addPath("/orders/.*")
        .customObject(OidcOutboundTargetConfig.class, targetPolicy)
        .build();
```

Programmatic Token Exchange target configuration with scopes, a resource, and an audience:

```java
OidcOutboundTargetConfig targetPolicy = OidcOutboundTargetConfig.builder()
        .tokenExchangeEnabled(true)
        .addTokenExchangeScope("orders.read")
        .tokenExchangeResource("https://orders.example.com")
        .tokenExchangeAudience("api://orders")
        .buildPrototype();

OutboundTarget ordersApi = OutboundTarget.builder("orders-api")
        .addTransport("https")
        .addHost("orders.internal.example")
        .addPath("/orders/.*")
        .customObject(OidcOutboundTargetConfig.class, targetPolicy)
        .build();
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
  principal-id-mode: issuer-subject
  principal-id-claim-paths: [ "sub", "username", "client_id" ]
  principal-name-claim-paths: [ "preferred_username", "username" ]
  role-claim-paths: [ "groups" ]
  scope-claim-paths: [ "scope" ]
  scope-grants-enabled: true
```

Principal name claim paths are tried in order. Principal id claim paths are tried in order for Protected Resource JWT and
introspection authentication, and for Authorization Code Flow local authentication when `principal-id-mode` is
`claim-path`. Role and scope claim paths are aggregated from all configured paths and duplicate grant names are ignored.
Dotted paths read nested objects, for example `realm_access.roles`.

Principal id and principal name claims must be strings. Role claims may be strings or string arrays. Standard `scope`
claims must be space-delimited RFC 6749 scope strings using ASCII spaces. Custom scope claim paths, such as `scp`, may be
strings or string arrays; array values are treated as individual scope tokens.

For Authorization Code Flow local authentication, scope grants come from the Token Endpoint scope value stored in the
local authentication result. ID Token scope claims are not promoted to Helidon scope grants.

For Authorization Code Flow local authentication, `principal-id-mode` controls `Principal.id()`. The default
`issuer-subject` mode derives an opaque issuer-qualified value from the ID Token `iss` and `sub` claims. OpenID Connect
Core 1.0, section 5.7 says that "the only guaranteed unique identifier for a given End-User is the combination of the
`iss` Claim and the `sub` Claim." The raw ID Token `iss` and `sub` values are still preserved as principal attributes.

Use `principal-id-mode: subject` when the application intentionally wants the raw ID Token `sub` claim as the principal
id, for example in a single-issuer application. Use `principal-id-mode: claim-path` when Authorization Code Flow local
authentication should use `principal-id-claim-paths`. Protected Resource JWT and introspection authentication always use
`principal-id-claim-paths`.

ID Token validation requires `sub` to be non-blank ASCII and no longer than 255 characters. This is an ID Token protocol
check; protected-resource access tokens and introspection responses keep using the configured subject mapping rules.

Example for a Keycloak-style token:

```yaml
subject-mapping:
  principal-id-mode: claim-path
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

### Custom Claims And ABAC

OIDC custom claims are copied to the Helidon principal as ABAC attributes. Claims selected by
`role-claim-paths` are also added as role grants. For Protected Resource authentication, claims selected by
`scope-claim-paths` are added as scope grants when `scope-grants-enabled` is `true`. For Authorization Code Flow local
authentication, scope grants come from the Token Endpoint scope value stored in the local authentication result.

For IDCS or IAM tenants, configure the claim paths to match the actual token or UserInfo claim names used by the
tenant. The names below are examples only.

```yaml
security:
  providers:
    - oidc-next:
        issuer: "https://issuer.example"
        client-id: "${OIDC_CLIENT_ID}"
        client-secret: "${OIDC_CLIENT_SECRET}"
        authorization-code:
          redirection-endpoint-uri: "https://app.example/oidc/callback"
          scopes: [ "openid", "profile", "email", "mcp.tools.read" ]
        subject-mapping:
          principal-id-mode: claim-path
          principal-id-claim-paths: [ "sub" ]
          principal-name-claim-paths: [ "preferred_username", "email" ]
          role-claim-paths: [ "groups", "idcs_groups", "iam.groups" ]
          scope-claim-paths: [ "scope", "scp" ]
          scope-grants-enabled: true
        cookies:
          encryption-secret: "${OIDC_COOKIE_SECRET}"
```

If the custom claims are returned only by the UserInfo Endpoint, enable UserInfo and include role or name claim paths in
`subject-mapping`. With the default `user-info.storage-policy: mapped`, those subject-mapping paths are stored after
the UserInfo `sub` check. Additional ABAC-only UserInfo claims must be listed in `user-info.attribute-claim-paths`, or
the application must choose `user-info.storage-policy: all`.

```yaml
security:
  providers:
    - oidc-next:
        issuer: "https://issuer.example"
        client-id: "${OIDC_CLIENT_ID}"
        client-secret: "${OIDC_CLIENT_SECRET}"
        authorization-code:
          redirection-endpoint-uri: "https://app.example/oidc/callback"
          scopes: [ "openid", "profile", "email" ]
        user-info:
          enabled: true
          attribute-claim-paths: [ "department" ]
        subject-mapping:
          role-claim-paths: [ "iam.groups" ]
        cookies:
          encryption-secret: "${OIDC_COOKIE_SECRET}"
```

After authentication, the application can authorize with Helidon roles, scopes, or custom principal attributes. For
example, WebServer path rules can require roles or scopes produced by the OIDC mapping:

```yaml
security:
  web-server.paths:
    - path: "/mcp/admin/*"
      roles-allowed: [ "mcp_admin" ]
    - path: "/mcp/tools/read/*"
      abac.scopes: [ "mcp.tools.read" ]
```

Application code can read custom claims from the current subject:

```java
boolean financeUser = context.user()
        .map(Subject::principal)
        .flatMap(principal -> principal.abacAttribute("department"))
        .filter("finance"::equals)
        .isPresent();
```

Programmatic subject mapping uses the same claim path names:

```java
OidcProviderConfig config = OidcProviderConfig.builder()
        .issuer("https://issuer.example")
        .clientId("client-id")
        .clientSecret("client-secret")
        .authorizationCode(authorizationCode -> authorizationCode
                .redirectionEndpointUri(URI.create("https://app.example/oidc/callback"))
                .scopes(List.of("openid", "profile", "email", "mcp.tools.read")))
        .subjectMapping(subjectMapping -> subjectMapping
                .principalIdMode(OidcPrincipalIdMode.CLAIM_PATH)
                .principalIdClaimPaths(List.of("sub"))
                .principalNameClaimPaths(List.of("preferred_username", "email"))
                .roleClaimPaths(List.of("groups", "idcs_groups", "iam.groups"))
                .scopeClaimPaths(List.of("scope", "scp"))
                .scopeGrantsEnabled(true))
        .cookies(cookies -> cookies
                .encryptionSecret(System.getenv("OIDC_COOKIE_SECRET")))
        .buildPrototype();
```

Claim-path limitations:

- Dots in claim paths mean nested JSON objects, for example `iam.groups`.
- Literal claim names containing dots cannot be selected as one path segment.
- Role claim values must be strings or arrays of strings. Custom scope claim values must be strings or arrays of
  RFC 6749 scope-token strings.
- Object-array claims such as `groups: [{ "name": "mcp_admin" }]` are not flattened by subject mapping.

## Combining Browser Login And API Bearer Tokens

A tenant may enable Authorization Code Flow and Protected Resource authentication at the same time.

```yaml
security:
  providers:
    - oidc-next:
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
reuse local authentication cookies when the endpoint accepts them. If a request has a Bearer token and that Bearer token
is invalid, the provider fails the Bearer Token request and does not fall back to a local authentication cookie.

`endpoint-policy` controls which credential types an endpoint accepts and what happens when none of them authenticates
the request.

```yaml
endpoint-policy:
  accepted-credentials: [ "bearer-token", "authentication-cookie" ]
  authentication-failure-response: unauthorized
```

If `accepted-credentials` is omitted, the provider infers it from the tenant:

- Protected Resource only: accepts `bearer-token`.
- Authorization Code Flow only: accepts `authentication-cookie`.
- Both Protected Resource and Authorization Code Flow: accepts both.
- Neither: no OIDC endpoint policy is active and the provider abstains.

If `authentication-failure-response` is omitted, the provider uses:

- `authorization-code-redirect` for endpoints that accept only `authentication-cookie`.
- `unauthorized` for endpoints that accept `bearer-token`, including mixed endpoints that accept both credentials.

This default keeps mixed browser/API tenants from returning browser login redirects from API endpoints when no credential
is present.

Configure a browser route to accept only the local authentication cookie and redirect when the cookie is missing:

```yaml
endpoint-policy:
  accepted-credentials: [ "authentication-cookie" ]
```

Configure a cookie-authenticated API endpoint to return `401` instead of a login redirect:

```yaml
endpoint-policy:
  accepted-credentials: [ "authentication-cookie" ]
  authentication-failure-response: unauthorized
```

Programmatic route-level endpoint policy can be attached through WebServer security custom objects:

```java
OidcEndpointPolicyConfig browserPolicy = OidcEndpointPolicyConfig.builder()
        .addAcceptedCredential(OidcEndpointCredential.AUTHENTICATION_COOKIE)
        .buildPrototype();

routing.get("/page",
            SecurityFeature.authenticate().customObject(browserPolicy),
            handler);
```

`bearer-token` requires enabled `protected-resource`. `authentication-cookie` and `authorization-code-redirect` require
enabled `authorization-code`. `authorization-code-redirect` also requires `authentication-cookie` to be accepted by the
resolved endpoint policy.

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

For isolated tests, the TLS requirement can be disabled for non-mTLS endpoint validation.

```yaml
endpoints:
  tls-required: false
  jwks-uri: "http://localhost:8081/jwks"
```

Do not disable TLS in production. Disabling TLS can expose access tokens, client credentials, and token signature
verification keys. Outbound targets that carry tokens should normally be constrained with `transports: [ "https" ]` even
though HTTPS is enforced by default. `TLS_CLIENT_AUTH` and `SELF_SIGNED_TLS_CLIENT_AUTH` still require an HTTPS Token
Endpoint and HTTPS well-known metadata when discovery supplies that endpoint, because mutual TLS client authentication
cannot happen over HTTP.

## Troubleshooting And Diagnostics

Caller-facing authentication failures are intentionally vague. RFC 6750 Bearer challenges use controlled local strings:
missing Bearer credentials return only `WWW-Authenticate: Bearer realm="..."`, malformed Bearer requests use
`invalid_request` with `Bearer Token request is invalid`, and invalid presented tokens use `invalid_token` with
`Bearer Token is invalid`. The provider does not relay provider `error_description` values, token claims, introspection
payloads, stack traces, cookie values, tokens, or secrets to callers.

Use DEBUG logging for `io.helidon.security.providers.oidc.next` when investigating operational failures. DEBUG output is
designed to give safe categories such as tenant id, validation method, endpoint role, config key, sanitized metadata or
JWK Set URI, JWT `kid`, and failure category. It still does not log raw access tokens, ID Tokens, refresh tokens, DPoP
proofs, cookies, authorization headers, client assertions, private keys, client secrets, provider response bodies, full
claims, or full introspection responses.

Common checks:

| Symptom | Check |
| --- | --- |
| `OIDC tenant is unavailable` | Enable DEBUG logging and check tenant initialization. Verify `issuer`, `endpoints.well-known-uri`, required endpoint URIs, TLS settings, and metadata requirements for the enabled features. |
| `Bearer Token is invalid` with JWT validation | Check configured `issuer`, `protected-resource.token-validation.audience`, allowed algorithms, JWKS URI, JWK Set refresh settings, token `kid`, clock skew, and whether the token is a strict RFC 9068 access token. |
| `Bearer Token is invalid` with introspection | Check the introspection endpoint URI, introspection client authentication method, Authorization Server policy, required audience, issuer validation, and whether the response contains `active: true` plus a configured principal claim. |
| `Bearer Token request is invalid` | Check for multiple Bearer token sources, multiple Authorization Bearer values, malformed `access_token` query parameters, or non-HTTPS transport when secure transport is required. |
| Browser login loops or callback failures | Check redirect URI registration, reverse proxy requested-URI discovery, `X-Forwarded-*` headers, cookie domain/path/SameSite settings, clock skew, PKCE metadata, PAR/JAR requirements, and cookie encryption secret consistency. |
| UserInfo failures | Check that `user-info-endpoint-uri` or metadata `userinfo_endpoint` is available and that the UserInfo `sub` matches the ID Token `sub`. |
| Logout failures | Check local logout path configuration, same-origin `Origin` or `Referer`, post-logout redirect allowlist, and End Session Endpoint metadata. |
| Outbound Token Propagation abstains | Check outbound target matching, HTTPS target URI, current subject `TokenCredential`, and downstream audience validation. |
| Client Credentials or Token Exchange fails | Check Token Endpoint URI or metadata, confidential client authentication, client credentials or assertion key material, enabled Keycloak/client permissions, resource/audience values, and outbound target configuration. |
| mTLS or certificate-bound token failures | Check WebServer client certificate configuration, tenant `webclient.tls`, mTLS endpoint aliases, HTTPS endpoint requirements, and the token/introspection `cnf.x5t#S256` thumbprint. |

## Configuration Reference

Provider options:

| Key | Description |
| --- | --- |
| `provider-name` | Provider name used by Helidon Security. Defaults to `oidc-next`. |
| `optional` | Whether authentication failures may be treated as optional by the provider. Defaults to `false`. |
| `socket` | WebServer socket name used by `OidcFeature` when it is registered as a WebServer feature. Defaults to the WebServer default socket. |
| `socket-required` | Whether the configured named socket must exist. Defaults to `true`; has no effect when `socket` is omitted or set to `@default`. |
| `default-tenant` | Tenant id used when no tenant is resolved from the request. Auto-filled when exactly one named tenant is configured. In root single-tenant config, this optionally names the synthetic tenant. |
| `tenant-resolution` | Tenant resolution rules. |
| `tenants` | Map of tenant id to tenant configuration for multi-tenant applications. Do not combine this with root tenant options. |
| `outbound` | Provider-level outbound target list using Helidon's common `OutboundTarget` model. Targets can match transport, host, path, and method, and may select Token Propagation, Client Credentials Grant, or Token Exchange. |

Tenant options are configured directly under `oidc-next` for a single tenant, or under `tenants.<tenant-id>` for
multi-tenant applications:

| Key | Description |
| --- | --- |
| `enabled` | Whether this tenant is enabled. Defaults to `true`. |
| `issuer` | Expected Issuer Identifier string. Issuer identity comparisons use this exact string value. |
| `client-id` | OAuth 2.0 client identifier. |
| `client-secret` | OAuth 2.0 client secret. |
| `token-endpoint-auth-method` | Token Endpoint client authentication method: `CLIENT_SECRET_BASIC`, `CLIENT_SECRET_POST`, `CLIENT_SECRET_JWT`, `PRIVATE_KEY_JWT`, `TLS_CLIENT_AUTH`, `SELF_SIGNED_TLS_CLIENT_AUTH`, or `NONE`. `TLS_CLIENT_AUTH` and `SELF_SIGNED_TLS_CLIENT_AUTH` require enabled tenant `webclient.tls` with private key plus certificate chain, an SSL context, or a custom TLS manager. |
| `client-assertion` | Client assertion signing configuration for `CLIENT_SECRET_JWT` and `PRIVATE_KEY_JWT`. Used for Token Endpoint authentication and as the default for Introspection Endpoint authentication unless `protected-resource.token-validation.introspection.client-assertion` overrides it. |
| `id-token` | ID Token validation and decryption configuration. |
| `webclient` | WebClient configuration for well-known metadata, JWKS, Token Endpoint, introspection, and UserInfo requests. For RFC 8705 mTLS client authentication, `webclient.tls` must be enabled and provide private key plus certificate chain, an SSL context, or a custom TLS manager. |
| `jwk-set` | JSON Web Key Set reload policy used for ID Token and JWT access-token signature validation. |
| `endpoints` | OpenID Provider and Authorization Server endpoint configuration. |
| `protected-resource` | Bearer Token Protected Resource configuration. |
| `authorization-code` | Authorization Code Flow configuration. |
| `endpoint-policy` | Endpoint accepted credentials and missing-credential failure response. |
| `logout` | OIDC logout endpoint configuration. |
| `user-info` | UserInfo request configuration for Authorization Code Flow local authentication. |
| `token-transport` | Bearer Token transport configuration. |
| `subject-mapping` | Claim-to-subject mapping configuration. |
| `cookies` | Cookie configuration used by stateful OIDC flows. |

ID Token options:

| Key | Description |
| --- | --- |
| `allowed-algorithms` | Allowed JWS algorithms for signed ID Tokens. Defaults to `[ "RS256" ]`. `none` and `HS*` algorithms are rejected. |
| `allowed-encryption-algorithms` | Allowed JWE `alg` algorithms for encrypted ID Tokens. Defaults to `[ "RSA-OAEP-256", "RSA-OAEP" ]`. `RSA1_5` is not enabled by default. |
| `allowed-content-encryption-algorithms` | Allowed JWE `enc` algorithms for encrypted ID Tokens. Defaults to `[ "A256GCM", "A128CBC-HS256" ]`. |
| `trusted-additional-audiences` | Additional ID Token `aud` values trusted by this client. The configured `client-id` is always required and should not be listed here. Defaults to an empty list. |
| `clock-skew` | Allowed ID Token time validation clock skew. Defaults to `PT1M`. |
| `decryption-jwk` | Private JWK Set resource used to decrypt encrypted ID Tokens before normal signed ID Token validation. |
| `encryption-required` | Whether signed-only ID Tokens are rejected. Defaults to `false`. |

Client assertion options:

| Key | Description |
| --- | --- |
| `algorithm` | JWS `alg` header used to sign the client assertion. Defaults to `HS256` for `CLIENT_SECRET_JWT`; for `PRIVATE_KEY_JWT`, defaults to the selected JWK algorithm and must match it when configured. |
| `key-id` | JWS `kid` header. For `PRIVATE_KEY_JWT`, selects the signing key and is required when `jwk` contains multiple keys. For `CLIENT_SECRET_JWT`, written to the assertion header when configured. |
| `jwk` | Private JWK Set resource used to sign `PRIVATE_KEY_JWT` assertions. |
| `lifetime` | Assertion lifetime used to calculate `exp`. Defaults to `PT1M`. |

JWK Set options:

| Key | Description |
| --- | --- |
| `unknown-key-id-refresh-enabled` | Whether an unknown JWT `kid` triggers a JWK Set reload attempt. Defaults to `true`. |
| `unknown-key-id-refresh-interval` | Minimum interval between unknown-`kid` reload attempts. Defaults to `PT5M`. |
| `refresh-interval` | Optional lazy JWK Set refresh interval. If configured, cached keys older than this interval are refreshed during token validation. No background thread is started. |
| `stale-on-error` | Whether cached keys may still be used when a reload fails. Defaults to `true`; initial loading still fails when no cached keys exist. |

Authorization Code Flow options:

| Key | Description |
| --- | --- |
| `enabled` | Whether Authorization Code Flow initiation is enabled when `authorization-code` is configured. Defaults to `true`. |
| `redirection-endpoint-uri` | Client callback URI sent as `redirect_uri`. Defaults to local path `/oidc/callback`, resolved from the incoming request origin. May also be configured as an absolute URI. |
| `scopes` | Authentication Request scopes. Defaults to `[ "openid" ]`, must contain `openid`, and each value must be one RFC 6749 `scope-token`. |
| `prompts` | Optional Authentication Request prompt values. Values are serialized into the `prompt` parameter as a space-delimited list. `none` cannot be combined with any other value. When `scopes` contains `offline_access`, the provider sends `prompt=consent` when prompts are omitted and appends `consent` to configured prompts that do not already contain it. |
| `resources` | Optional RFC 8707 resource indicators for Authorization Code Flow. Values are emitted only when configured, as repeated `resource` parameters on the Authentication Request, authorization-code token request, and refresh-token requests. Each value must be an absolute URI without a fragment; blanks, padded values, and duplicates are rejected. |
| `pushed-authorization-requests` | RFC 9126 Pushed Authorization Request mode: `DISABLED`, `AUTO`, or `REQUIRED`. Defaults to `AUTO`. `AUTO` uses PAR when a PAR endpoint is configured or already-loaded metadata advertises it, and requires PAR when loaded metadata requires it. `REQUIRED` may load metadata to discover the endpoint. |
| `request-object` | RFC 9101 signed Request Object configuration. Defaults to `AUTO` mode without signing key material, so no Request Object is sent unless `jwk` is configured or loaded metadata requires signed Request Objects. |
| `pkce-required` | Whether PKCE parameters are sent. Defaults to `true`. Public clients using `token-endpoint-auth-method: NONE` cannot disable PKCE. |
| `pkce-method` | PKCE code challenge method: `S256` or `plain`. Defaults to `S256`. Public clients using `token-endpoint-auth-method: NONE` must use `S256`; `plain` is for legacy confidential-client compatibility only. |

Request Object options:

| Key | Description |
| --- | --- |
| `mode` | Signed Request Object mode: `DISABLED`, `AUTO`, or `REQUIRED`. Defaults to `AUTO`. `AUTO` signs when `jwk` is configured and requires signing when loaded metadata has `require_signed_request_object: true`. |
| `algorithm` | JWS `alg` header used to sign the Request Object. When omitted, the selected JWK algorithm is used. When configured, it must match the selected JWK and be one of the supported RSA or EC signing algorithms. |
| `key-id` | JWS `kid` header and JWK selector. Required when `jwk` contains more than one key. |
| `jwk` | Private JWK Set resource configuration used to sign Request Objects. This is local client key material registered with the Authorization Server; it is not the OP `jwks-uri`. URI resources are rejected before resource creation. |
| `lifetime` | Request Object lifetime used to calculate `exp`. Defaults to `PT1M`. |

Endpoint policy options:

| Key | Description |
| --- | --- |
| `accepted-credentials` | Accepted endpoint credentials: `bearer-token` and/or `authentication-cookie`. If omitted, inferred from enabled `protected-resource` and `authorization-code`. |
| `authentication-failure-response` | Response when no accepted credential authenticates the request: `unauthorized` or `authorization-code-redirect`. If omitted, authentication-cookie-only endpoints redirect and all other endpoint policies return `401`. |

Subject mapping options:

| Key | Description |
| --- | --- |
| `principal-id-mode` | Authorization Code Flow local authentication principal id mode: `issuer-subject`, `subject`, or `claim-path`. Defaults to `issuer-subject`. Protected Resource JWT and introspection authentication use `principal-id-claim-paths`. |
| `principal-id-claim-paths` | Dotted claim paths tried in order for Protected Resource JWT and introspection principal ids, and for Authorization Code Flow local authentication when `principal-id-mode` is `claim-path`. Defaults to `[ "sub", "username", "client_id" ]`. |
| `principal-name-claim-paths` | Dotted claim paths tried in order for the principal display name. Defaults to `[ "preferred_username", "username" ]`. |
| `role-claim-paths` | Dotted claim paths used to create Helidon role grants. String values and string-array values are supported. Defaults to `[ "groups" ]`. |
| `scope-claim-paths` | Dotted claim paths used to create Helidon scope grants for Protected Resource JWT and introspection authentication. Defaults to `[ "scope" ]`. |
| `scope-grants-enabled` | Whether scope claim values are mapped to Helidon scope grants for Protected Resource JWT and introspection authentication. Defaults to `true`. Authorization Code Flow local authentication uses the Token Endpoint scope value stored in the local authentication result. |

UserInfo options:

| Key | Description |
| --- | --- |
| `enabled` | Whether UserInfo requests are enabled when `user-info` is configured. Defaults to `true`. |
| `jwt` | Exact registered signed and/or encrypted UserInfo JWT response configuration. When omitted, JSON is required. |
| `storage-policy` | UserInfo claim storage policy: `mapped`, `all`, or `none`. Defaults to `mapped`. |
| `attribute-claim-paths` | Additional dotted UserInfo claim paths stored when `storage-policy` is `mapped`. The provider also stores `sub` and paths used by `subject-mapping`. |

UserInfo JWT options:

| Key | Description |
| --- | --- |
| `signing-algorithm` | Exact `userinfo_signed_response_alg` registered for this client. `none` and `HS*` are rejected. |
| `encryption-algorithm` | Exact `userinfo_encrypted_response_alg` registered for this client. |
| `content-encryption-algorithm` | Exact `userinfo_encrypted_response_enc`. Defaults to `A128CBC-HS256` when encryption is configured. |
| `decryption-jwk` | Confidential private RP JWK Set resource used for UserInfo decryption. Required with `encryption-algorithm`. |
| `clock-skew` | Clock skew for optional signed UserInfo JWT time claims. Defaults to `PT1M`. |

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
| `client-credentials-grant-enabled` | Use Client Credentials Grant for this outbound target. Mutual TLS methods require enabled tenant `webclient.tls` with private key plus certificate chain, an SSL context, or a custom TLS manager, and an HTTPS Token Endpoint or HTTPS well-known metadata. |
| `client-credentials-scopes` | Access-token scopes requested by Client Credentials Grant for this outbound target. Each value must be one RFC 6749 `scope-token`. Values are serialized, in configured order, as one OAuth `scope` form parameter. Requires `client-credentials-grant-enabled: true`. |
| `client-credentials-resources` | RFC 8707 resource indicators requested by Client Credentials Grant for this outbound target. Each value must be an absolute URI with no fragment. Values are sent as separate OAuth `resource` form parameters and are included in the Client Credentials token cache key. Requires `client-credentials-grant-enabled: true`. |
| `token-exchange-enabled` | Use RFC 8693 Token Exchange for this outbound target. Requires a current subject `TokenCredential`, confidential Token Endpoint client authentication, and `token-exchange-resource` or `token-exchange-audience`. |
| `token-exchange-scopes` | Access-token scopes requested by Token Exchange for this outbound target. Each value must be one RFC 6749 `scope-token`. Values are serialized, in configured order, as one OAuth `scope` form parameter. Requires `token-exchange-enabled: true`. |
| `token-exchange-resource` | RFC 8693 target resource requested by Token Exchange. The value must be an absolute URI with no fragment and is sent as the Token Endpoint `resource` form parameter. Requires `token-exchange-enabled: true`. |
| `token-exchange-audience` | RFC 8693 target audience requested by Token Exchange. The value is sent as the Token Endpoint `audience` form parameter. Requires `token-exchange-enabled: true`. |
| `audience` | Expected `aud` claim for Token Propagation to this outbound target. Required by default when `token-propagation-enabled: true`. This identifies the downstream resource server. |
| `audience-validation-enabled` | Whether Token Propagation audience validation is enabled for this outbound target. Defaults to `true`. Disabling it allows raw or opaque token propagation without local audience validation and should be limited to testing, local development, or legacy deployments. |

Token validation options:

| Key | Description |
| --- | --- |
| `method` | `JWT` or `INTROSPECTION`. |
| `audience` | Expected access-token audience when audience validation is enabled. For JWT access tokens, this should identify the current resource server. |
| `audience-validation-enabled` | Whether audience validation is enabled. Defaults to `true`. For JWT access tokens, disabling it relaxes RFC 9068 validation and logs a warning. |
| `introspection` | RFC 7662 Token Introspection request configuration. Used only with `method: INTROSPECTION`. |
| `certificate-bound-access-tokens` | RFC 8705 certificate-bound access-token validation configuration. Applies to Protected Resource Bearer Token requests. |
| `allowed-algorithms` | Allowed JWS algorithms for JWT access tokens. Defaults to `[ "RS256" ]`. The `none` algorithm is rejected. |
| `clock-skew` | Allowed token time validation clock skew. Defaults to `PT1M`. |

Certificate-bound access-token options:

| Key | Description |
| --- | --- |
| `mode` | `DISABLED`, `IF_PRESENT`, or `REQUIRED`. Defaults to `DISABLED`. |

Introspection options:

| Key | Description |
| --- | --- |
| `auth-method` | Introspection Endpoint authentication method: `CLIENT_SECRET_BASIC`, `CLIENT_SECRET_POST`, `CLIENT_SECRET_JWT`, `PRIVATE_KEY_JWT`, `TLS_CLIENT_AUTH`, or `SELF_SIGNED_TLS_CLIENT_AUTH`. Defaults to `CLIENT_SECRET_BASIC` when an introspection or tenant `client-secret` is configured. `NONE` is rejected. |
| `client-id` | Client identifier used to authenticate this protected resource to the Introspection Endpoint. Defaults to the tenant `client-id`. |
| `client-secret` | Client secret used to authenticate this protected resource to the Introspection Endpoint. Defaults to the tenant `client-secret`. |
| `client-assertion` | Client assertion signing configuration for Introspection Endpoint `CLIENT_SECRET_JWT` and `PRIVATE_KEY_JWT`. Defaults to the tenant `client-assertion`. |
