# OIDC Next Provider User Guide

This document describes the current `oidc-next` security provider implementation.

Single-tenant applications configure tenant options directly under `oidc-next`. Multi-tenant applications configure
named tenants under `tenants` and use `default-tenant` or `tenant-resolution` to select one for each request.

## Supported Use Cases

The current implementation supports:

- Protected Resource Bearer Token authentication.
- Access-token validation by local JWT validation against a provider JWKS URI or explicitly provisioned local verification keys.
- Access-token validation by OAuth 2.0 Token Introspection.
- Introspection Endpoint authentication with separate protected-resource credentials when needed.
- RFC 8705 certificate-bound access-token validation for Protected Resource Bearer Token requests.
- OpenID Connect Authorization Code Flow.
- RFC 9126 Pushed Authorization Requests for Authorization Code Flow.
- RFC 9101 signed and signed-then-encrypted by-value Request Objects for Authorization Code Flow.
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
- Hosted Request Objects through client-hosted `request_uri` or unsigned Request Objects.

## Supported Standards Boundary

`oidc-next` implements client-side and resource-server-side OAuth/OIDC behavior. It is an OpenID Connect Relying Party,
an OAuth client, and an OAuth Protected Resource provider. It is not an OpenID Provider, OAuth Authorization Server,
Dynamic Client Registration server, Device Flow client, CIBA client, or browser session-management implementation.

The supported standards surface is intentionally scoped:

- OpenID Connect Core 1.0: Authorization Code Flow, Authentication Request construction, ID Token validation, encrypted
  ID Token decryption before validation, JSON, signed, encrypted, and nested JWT UserInfo retrieval, offline access
  prompt handling, and JWT client authentication. Implicit Flow, Hybrid Flow, and OP behavior are not implemented.
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
- JWT-Secured Authorization Request, RFC 9101: signed and signed-then-encrypted by-value Request Objects, including PAR
  transport. Unsigned and client-hosted `request_uri` Request Objects are not implemented.
- Pushed Authorization Requests, RFC 9126: PAR request and response handling, including metadata-driven enforcement.
- Authorization Server Issuer Identification, RFC 9207: authorization response `iss` validation when present or when
  metadata advertises support. It is mandatory when distinct or not-statically-known issuers can share a callback;
  distinct callback paths or absolute callback origins provide the RFC 9700 alternative defense.
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
| Secured Request Objects | No Keycloak CI path. | Signed and nested encrypted by-value/PAR JAR construction, metadata checks, and Nimbus interoperability. | FAPI-style providers requiring JAR. |
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

import io.helidon.common.configurable.ResourceConfig;
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
                .failureRetryInterval(Duration.ofSeconds(10))
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
                        .audience("api://orders")
                        .introspection(introspection -> introspection
                                .remoteWork(remoteWork -> remoteWork
                                        .maxConcurrent(16)
                                        .maxQueued(64)
                                        .admissionTimeout(Duration.ofMillis(250))))))
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
                .protection(protection -> protection.password(System.getenv("OIDC_COOKIE_PASSWORD"))))
        .buildPrototype();

OidcProvider provider = OidcProvider.create(config);
```

Configure signed-then-encrypted Request Objects programmatically:

```java
OidcProviderConfig config = OidcProviderConfig.builder()
        .issuer("https://issuer.example")
        .clientId(System.getenv("OIDC_CLIENT_ID"))
        .clientSecret(System.getenv("OIDC_CLIENT_SECRET"))
        .authorizationCode(authorizationCode -> authorizationCode
                .scopes(List.of("openid", "profile"))
                .requestObject(requestObject -> requestObject
                        .mode(OidcRequestObjectMode.REQUIRED)
                        .signingJwk(jwk -> jwk.resourcePath("private-request-object-jwks.json"))
                        .signingKeyId("request-object-signing-key")
                        .signingAlgorithm("RS256")
                        .encryptionAlgorithm("RSA-OAEP-256")
                        .contentEncryptionAlgorithm("A128CBC-HS256")
                        .encryptionKeyId("op-encryption-key")
                        .lifetime(Duration.ofMinutes(1))))
        .cookies(cookies -> cookies
                .protection(protection -> protection.password(System.getenv("OIDC_COOKIE_PASSWORD"))))
        .buildPrototype();
```

When Authorization Code Flow or logout is enabled, register `OidcFeature` as a WebServer feature so the local routes are
installed. Create the feature from the same `OidcProvider` instance registered with Security so authentication, callbacks,
and logout share tenant initialization, clients, and caches. This registration form also applies the configured `socket`:

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
                .protection(protection -> protection.password(System.getenv("OIDC_COOKIE_PASSWORD"))))
        .buildPrototype();

OidcProvider oidcProvider = OidcProvider.create(config);
Security security = Security.builder()
        .addProvider(oidcProvider, config.providerName())
        .build();

WebServer server = WebServer.builder()
        .addFeature(SecurityFeature.builder()
                .security(security)
                .build())
        .addFeature(OidcFeature.create(oidcProvider))
        .build();
```

If Security created the provider from configuration, retrieve that registered instance before creating the feature:

```java
OidcProvider oidcProvider = security.resolveAtnProvider("oidc-next")
        .filter(OidcProvider.class::isInstance)
        .map(OidcProvider.class::cast)
        .orElseThrow(() -> new IllegalStateException("Configured authentication provider is not an OIDC provider"));
OidcFeature feature = OidcFeature.create(oidcProvider);
```

Use the provider's registered Security name in the lookup. The configuration-only `OidcFeature.create(...)` factories
remain available for independent feature instances; passing the same configuration to two factories does not share a
runtime. Separately created providers remain independent, even if their configuration is identical.

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
          protection:
            password: "${OIDC_COOKIE_PASSWORD}"
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

### Runtime ownership and shutdown

`OidcProvider` implements `AutoCloseable` and owns its tenant clients. The application must stop all consumers, including
servers and outbound work, before closing the provider. A feature created with `OidcFeature.create(provider)` borrows that
runtime: stopping one server must not close a provider that another server or Security instance still uses. Neither
registering the provider with Security nor creating a feature from it transfers ownership.

At application shutdown, for the single-server example above:

```java
try {
    server.stop();
} finally {
    oidcProvider.close();
}
```

Use `try`-with-resources around the provider's application lifetime when convenient, with server shutdown inside that
scope. The same ownership rule applies to a provider retrieved from a configuration-created Security instance.

The configuration-only `OidcFeature.create(config)` factories own an independent runtime. WebServer lifecycle hooks
release that runtime when its last active routing registration stops, including when using `feature.setup(routing)`
directly. An independently owned feature shared by several running servers stays usable until the last one stops.
For explicit cleanup independent of lifecycle-hook dispatch, create and own an `OidcProvider` and pass it to the feature.

Closing is terminal and idempotent: new authentication, outbound operations, and runtime lookups are rejected after
closure. Create a new provider or independent feature for a new lifetime. Cleanup does not wait for pending discovery;
an initialization finishing after closure releases its client instead of reactivating the runtime. Other in-flight work
must be quiesced by the application before close.

Cleanup releases client-owned resources, including private connection pools configured with
`webclient.share-connection-cache: false`. Default JVM-shared connection pools remain managed by WebClient and are not
evicted when an OIDC runtime closes.

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
enabled. JWKS requests also disable redirect following to preserve the configured or discovered key endpoint and
prevent transport downgrades.

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

Tenant initialization and lazy outbound Token Endpoint discovery retry a failed well-known metadata load after
`initialization-retry-interval`, which defaults to `PT10S`. Callers during that interval observe the same failed outcome,
and one caller performs the next load after the interval. This avoids a retry storm while allowing recovery from an
Authorization Server outage or an invalid response that is later corrected. Deterministic local configuration and
metadata compatibility failures are not retried; correct the configuration or provider metadata and recreate the
provider.

Tenant contexts are initialized on first use, with one initialization attempt per tenant. `initialization-max-queued`
bounds the callers waiting behind that attempt (default `128`); zero rejects followers while initialization is occupied,
and negative values are rejected. Admitted callers wait interruptibly for the shared outcome, with no separate admission
timeout. In particular, they are not subject to the JWKS admission timeout. Network work retains the tenant WebClient's
configured connect/read timeouts; this setting does not establish a total initialization deadline or start background work.

Ready contexts and failures retained during retry backoff bypass admission. Queue exhaustion or interruption of a waiting
caller affects only that caller: it neither cancels the active initialization nor replaces its result or changes the retry interval.
Authentication returns HTTP 503 without an invalid-token challenge, and outbound security reports an unavailable failure.
Callback admission failure returns 503 before code redemption and preserves the state cookie so the same unexpired
transaction can be retried. RP-Initiated Logout returns 503 if it cannot initialize the tenant for end-session discovery,
while retaining local session-cookie removal and browser-session generation rotation already performed by logout.
These limits apply independently per tenant, only to tenant initialization; deferred outbound metadata resolution and
token acquisition retain their own policies.

```yaml
security:
  providers:
    - oidc-next:
        issuer: "https://issuer.example"
        initialization-retry-interval: "PT10S"
        initialization-max-queued: 128
```

Programmatic equivalent:

```java
OidcProviderConfig config = OidcProviderConfig.builder()
        .issuer("https://issuer.example")
        .initializationRetryInterval(Duration.ofSeconds(10))
        .initializationMaxQueued(128)
        .buildPrototype();
```

Well-known metadata is used by Authorization Code Flow when the issuer, Authorization Endpoint, or Token Endpoint is
missing, by Client Credentials Grant when `endpoints.token-endpoint-uri` is not configured, by Protected Resource JWT
validation when the issuer or `endpoints.jwks-uri` is not configured, and by Protected Resource introspection when the
issuer or `endpoints.introspection-endpoint-uri` is not configured. It is also used by RP-Initiated Logout when
`endpoints.end-session-endpoint-uri` is not configured, and by UserInfo when `endpoints.user-info-endpoint-uri` is not
configured. It can provide `authorization_endpoint`, `token_endpoint`, `jwks_uri`, `introspection_endpoint`,
`response_types_supported`, `grant_types_supported`, `code_challenge_methods_supported`,
`token_endpoint_auth_methods_supported`, `token_endpoint_auth_signing_alg_values_supported`,
`introspection_endpoint_auth_methods_supported`, `introspection_endpoint_auth_signing_alg_values_supported`,
`id_token_signing_alg_values_supported`, `id_token_encryption_alg_values_supported`,
`id_token_encryption_enc_values_supported`, `userinfo_endpoint`, `end_session_endpoint`,
`mtls_endpoint_aliases.token_endpoint`, `mtls_endpoint_aliases.pushed_authorization_request_endpoint`,
`mtls_endpoint_aliases.introspection_endpoint`, `pushed_authorization_request_endpoint`,
`require_pushed_authorization_requests`, `request_parameter_supported`,
`request_object_signing_alg_values_supported`, `request_object_encryption_alg_values_supported`,
`request_object_encryption_enc_values_supported`, `require_signed_request_object`, and
`authorization_response_iss_parameter_supported`.
When well-known metadata is loaded, OIDC Next retains mTLS aliases independently from conventional endpoint URIs.
Requests authenticated with `TLS_CLIENT_AUTH` or `SELF_SIGNED_TLS_CLIENT_AUTH` prefer the corresponding Token, PAR, or
Introspection Endpoint alias even when the conventional endpoint was configured explicitly. A non-mTLS request uses the
conventional endpoint. If metadata contains no corresponding alias, the configured or discovered conventional endpoint
is the fallback.

For example, an Authorization Server can isolate mTLS traffic while the application retains conventional endpoint
configuration:

```json
{
  "token_endpoint": "https://issuer.example/token",
  "introspection_endpoint": "https://issuer.example/introspect",
  "pushed_authorization_request_endpoint": "https://issuer.example/par",
  "mtls_endpoint_aliases": {
    "token_endpoint": "https://mtls.issuer.example/token",
    "introspection_endpoint": "https://mtls.issuer.example/introspect",
    "pushed_authorization_request_endpoint": "https://mtls.issuer.example/par"
  }
}
```

If discovery is not loaded, no alias is known and OIDC Next uses the statically configured URI. A fully static
deployment can therefore configure the intended mTLS listener directly as the conventional endpoint URI.
When Authorization Code Flow is configured with explicit Authorization and Token Endpoint URIs instead of loading
well-known metadata, configure `endpoints.jwks-uri` as well so ID Token signatures can be verified.
When ID Token encryption is configured through `id-token.decryption-jwk` or `id-token.encryption-required: true`, advertised
`id_token_encryption_alg_values_supported` and `id_token_encryption_enc_values_supported` must each include at least one
algorithm allowed by the local `id-token` JWE policy. When encryption is not required and no decryption key is configured,
these optional provider capabilities do not constrain a signed-only client. Local JWE allowlists alone do not enable encryption.
When Authorization Code Flow loads well-known metadata, the metadata must advertise `response_types_supported`
containing `code`. If `grant_types_supported` is present, it must contain `authorization_code`; if it is omitted, the
Discovery default includes `authorization_code`. When PKCE is enabled, `code_challenge_methods_supported` must be present
and include the configured PKCE method. The provider also validates the configured Token Endpoint authentication method
against `token_endpoint_auth_methods_supported`; if that metadata is omitted, the Discovery default is
`client_secret_basic`. For `client_secret_jwt` and `private_key_jwt`, well-known metadata must include
`token_endpoint_auth_signing_alg_values_supported` with the configured assertion signing algorithm.
When Request Objects are enabled and well-known metadata is loaded, `request_parameter_supported` must be `true`
unless the Authentication Request is pushed through PAR. If
`request_object_signing_alg_values_supported` is present, it must include the configured Request Object signing
algorithm. For encrypted Request Objects, advertised `request_object_encryption_alg_values_supported` and
`request_object_encryption_enc_values_supported` values must include the configured algorithms. If
`require_signed_request_object` is `true`, the provider rejects `request-object.mode: DISABLED` and requires local
Request Object signing key material.
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

`issuer` or `endpoints.well-known-uri` is required. By default, `endpoints.jwks-uri` can be configured explicitly;
otherwise the provider loads well-known metadata and uses its `jwks_uri`. RFC 9068 JWT access-token validation expects
`audience` to identify this resource server.

Provider JWKS URIs always supply public keys, whether configured explicitly, discovered, or overridden alongside
discovery. Initial loads and refreshes reject private or symmetric key material, including in file-backed copies of
provider JWKS. This follows the OP key-set rule in
[OpenID Connect Discovery section 3](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata).
RP private resources for client authentication, Request Object signing, ID Token decryption, and UserInfo decryption
remain separate; they are not subject to the OP public-key-only restriction.

For locally provisioned JWT access-token verification keys, use `protected-resource.token-validation.verification-jwk`.
This option is required for HMAC access-token algorithms. Its complete key set is used exclusively for access tokens;
there is no fallback to, or merging with, provider JWKS keys. It does not supply keys for ID Tokens, UserInfo, or Request
Objects, and it does not enable HMAC ID Token or UserInfo signatures. Provision these keys securely from the trusted
authorization server; the option does not derive verification keys from `client-secret`.

```yaml
issuer: "https://issuer.example"
protected-resource:
  token-validation:
    method: JWT
    audience: "api://orders"
    allowed-algorithms: [ "HS256" ]
    verification-jwk:
      path: "/run/secrets/access-token-verification.jwks"
```

`verification-jwk` accepts Common Resource configuration for filesystem `path`, classpath `resource-path`, inline
`content-plain`, or Base64 `content`. URI sources are rejected before opening. It requires `method: JWT` and does not
remove issuer, audience, algorithm, key-use, or token-claim validation. A local-only JWT tenant with an explicit issuer
does not need discovery or a provider JWKS URI; other enabled OIDC flows still require their normal metadata and OP keys.
When discovery is loaded, its required JWKS metadata is still validated.

Tenant `jwk-set` refresh, unknown-key throttling, and failure policies also apply to local verification keys. A
successfully loaded empty key set replaces the old keys; it is not a fetch failure that retains stale keys. Configurations
that previously placed HMAC secrets in `endpoints.jwks-uri` must move those keys to `verification-jwk`.

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
          failure-retry-interval: "PT10S"
          stale-on-error: true
          max-queued: 128
          admission-timeout: "PT1S"
        protected-resource:
          token-validation:
            method: JWT
            audience: "api://orders"
```

Remote JWK Set loads never follow HTTP redirects, including same-origin redirects. This OIDC Next security policy keeps
key retrieval at the configured or discovered endpoint and prevents HTTPS-to-HTTP downgrades. Configure the final HTTPS
location in `endpoints.jwks-uri` or the provider's `jwks_uri`; do not use a redirecting alias. The policy applies to initial
loading, unknown-key refresh, and periodic refresh, even if `webclient.follow-redirects` is enabled. Explicitly disabling
`endpoints.tls-required` still permits direct HTTP for development, but does not enable JWKS redirects.

A redirect is handled as a key-load failure. Initial loading fails; refresh follows the configured `stale-on-error` and
retry policy without contacting the redirect target or replacing cached keys with that target's response.

`unknown-key-id-refresh-enabled` reloads the JWK Set when a token uses a `kid` that is not present in the cached keys.
This supports Authorization Server key rotation. `unknown-key-id-refresh-interval` globally rate-limits those reload
attempts across all unknown `kid` values, including failed reload attempts; the default is `PT5M`.

`refresh-interval` enables lazy periodic refresh. No background thread is started. The provider checks the cache age
during token validation and refreshes only when a request needs keys after the interval has elapsed.

`failure-retry-interval` is the minimum delay before retrying a failed JWK Set load and defaults to `PT10S`. Concurrent
callers observe the same failed refresh outcome during that interval instead of each starting another HTTP request. When
cached keys exist, `stale-on-error` decides whether they remain usable while the failure is held.

Refreshes are coordinated as single-flight operations for concurrent requests. Valid cached-key hits bypass admission.
When many virtual threads hit a cold cache, expired cache, or unknown `kid` at the same time, one admitted caller loads
the JWK Set for that refresh opportunity and admitted followers reuse its published outcome. With `stale-on-error: true`,
requests may continue to use cached keys when a reload fails. With `stale-on-error: false`, a failed scheduled reload causes
requests to fail until `failure-retry-interval` permits another reload attempt.

`max-queued` bounds waiting callers (default 128), in addition to the one admitted coordinator. `admission-timeout`
limits how long a caller that reserved a queue slot may wait for coordination (default `PT1S`). Setting either to zero
provides fail-fast admission while coordination is occupied. Negative values are rejected. These flat `jwk-set` settings
apply independently to the provider JWK Set and a configured local `token-validation.verification-jwk` set.

Waiting is interruptible; cancelling or timing out a follower does not cancel the shared load. The admission timeout is
separate from the tenant WebClient's network timeouts and does not terminate an admitted load. Queue rejection, timeout,
and interruption do not replace cached keys, reset refresh throttles, or get cached as key-load failures. In particular,
`stale-on-error` does not turn local admission failure into acceptance of keys whose required refresh is still pending.

JWKS admission failure yields HTTP 503 for Protected Resource JWT validation, without an `invalid_token` challenge.
ID Token and signed UserInfo callback validation also return 503 and do not establish a session. Restart sign-in from
the application after a callback failure; do not retry a consumed authorization code. If admission prevents validation
after a successful refresh grant, the session cookies are removed and the request returns 503: replacement tokens have
not been validated, and the source refresh token may already have rotated. Other refresh-failure recovery policies are
unchanged. Existing key-load failures continue to follow the configured retry/stale policy.

JWS defines the `kid` header as optional. When it is present, OIDC Next selects that exact key and may refresh for an
unknown value according to the policy above. For a JWT access token without `kid`, OIDC Next filters the complete JWK Set
by the JWS algorithm, declared JWK `alg`, key type and curve, `use`, `key_ops`, and mandatory key strength. The signature
is attempted only when exactly one eligible verification key remains. Zero eligible keys or multiple eligible keys are
rejected; OIDC Next does not guess based on document order.

OpenID Connect Core applies a stricter rule to ID Tokens and signed UserInfo JWTs: when the referenced JWK Set contains
multiple keys, the issuer must include `kid`. OIDC Next therefore accepts one of these messages without `kid` only when
the complete JWK Set contains exactly one key and that key satisfies all verification constraints.

For example, an issuer can omit `kid` and JWK `alg` when its JWK Set contains exactly one key and that key is an eligible
RSA verification key. The placeholder modulus must be replaced with an actual base64url-encoded value of at least 2048
bits:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "key_ops": [ "verify" ],
      "n": "<base64url-encoded modulus of at least 2048 bits>",
      "e": "AQAB"
    }
  ]
}
```

During OpenID Connect signing-key rotation, the issuer must include `kid` as soon as its JWK Set contains more than one
key. A JWT access token also needs `kid` whenever filtering would otherwise leave multiple eligible keys.

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

JWT client authentication also supports a fully static Introspection Endpoint configuration. Configure the endpoint,
authentication method, credentials, and assertion settings to match the Authorization Server's registration; discovery
signing-algorithm metadata is not required when discovery is not loaded. A configured well-known URI alone does not
trigger discovery when the required endpoint and issuer are already available.

If discovery is loaded, including to obtain an issuer for a statically configured endpoint, its authentication capability
checks still apply. JWT authentication then requires signing-algorithm metadata containing the effective assertion
algorithm. Local credential, signing-key, and endpoint security checks apply in both static and discovered configurations.

Introspection requires `client-id`, authentication credentials for the selected method, and either
`endpoints.introspection-endpoint-uri` or well-known metadata that provides `introspection_endpoint`.
Principal mapping also needs a configured/discovered issuer or an explicit `subject-mapping.principal-id-namespace`.
This does not require the introspection response to contain `iss` or `sub`; see [Subject Mapping](#subject-mapping) for
issuer-less responses and explicit client/custom identity mappings.

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

### Introspection Failure Responses

Protected Resource authentication distinguishes token rejection from an inability to complete introspection:

| Result | Protected Resource response |
| --- | --- |
| Successful introspection with `active: false`, or token claims that fail local validation policy | `401` with the Bearer `invalid_token` challenge |
| An unsuccessful Introspection Endpoint HTTP response, including `400`, `401`, `403`, `429`, or `5xx` | `503 Service Unavailable` |
| A transport failure, timeout, cancellation, or unusable introspection response | `503 Service Unavailable` |
| Introspection admission capacity is exhausted | `503 Service Unavailable` |

This follows the distinction in [RFC 7662 sections 2.2 and 2.3](https://www.rfc-editor.org/rfc/rfc7662.html#section-2.3):
an inactive token is represented by a successful response containing `active: false`; an upstream authentication error
concerns the resource server's own introspection credentials. It does not establish that the caller's access token is
invalid. HTTP `503` is OIDC Next's dependency-unavailability policy, not a downstream status mandated by RFC 7662.

Unavailable validation fails closed with the controlled description `Bearer Token validation is unavailable` and no
`invalid_token` challenge. Upstream bodies, authentication challenges, cookies, redirect locations, and `Retry-After`
values are not forwarded. Safe HTTP status and exception-type diagnostics remain available internally. No automatic
retry or token acceptance fallback is introduced; once introspection recovers, the same still-valid token can succeed.

These responses describe Protected Resource Bearer Token authentication. Browser refresh retains its existing failure
policy; this change does not add recovery of partially completed refreshes or persistence of rotated refresh tokens
when subsequent validation cannot complete.

### Limiting Introspection Remote Work

Every distinct opaque token can cause an Introspection Endpoint request. Bound this work so a burst of invalid or unique
tokens cannot create unbounded remote calls and waiting request tasks:

```yaml
protected-resource:
  token-validation:
    method: INTROSPECTION
    introspection:
      remote-work:
        max-concurrent: 16
        max-queued: 64
        admission-timeout: "PT0.25S"
```

`max-concurrent` bounds Introspection Endpoint HTTP operations currently running for this tenant. `max-queued` is a hard
bound on callers waiting for an active permit; callers which cannot reserve queue capacity fail immediately.
`admission-timeout` controls how long an admitted caller may wait for an active permit, and `PT0S` makes active admission
fail immediately. Setting `max-queued` to `0` also makes requests fail immediately whenever all active permits are
occupied.

The defaults are 32 concurrent operations, 128 queued callers, and a `PT1S` admission timeout. Limits are local to each
tenant in each `OidcProvider` instance, so every service node enforces its own capacity. Cache behavior does not change:
introspection responses are still not cached.

When admission fails, the token is not mislabeled as invalid. Authentication fails with HTTP `503 Service Unavailable`
and the controlled description `Bearer Token validation is unavailable`; no Introspection Endpoint request is started.
Choose the concurrent limit from the Authorization Server's capacity and the service's connection budget. Keep the queue
short enough to fit the inbound request latency budget; increasing it absorbs a brief burst but does not add throughput.

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

When well-known metadata is loaded, `REQUIRED` mode requires
`tls_client_certificate_bound_access_tokens: true`. `IF_PRESENT` accepts an omitted or false capability flag because it
also accepts unbound tokens; any token containing `cnf.x5t#S256` still requires matching certificate proof. RFC 8705
defines this issuer capability metadata member as optional, with a default of `false` when omitted.

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
          protection:
            password: "${OIDC_COOKIE_PASSWORD}"
```

When `authorization-code` is configured and not explicitly disabled:

- `client-id` is required.
- `authorization-code.redirection-endpoint-uri` defaults to `/oidc/callback`.
- `authorization-code.scopes` must contain `openid` and each value must be one RFC 6749 `scope-token`.
- `authorization-code.prompts`, when configured, are sent as the OIDC Authentication Request `prompt` parameter.
- `authorization-code.resources`, when configured, are sent as repeated RFC 8707 Authentication Request `resource`
  parameters.
- `cookies.protection.password` is required.
- An Authorization Endpoint and Token Endpoint are required, either explicitly or from well-known metadata.
- A JWK Set URI is required for ID Token signature verification, either as `endpoints.jwks-uri` or as `jwks_uri` from
  well-known metadata.
- An issuer or well-known URI is required.

When Authorization and Token Endpoint URIs are static but `endpoints.jwks-uri` is omitted, OIDC Next loads well-known
metadata before initiating login to obtain `jwks_uri`. Tenant initialization fails before redirecting the browser or
exchanging an authorization code if no JWK Set source is available. To run with fully static endpoint configuration,
configure all three endpoints explicitly:

```yaml
endpoints:
  authorization-endpoint-uri: "https://issuer.example/authorize"
  token-endpoint-uri: "https://issuer.example/token"
  jwks-uri: "https://issuer.example/jwks"
```

Cookie protection uses PBKDF2-HMAC-SHA-256 with 600,000 iterations by default, followed by HKDF-SHA-256 to derive
separate AES-256-GCM keys for Authentication Request and local authentication cookies. Key derivation runs
synchronously on the tenant's first cookie operation and the derived keys are then retained in memory. Configure the
same strong, deployment-specific password on every replica. The password must contain between 16 and 1024 characters.

By default, the PBKDF2 salt is deterministically derived from a public format label, the tenant id, and the client id.
This keeps replicas interoperable without another required setting. To isolate deployments that intentionally reuse the
same tenant id, client id, and password, configure a random 16-byte salt as canonical unpadded Base64URL and use the same
value on every replica. The salt is public; it does not need confidential storage. The optional iteration count must be
between 600,000 and 10,000,000.

```yaml
cookies:
  protection:
    password: "${OIDC_COOKIE_PASSWORD}"
    salt: "yD6wIno2KCq2znbRzL3aUQ"
    iterations: 700000
```

Authorization Request `state` uses the versioned form
`s1.<base64url-encoded-tenant-id>.<256-bit-random-request-id>`. This lets an Authorization Response select one tenant
from local configuration before any tenant runtime is initialized. The tenant segment is an untrusted routing hint: the
provider still requires the protected Authentication Request cookie to contain the same tenant id and complete `state`
value before initializing that tenant or exchanging the authorization code. Base64URL encoding is not encryption, so
tenant ids used with Authorization Code Flow must not contain confidential information.

Authorization Response `iss` validation is automatic. If the callback contains `iss`, the provider requires an exact
string match with the issuer stored in the protected Authentication Request state. If well-known metadata advertises
`authorization_response_iss_parameter_supported: true`, callbacks without `iss` are rejected.

When enabled Authorization Code tenants with distinct (or not statically configured) issuers can use the same callback
path and origin, `iss` is required even if metadata was not loaded. If well-known metadata is loaded for such a tenant,
initialization requires `authorization_response_iss_parameter_supported: true`, so an incompatible provider fails before
login is initiated. A provider which does not implement RFC 9207 can be used safely in a multi-issuer client only with a
distinct callback path or distinct absolute callback origin for each issuer. Query-only differences are not treated as
distinct callback routes. The callback is also rejected if the issuer stored in protected Authentication Request state no
longer matches the initialized tenant issuer; no authorization code is sent to a Token Endpoint after either failure.

The default local callback path is resolved from the incoming request origin before it is sent as the OIDC
`redirect_uri`. When `endpoints.tls-required` is enabled, the resolved URI must use `https`. Configure
`authorization-code.redirection-endpoint-uri` only when the callback path or absolute callback URI must differ.

GET requests to enabled, configured callback endpoints are left to `OidcFeature` for Authorization Response validation.
Recognition matches the requested URI's decoded path, the origin for absolute callback configuration, and any configured
query values; it does not infer a callback from `state`, `code`, or `error` on other application routes. Fixed callback
query parameters are retained, and additional response parameters are allowed. Missing or malformed response parameters
are still rejected by the callback handler. Custom Security integrations must supply the actual request URI and query
parameters through `SecurityEnvironment.targetUri` and `queryParams`; the WebServer integration already does so.
Callback routes must remain reachable without an existing authenticated session.

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

Request Objects use RFC 9101 JWT-Secured Authorization Requests (JAR). RFC 9101 says the Request Object contains the
authorization request parameters as JWT claims, excludes `request` and `request_uri`, and is signed or signed then
encrypted. OpenID Connect Core also requires `response_type`, `client_id`, and `scope` to remain in the outer OAuth
request syntax when the by-value `request` parameter is used. `oidc-next` therefore sends only outer `response_type`,
`client_id`, `scope`, and `request` for normal by-value JAR redirects; the full request, including `redirect_uri`,
`state`, `nonce`, PKCE, prompts, and resource indicators, is inside the secured Request Object.

Configure signing and optional encryption under `authorization-code.request-object`.

```yaml
authorization-code:
  scopes: [ "openid", "profile" ]
  request-object:
    mode: REQUIRED
    signing-jwk:
      resource-path: "private-request-object-jwks.json"
    signing-key-id: "request-object-signing-key"
    signing-algorithm: RS256
    encryption-algorithm: RSA-OAEP-256
    content-encryption-algorithm: A128CBC-HS256
    encryption-key-id: "op-encryption-key"
    lifetime: "PT1M"

jwk-set:
  refresh-interval: "PT10M"
```

Modes:

- `DISABLED`: never sends Request Objects. If loaded metadata has `require_signed_request_object: true`, tenant
  initialization fails.
- `AUTO`: default. Signs when `request-object.signing-jwk` is configured, and requires signing when loaded metadata has
  `require_signed_request_object: true`. Without local signing key material and without a metadata requirement, the
  normal Authorization Code request is unchanged.
- `REQUIRED`: every Authentication Request uses a signed Request Object. `request-object.signing-jwk` is required.

The Request Object signing key is local client private key material. It must correspond to a public key registered at the
Authorization Server for Request Object validation. It is separate from the provider `jwks-uri`, which is the OP public
key set used to verify ID Tokens or access tokens, and separate from `client-assertion.jwk`, which is used for
`private_key_jwt` endpoint authentication. Supported Request Object signing keys are RSA and EC private JWKs using the
same JWS algorithms as `PRIVATE_KEY_JWT`, such as `RS256` or `ES256`. URI-backed `request-object.signing-jwk` resources
are rejected before the resource is created; use classpath, file, or configured content resources for this local private
key material.

Setting `encryption-algorithm` changes the result to a signed-then-encrypted Nested JWT with `cty=JWT`. Supported key
management algorithms are `RSA-OAEP-256` and `RSA-OAEP`; `RSA1_5` is rejected. The OP encryption key is never configured
as local key material. It is selected from the OP public JWK Set at `jwks_uri`, must be an RSA key of at least 2048 bits,
and must permit encryption when `use` or `key_ops` is declared. `encryption-key-id` optionally pins an exact OP key;
otherwise the first eligible key in JWK Set order is selected. Its `kid` is emitted when present and is required when the
JWK Set contains multiple keys. Configure `jwk-set.refresh-interval` when outbound encryption keys must follow OP key
rotation.

`content-encryption-algorithm` selects the JWE `enc` value. When omitted with encryption enabled, it defaults to
`A128CBC-HS256` as defined by OpenID Connect Dynamic Client Registration. Encryption is never enabled merely because OP
metadata advertises it. With explicit Authorization and Token Endpoint configuration, also configure
`endpoints.jwks-uri`; discovery normally supplies it.

Request Objects can be combined with PAR. In that mode the PAR body contains the compact signed or encrypted `request`
parameter plus any client-authentication parameters required by the selected client authentication method; authorization
request parameters remain inside the secured JWT claims. The browser redirect remains the PAR redirect with only
`client_id` and the server-generated `request_uri`. Unsigned Request Objects and client-hosted `request_uri` remain
unsupported.

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
An enabled tenant with `encryption-required: true` must configure `decryption-jwk`; otherwise configuration fails before
tenant initialization or any login requests. When encryption is not required, decryption keys remain optional, and
configuring a key alone does not prohibit signed-only ID Tokens.
The key uses the [private-key source policy](#private-key-sources): local paths, classpath resources, or supplied content;
URI sources are rejected before opening.

Provider-wide discovery capabilities do not request encryption for the client. Align the decryption key, allowed
algorithms, and `encryption-required` setting with the client registration. Ignoring unused discovery encryption
capabilities does not relax signature, claim, JWE-header, or required-encryption validation of received ID Tokens.

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
          protection:
            password: "${OIDC_COOKIE_PASSWORD}"
```

The provider requires encrypted ID Tokens to be nested JWTs (`cty=JWT`), decrypts the outer JWE, and then validates the
inner signed JWT with the normal ID Token validation rules and the OpenID Provider JWK Set. Signed ID Tokens remain
accepted when decryption keys are configured unless `encryption-required` is enabled; decryption keys mean that encrypted
ID Tokens can be processed.

Critical JWE extensions are not supported. Encrypted ID Tokens containing a `crit` header are rejected before key
selection or decryption, including empty or malformed critical lists. Unknown non-critical extension headers are ignored.
The same policy applies when validating a refreshed ID Token or restoring an encrypted ID Token from a local cookie.

The decryption JWK Set should contain private client/RP encryption keys. If more than one decryption key is configured,
the encrypted ID Token JWE header must contain `kid`. When a JWK declares `use`, the value must be `enc`; when it
declares `key_ops`, it must allow `unwrapKey` or `decrypt`.

Supported JWE key management algorithms are `RSA-OAEP-256` and `RSA-OAEP`. Supported content encryption algorithms are
`A128GCM`, `A192GCM`, `A256GCM`, `A128CBC-HS256`, `A192CBC-HS384`, and `A256CBC-HS512`. The local allowlists may select
a subset of these capabilities; defaults remain `[ "RSA-OAEP-256", "RSA-OAEP" ]` for `alg` and
`[ "A256GCM", "A128CBC-HS256" ]` for `enc`. Algorithm names are case-sensitive, and every configured entry must be
supported by Helidon's shared JWT implementation. Unsupported values, including `RSA1_5`, are rejected when an enabled
tenant is built. Keeping `RSA1_5` disabled follows the recommendation in
[RFC 8725 section 3.2](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.2) to avoid RSA-PKCS1 v1.5 encryption.

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
                .decryptionJwk(ResourceConfig.builder()
                        .resourcePath("rp-id-token-decryption-jwks.json")
                        .buildPrototype())
                .encryptionRequired(true))
        .authorizationCode(authorizationCode -> authorizationCode
                .redirectionEndpointUri(URI.create("https://app.example/oidc/callback"))
                .scopes(List.of("openid", "profile")))
        .cookies(cookies -> cookies
                .protection(protection -> protection.password(System.getenv("OIDC_COOKIE_PASSWORD"))))
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
          protection:
            password: "${OIDC_COOKIE_PASSWORD}"
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

Supported JWE key management algorithms are `RSA-OAEP-256` and `RSA-OAEP`. Supported content
encryption algorithms are `A128GCM`, `A192GCM`, `A256GCM`, `A128CBC-HS256`, `A192CBC-HS384`, and
`A256CBC-HS512`. Algorithm names are case-sensitive. Unsupported values, including `RSA1_5`, are rejected during tenant
configuration when UserInfo is enabled; there is no algorithm fallback. UserInfo signing algorithm `none` and `HS*`
algorithms are rejected. When well-known metadata publishes UserInfo signing or encryption capabilities, the configured
registration algorithms must be advertised.

UserInfo and ID Token algorithms are separate client-registration properties. Their configuration is therefore kept
separate. Both can reference the same private JWK Set resource when the provider registration uses the same RP key, but
configuring ID Token decryption does not implicitly enable UserInfo decryption.

Encrypted UserInfo uses the same critical-header policy as encrypted ID Tokens: any `crit` header is rejected, including
an empty or malformed list. This applies to both encryption-only and signed-then-encrypted UserInfo responses.

By default, `storage-policy: mapped` stores only the UserInfo `sub`, claims used to map names/roles/scopes, and claims listed
in `attribute-claim-paths`. Protected Resource principal-id paths do not add fields to browser UserInfo storage.
This follows the OpenID Connect Core privacy guidance: "Only necessary UserInfo data should
be stored at the Client". Stored UserInfo claims are kept in the protected local authentication result cookie and merged
into subject attributes on later requests. UserInfo claims override ID Token claims with the same name for principal
attributes, principal name, and roles, except ID Token protocol and authentication claims remain ID Token sourced.
Principal id always comes from the validated ID Token's issuer and subject.

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
                        .decryptionJwk(ResourceConfig.builder()
                                .resourcePath("userinfo-decryption-jwks.json")
                                .buildPrototype()))
                .storagePolicy(OidcUserInfoStoragePolicy.MAPPED)
                .attributeClaimPaths(List.of("email", "department")))
        .cookies(cookies -> cookies
                .protection(protection -> protection.password(System.getenv("OIDC_COOKIE_PASSWORD"))))
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
          protection:
            password: "${OIDC_COOKIE_PASSWORD}"
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
          protection:
            password: "${OIDC_COOKIE_PASSWORD}"
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
        .cookies(cookies -> cookies
                .protection(protection -> protection.password(System.getenv("OIDC_COOKIE_PASSWORD"))))
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
          protection:
            password: "${OIDC_COOKIE_PASSWORD}"
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
          protection:
            password: "${OIDC_COOKIE_PASSWORD}"
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
          protection:
            password: "${OIDC_COOKIE_PASSWORD}"
```

`client_secret_jwt` and `private_key_jwt` send `client_assertion_type` with
`urn:ietf:params:oauth:client-assertion-type:jwt-bearer` and a signed `client_assertion` JWT. The assertion uses
`client-id` as `iss` and `sub`, the Token Endpoint URI as `aud`, and includes `iat`, `exp`, and `jti`.
For `CLIENT_SECRET_JWT`, `algorithm` defaults to `HS256`; configure `key-id` if the Authorization Server expects a
`kid` header on the assertion. For `PRIVATE_KEY_JWT`, `jwk` is required and `key-id` is required when the configured JWK
Set contains more than one key. A configured `algorithm` must match a declared JWK `alg`; when the JWK omits optional
`alg`, the configured algorithm selects a compatible use of that key.
When well-known metadata is loaded, the configured method must be listed in `token_endpoint_auth_methods_supported`.
If the metadata omits that entry, the Discovery default is `client_secret_basic`. JWT client authentication additionally
requires `token_endpoint_auth_signing_alg_values_supported` to include the assertion signing algorithm; no default
assertion signing algorithms are assumed.

The same authentication methods can be used for Token Introspection, but introspection is configured under
`protected-resource.token-validation.introspection`. If `introspection.client-assertion` is omitted, the tenant
`client-assertion` is reused. For introspection assertions, the `aud` claim is the Introspection Endpoint URI.

Private assertion keys use a Common `ResourceConfig` description, not an already-open stream. Each authentication-support
instance opens its own local resource, parses the signing key, and retains that key for its requests. Repeated or
concurrent consumers therefore do not share a single-use stream, including inherited introspection authentication,
deferred endpoint clients, and provider/feature initialization.

Only key material is reused, not a signed assertion. Every JWT client authentication request still creates a unique `jti`
and computes `iat` and `exp` for that request, with the effective client identity, endpoint audience, key selection, and
signing algorithm. This
preserves [OIDC Core section 9](https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication) assertion
single-use semantics.

### Private key sources

`client-assertion.jwk`, `id-token.decryption-jwk`, and `user-info.jwt.decryption-jwk` accept these Common resource forms:

- `path`: a filesystem path.
- `resource-path`: a classpath resource.
- `content-plain`: supplied private JWK Set JSON.
- `content`: Base64-encoded private JWK Set JSON.

URI sources are rejected before opening, including HTTPS and file URIs; use `path` for a file. A URI cannot be hidden
alongside another source. This policy also applies to independently built sub-configurations and disabled tenants;
`endpoints.tls-required: false` does not relax it. These private keys are separate from the OpenID Provider's public
`jwks-uri`, whose normal WebClient retrieval is unchanged.

Programmatic setters take `ResourceConfig`. Build it with `buildPrototype()`, as in the examples, rather than `build()`,
which creates an open `Resource`. Configuration retains the description without opening the key source. Keep files and
classpath resources available when new runtime consumers are created. Each consumer retains its parsed key; changing a
file does not automatically reload existing consumers. Use fresh consumers/providers for deliberate key rotation.
Use supplied content when all consumers must use the same immutable key material.

A secure external secret store may be used by explicitly retrieving its private JWK Set through the application's
controlled secret-loading mechanism and supplying `content-plain` or `content`. Do not log the private material or its
resource description when it contains inline content. This is the provider's local-source policy, not an OIDC requirement
to store keys on disk; the standards require protecting private-key confidentiality.

### JOSE Key Strength And Optional JWK Algorithms

OIDC Next applies the mandatory [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html) key-strength rules to every
supported JOSE operation. For
`CLIENT_SECRET_JWT`, the UTF-8 representation of `client-secret` must meet the selected HMAC hash-output size:

| Algorithm | Minimum secret size |
| --- | --- |
| `HS256` | 32 UTF-8 octets |
| `HS384` | 48 UTF-8 octets |
| `HS512` | 64 UTF-8 octets |

The limit is measured in encoded octets, not Java characters. OIDC Next does not hash, pad, or otherwise expand a short
client secret into a compliant HMAC key. Provision a cryptographically random secret of sufficient size at the
Authorization Server and supply the exact registered value to every service replica.

```yaml
security:
  providers:
    - oidc-next:
        client-id: "${OIDC_CLIENT_ID}"
        client-secret: "${OIDC_CLIENT_SECRET}" # At least 48 UTF-8 octets for HS384
        token-endpoint-auth-method: CLIENT_SECRET_JWT
        client-assertion:
          algorithm: HS384
```

Programmatic equivalent:

```java
OidcProviderConfig config = OidcProviderConfig.builder()
        .clientId(System.getenv("OIDC_CLIENT_ID"))
        .clientSecret(System.getenv("OIDC_CLIENT_SECRET"))
        .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.CLIENT_SECRET_JWT)
        .clientAssertion(assertion -> assertion.algorithm("HS384"))
        .endpoints(endpoints -> endpoints
                .tokenEndpointUri(URI.create("https://issuer.example/token")))
        .buildPrototype();
```

All RSA JWKs selected for OIDC Next signing, signature verification, key encryption, or key decryption must have a
modulus of at least 2048 bits. This covers JWT access tokens, ID Tokens, signed UserInfo responses, client assertions,
signed or encrypted Request Objects, and encrypted ID Token/UserInfo responses. A 1024-bit RSA key is rejected even if
the underlying JCA provider can technically execute the operation.

[RFC 7517 section 4.4](https://www.rfc-editor.org/rfc/rfc7517.html#section-4.4) makes the JWK `alg` member optional.
Omission does not mean `RS256`: OIDC Next uses the already validated JWT/JWE header or configured signing algorithm when
it is compatible with the key. If the JWK declares `alg`, that declaration is an exact constraint and a different
operation algorithm is rejected. For example, this configuration legitimately uses `RS384` with a private JWK that
omits `alg`:

```yaml
token-endpoint-auth-method: PRIVATE_KEY_JWT
client-assertion:
  algorithm: RS384
  key-id: "client-signing-key"
  jwk:
    resource-path: "private-client-jwks.json"
```

The selected JWK can have this shape; the placeholder values must be replaced with actual base64url-encoded key values:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "client-signing-key",
      "use": "sig",
      "n": "<base64url-encoded modulus of at least 2048 bits>",
      "e": "AQAB",
      "d": "<base64url-encoded private exponent>"
    }
  ]
}
```

Before upgrading an existing deployment, rotate any shorter HMAC secrets or RSA keys. These configurations previously
reached the crypto provider but now fail at OIDC configuration/runtime initialization or remote-key validation with a
controlled authentication failure.

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
          protection:
            password: "${OIDC_COOKIE_PASSWORD}"
```

For `TLS_CLIENT_AUTH` and `SELF_SIGNED_TLS_CLIENT_AUTH`, the OIDC provider sends `client_id` in the Token Endpoint form
and relies on enabled tenant `webclient.tls` for the mutual TLS client certificate proof. Configure private key plus
certificate chain, an SSL context, or a custom TLS manager. The `private-key` TLS block supplies the client
certificate/key used for mutual TLS. The `trust` TLS block validates the Authorization Server certificate. When
well-known metadata supplies an alias for the Token, PAR, or Introspection Endpoint, an mTLS-authenticated request uses
that alias in preference to the conventional endpoint, including when the conventional URI is explicitly configured.
Non-mTLS requests continue to use the conventional URI. RFC 8705 mTLS endpoints always require HTTPS. If the Token
Endpoint is loaded from well-known metadata, the well-known URI must also use HTTPS. `endpoints.tls-required: false`
does not relax these mTLS requirements.

Programmatic `private_key_jwt` configuration:

```java
OidcProviderConfig config = OidcProviderConfig.builder()
        .issuer("https://issuer.example")
        .clientId(System.getenv("OIDC_CLIENT_ID"))
        .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.PRIVATE_KEY_JWT)
        .clientAssertion(clientAssertion -> clientAssertion
                .jwk(ResourceConfig.builder()
                        .resourcePath("private-client-jwks.json")
                        .buildPrototype())
                .keyId("client-signing-key")
                .algorithm("RS256"))
        .authorizationCode(authorizationCode -> authorizationCode
                .redirectionEndpointUri(URI.create("https://app.example/oidc/callback")))
        .cookies(cookies -> cookies
                .protection(protection -> protection.password(System.getenv("OIDC_COOKIE_PASSWORD"))))
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
          protection:
            password: "${OIDC_COOKIE_PASSWORD}"
```

## Outbound Token Propagation, Client Credentials, And Token Exchange

Outbound target selection uses Helidon's common `OutboundTarget` model. Configure targets as the provider-level
`outbound` list. A target can match by transport, host, path, and method. The matching target selects the OIDC outbound
action. For token acquisition, the resolved tenant supplies the issuer, client credentials, Token Endpoint, and TLS
settings for OpenID Provider or Authorization Server calls. The application's HTTP client separately configures TLS
for its downstream resource requests; Token Propagation only prepares their Authorization header.

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

Certificate-bound tokens retain their binding when propagated. For direct resource access,
[RFC 8705 section 3](https://www.rfc-editor.org/rfc/rfc8705.html#section-3) requires the downstream connection to use mutual
TLS with the certificate associated with the token and proof of possession of its private key. The
`Authorization: Bearer` header remains correct. A different certificate is rejected with `401 invalid_token`; requiring
a client certificate at the TLS layer can instead reject a missing certificate before HTTP processing.

Configure the application's downstream `WebClient` TLS identity independently. Tenant `webclient.tls` is used for OP/AS
calls and does not configure that application client. Neither an incoming peer certificate nor successful propagation
proves possession of the private key on the outgoing connection. `oidc-next` does not select or transfer proof keys, strip
token bindings, or automatically exchange tokens. If the service cannot provide the required proof, propagation alone
cannot make that call work. Explicit Token Exchange is an alternative only if issuer policy permits it and issues a
token suitable for the downstream call.

[RFC 8705 section 6.5](https://www.rfc-editor.org/rfc/rfc8705.html#section-6.5) also permits TLS termination at an
intermediary, but securing certificate metadata between that intermediary and the resource is a separate integration.
Token Propagation does not provide it; `oidc-next` protected-resource validation does not trust forwarded certificate
headers. An outbound `SUCCESS` means headers were prepared, not that downstream authentication has succeeded.

Client Credentials Grant obtains an access token from the Token Endpoint with `grant_type=client_credentials` and applies
the same Token Endpoint client authentication settings as Authorization Code Flow and refresh-token requests. The token is
cached until it is close to expiration, then reacquired.

Each `OidcProvider` instance maintains separate process-local Client Credentials and Token Exchange caches. Each cache
uses Helidon's thread-safe least-recently-used cache with a strict 10,000-entry capacity; the least recently used entry is
evicted when a new value exceeds that capacity. These caches are performance optimizations, not shared token stores.
Different service nodes may acquire and cache their own tokens, and neither request affinity nor distributed storage is
required. The caches start no background threads and need no external lifecycle management.

Concurrent misses for the same complete cache key are coalesced within one provider instance. One caller performs the
Token Endpoint request while admitted followers wait for that same result. Different keys do not share a result and can
run concurrently, subject to the separate per-tenant Client Credentials and Token Exchange admission limits. A successful
token is retained only when it has a positive `expires_in` and remains valid beyond the configured tenant clock skew.
OAuth failures, responses without a reusable lifetime, and already-expired responses are shared only with callers waiting
for that request and are not cached. Expired entries are never returned; they are replaced by a later successful load or
removed by normal bounded LRU eviction.

The coordination path is designed for virtual-thread callers. Token Endpoint I/O runs outside the LRU cache locks and
outside `ConcurrentHashMap` update callbacks. Callers waiting for the same key hold no cache or map lock, so a slow Token
Endpoint request does not serialize unrelated keys through a cache critical section. Both grant types may deliberately
queue unrelated keys at their configured admission limits.

Client Credentials admission is configured through `client-credentials-remote-work`, alongside `token-exchange-remote-work`
at provider root or under `tenants.<tenant-id>`. Its defaults are `max-concurrent: 32`, `max-queued: 128`, and
`admission-timeout: PT1S`. One active permit covers the complete acquisition, including deferred metadata resolution when
needed and the Token Endpoint request. Capacity is shared across all this tenant's outbound targets and endpoint policies,
but independent of other tenants and other grant categories. Valid cached tokens bypass admission.

The queue is shared by new operations awaiting active capacity and followers of an existing same-key operation. Queue
slots are reserved immediately. `max-queued: 0` allows new operations with available active capacity but does not allow
waiting, including same-key followers. The admission timeout limits only a new operation's wait for an active permit;
it is not a deadline for an admitted same-key follower or for network I/O. Followers wait interruptibly for the shared
result, with no additional one-second cutoff. Interrupting a follower does not cancel the shared operation.

Rejection or interruption produces the existing outbound `FAILURE`, with no generated Authorization header. It is not
cached as a token result and does not cause an expired token to be forwarded. DEBUG logging distinguishes local admission
failure from Token Endpoint failure. Consumers must honor the outbound failure: the current shared `WebClientSecurity`
integration traces provider failure but continues the HTTP request, so it does not automatically abort transmission or
map admission failure to HTTP 503. Downstream authentication and application error handling remain necessary.

### Token Response Lifetimes

Authorization Code, refresh, Client Credentials, and Token Exchange responses use `expires_in` as a lifetime in seconds,
as defined by [RFC 6749 section 5.1](https://www.rfc-editor.org/rfc/rfc6749.html#section-5.1) and
[RFC 8693 section 2.2.1](https://www.rfc-editor.org/rfc/rfc8693.html#section-2.2.1). An explicit zero means that the access
token is already expired. OIDC Next rejects such a response before sending the token to UserInfo or an outbound resource
or storing it in an authentication cookie. Negative, fractional, nonnumeric, or numerically out-of-range values also
produce a controlled Token Endpoint failure. Numeric lifetimes must fit in a signed 64-bit integer.

An omitted `expires_in` remains distinct from an expired token. Client Credentials and Token Exchange can use a token
without this field for the current request, but do not cache it. Initial browser authentication stores no access-token
deadline when the field is absent; the ID Token expiry and configured local authentication lifetime still bound the
session. Automatic renewal needs an access-token deadline, and a refresh response without `expires_in` retains its
existing failure handling: keep the current authentication only while its access token remains valid; otherwise clear it
and start authentication again.

A short positive lifetime is not rejected just because it falls within the clock-skew margin. Such an outbound token is
used for the current request without being cached. Very large positive lifetimes are converted without arithmetic
overflow: an absolute expiry beyond Java's `Instant.MAX` is conservatively capped at that representable bound. This does
not extend the advertised token lifetime or the browser's configured/ID-Token-bounded session lifetime.

### Endpoint-Level Grant Discovery

Provider-level `outbound` targets are known while each tenant is initialized, so required Token Endpoint metadata and
capabilities can be loaded and validated at that point. An endpoint-level `OidcOutboundPolicy` is visible only when an
outbound request is made. When such a policy needs Client Credentials Grant or Token Exchange and the tenant has no static
`endpoints.token-endpoint-uri`, discovery is deferred until the first token-cache miss.

Deferred discovery is coordinated once per configured tenant. Concurrent cache misses share one metadata request, and a
successful result is reused by both endpoint-level grant types. A token-cache hit does not perform discovery at all, so a
later metadata-endpoint outage does not prevent reuse of an otherwise valid cached token. Waiting metadata followers are
interruptible and do not cancel the shared request.

Only an admitted Client Credentials or Token Exchange loader reaches deferred discovery. Consequently, the number of
callers inside resolution is bounded by the sum of those grants' configured active limits; same-key token followers stay
outside resolution and consume their grant's bounded queue instead. The limits apply before metadata access, including
retry attempts. No additional discovery-specific limiter or queue setting is needed for these entry paths.

A transient metadata load failure is shared and held for the tenant's `initialization-retry-interval`; one later caller
retries after that interval. Successfully loaded metadata is retained for the lifetime of the `OidcProvider` and is not
periodically refreshed. Recreate the provider to adopt a later metadata capability or endpoint change. Static Token
Endpoint configuration also remains static for the provider lifetime.

Before any Token Endpoint request, deferred metadata is validated with the same rules as provider-level targets.
The discovered `grant_types_supported` list must include `client_credentials` for Client Credentials Grant or
`urn:ietf:params:oauth:grant-type:token-exchange` for Token Exchange. If omitted, the RFC 8414 default
`["authorization_code", "implicit"]` applies and does not advertise either grant.
Both grants validate `token_endpoint_auth_methods_supported` and, for JWT client
authentication, `token_endpoint_auth_signing_alg_values_supported`. An unsupported combination returns the grant's
controlled outbound failure without contacting the Token Endpoint.

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
        client-credentials-remote-work:
          max-concurrent: 32
          max-queued: 128
          admission-timeout: "PT1S"
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
is loaded, `grant_types_supported` must include `urn:ietf:params:oauth:grant-type:token-exchange`. Omitting that member
uses the RFC 8414 default `["authorization_code", "implicit"]`, so Token Exchange is rejected before a Token Endpoint
request. Wholly static Token Endpoint configuration without discovery does not require advertised grant metadata.

The first Token Exchange implementation intentionally supports only issued Bearer access tokens. The Token Endpoint
successful response must contain `issued_token_type=urn:ietf:params:oauth:token-type:access_token` and
`token_type=Bearer`. `token_type=N_A`, issued ID Tokens, SAML assertions, refresh-token exchange, actor-token delegation,
and first-class `act` or `may_act` handling are not implemented by this outbound mode.

Exchanged tokens are cached only when the response includes a positive `expires_in`. The cache key includes the tenant id,
a SHA-256 hash of the subject token, configured scopes, resource, and audience. Raw subject tokens are not stored in cache
keys. The cache uses the tenant token-validation clock skew and does not assume that input-token revocation automatically
revokes already exchanged tokens. The shared process-local cache and concurrent-miss behavior described for Client
Credentials Grant above also applies to Token Exchange.

Token Exchange remote work is bounded per tenant because an attacker or large burst can supply a different subject token
for every request and bypass same-key coalescing. Cache hits consume no permit. A cache miss uses one active permit, and
both distinct-key callers waiting for an active permit and same-key callers waiting for the elected request count against
the shared queue. Waiting for a same-key result is interruptible; interrupting a follower does not cancel the elected
Token Endpoint request.

```yaml
security:
  providers:
    - oidc-next:
        client-id: "${OIDC_CLIENT_ID}"
        client-secret: "${OIDC_CLIENT_SECRET}"
        token-endpoint-auth-method: CLIENT_SECRET_BASIC
        token-exchange-remote-work:
          max-concurrent: 16
          max-queued: 64
          admission-timeout: "PT0.25S"
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

`token-exchange-remote-work` uses the same defaults and option semantics as introspection remote work: 32 active, a hard
bound of 128 queued callers, and `PT1S` for an admitted caller to obtain active capacity. It is tenant configuration shared
by all Token Exchange outbound targets for that tenant; it does not limit Token Propagation or Client Credentials Grant.
On overload, outbound security returns `FAILURE` with the controlled description `Token Exchange failed` and does not add
an exchanged Bearer token. `PT0S` or `max-queued: 0` provides fail-fast behavior when active capacity is exhausted.

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

OidcProviderConfig config = OidcProviderConfig.builder()
        .issuer("https://issuer.example")
        .clientId(System.getenv("OIDC_CLIENT_ID"))
        .clientSecret(System.getenv("OIDC_CLIENT_SECRET"))
        .tokenEndpointAuthenticationMethod(OidcClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .endpoints(endpoints -> endpoints
                .tokenEndpointUri(URI.create("https://issuer.example/token")))
        .tokenExchangeRemoteWork(remoteWork -> remoteWork
                .maxConcurrent(16)
                .maxQueued(64)
                .admissionTimeout(Duration.ofMillis(250)))
        .outboundTargets(List.of(ordersApi))
        .buildPrototype();
```

## Local Authentication Cookies

Authorization Code Flow stores one authenticated session in a bounded set of protected local authentication cookies.
Small sessions use one cookie; larger sessions are automatically split after authenticated encryption and encoding.
This is provider-neutral and does not change the tokens issued by the OpenID Provider.

```yaml
cookies:
  authentication-request-cookie-name: "__Host-helidon-oidc-state"
  local-authentication-cookie-name: "__Host-helidon-oidc-auth"
  authentication-request-lifetime: "PT5M"
  local-authentication-lifetime: "PT1H"
  max-cookie-size: 3800
  max-chunks: 4
  max-total-size: 12288
  compression: NONE
  max-session-size: 65536
  protection:
    password: "${OIDC_COOKIE_PASSWORD}"
```

Cookie lifetimes must be positive. Both names must be distinct valid HTTP cookie names. Use the same cookie protection
password, salt override, and iteration count on every service node that must accept the same browser session. This makes
cookies readable without affinity, but safe coalescing of refresh-token rotation remains process-local as described
below.

The additional settings are directly on `OidcCookieConfig`, with equivalent programmatic builder methods. There is no
`chunking` subnode. Root `cookies` is single-tenant shorthand; named tenants use `tenants.<name>.cookies`.

| Setting | Meaning |
| --- | --- |
| `max-cookie-size` | Maximum serialized bytes of each session Set-Cookie field value, including its name and attributes. At most 4096; must leave room for framing and payload. |
| `max-chunks` | Maximum physical cookies in one session, including the base, between 1 and 16. One disables multi-cookie sessions. Applies to reads and writes. |
| `max-total-size` | Encoded session-cookie request-header budget, including names and separators. Also bounds outgoing session Set-Cookie headers, including required deletions. At most 65536; must accommodate clearing the fixed namespace. |
| `compression` | `NONE` or `GZIP`, which is used only when smaller. NONE affects new writes; authenticated GZIP sessions remain readable. No provider-specific defaults or detection. |
| `max-session-size` | Maximum UTF-8 session JSON bytes before compression and after authenticated decompression, between 1 and 1048576. Applies even without compression. |

Leave header capacity for other application cookies, authentication-request state, browser generation, and other headers.
The default 12-KiB budget is below Helidon's default 16-KiB HTTP/1 received-header limit, but smaller proxy limits must
also be respected. Chunking does not reduce aggregate traffic or permit unlimited token sizes. Final serialized sizes,
not raw token lengths, determine whether a session fits. Reducing configured limits can require reauthentication.

The base cookie keeps the configured name; subsequent pieces use `.1` through `.15`. The finite namespace is reserved
regardless of the configured count, and overlapping state/generation or different tenant session namespaces are rejected.
The authenticated v2 framing binds the encoding, count, and update identity to the tenant/client/purpose-protected
session. Missing, duplicate, mixed, or tampered required pieces cannot authenticate. Earlier unchunked v1 local-session
values are not accepted by this format; authentication-request and generation cookies retain their existing format.

Every piece shares the absolute local session expiration. Shrinking or replacing a session explicitly expires observed
obsolete pieces. Logout, expired/corrupt sessions, and terminal refresh failures clear the entire sixteen-slot namespace
even when the base/count is missing. Clearing uses a past Expires with the same host/path policy; unrelated cookie names
are not reflected into deletion headers. Logout also rotates the separate browser-generation cookie, while ordinary
refresh does not: a late refresh response must not authenticate against the new browser generation.

Cookie updates are prepared and checked before success is reported. A session that cannot fit produces a controlled
storage error rather than token truncation or a successful redirect followed by a login loop. If a completed refresh
cannot be persisted, its source session is cleared and the cohort receives an unavailable result; the provider does not
fall back to its predecessor refresh token. Ordinary transient upstream/admission failures retain their existing policy.

GZIP is opt-in because compression can disclose information through ciphertext lengths when chosen plaintext shares a
compression context with secrets. Assess the deployment before enabling it; this is cookie compression, not JOSE `zip`.
Decompression occurs only after authentication and is size-bounded. See
[RFC 8725 sections 2.4 and 3.6](https://www.rfc-editor.org/rfc/rfc8725.html#section-2.4).

The local authentication result lifetime is capped by the configured `local-authentication-lifetime` and by token
expiration. The provider uses the ID Token as the authentication source and exposes the access token through
`TokenCredential`.

If a refresh token is available, the provider can refresh the local authentication result before the access token
expires. A terminal refresh failure, such as `invalid_grant`, removes the local authentication cookie.

Concurrent requests carrying the same source authentication cookie share one refresh operation within a tenant runtime.
The elected caller performs the Token Endpoint request, refreshed-token validation, and UserInfo retrieval. Admitted
followers wait interruptibly without holding a cache or coordination lock, which allows virtual threads to park normally.
All admitted cohort callers receive the same refreshed, retained, removal, or unavailable decision. A successful cohort
also shares one prepared encrypted chunk set and retirement plan; followers do not independently encrypt different
fragments of the same logical refresh result. Remaining cookie lifetimes are calculated when each response is emitted.

A completed result remains reusable for a short grace interval so a request which reaches refresh just after rotation
does not submit the now-invalid old refresh token. The key contains SHA-256 fingerprints rather than raw ID, access, or
refresh tokens and also identifies the source browser generation and local-session creation time. The grace cache is
strictly capacity bounded. Defaults are five seconds and 1,024 completed source sessions; configuration rejects intervals
below one second or above one minute to avoid both ineffective coordination and long refresh-token replay windows.

```yaml
authorization-code:
  refresh-result-retention: "PT5S"
  refresh-result-cache-capacity: 1024
  refresh-remote-work:
    max-concurrent: 32
    max-queued: 128
    admission-timeout: "PT1S"
```

Refresh coordination and its limits are local to one tenant in one `OidcProvider` runtime. In a multi-node deployment,
route a browser session consistently during refresh or use an Authorization Server with an appropriate legitimate-use
grace policy. Process-local coordination cannot suppress a simultaneous redemption performed by another service node.

Queue capacity is reserved without waiting and is therefore a hard bound. A distinct source session may wait up to
`admission-timeout` for an active refresh slot. A same-session follower reserves a queue slot and then waits interruptibly
for its leader. If admission fails or a follower is interrupted, a still-valid access token remains usable without a
cookie change. An expired session receives `503 Service Unavailable` without cookie deletion or a competing login flow.

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
          protection:
            password: "${OIDC_COOKIE_PASSWORD}"
```

Refreshed ID Tokens are validated before storage. The provider rejects refreshed ID Tokens that unexpectedly change
issuer, subject, audience, authorized party, nonce, or authentication time.

## Subject Mapping

Subject mapping controls how token claims become the Helidon Security principal and grants.

Defaults:

```yaml
subject-mapping:
  principal-id-claim-paths: [ "sub" ]
  principal-name-claim-paths: [ "preferred_username", "username" ]
  role-claim-paths: [ "groups" ]
  scope-claim-paths: [ "scope" ]
  scope-grants-enabled: true
```

Principal name claim paths are tried in order. Principal id claim paths are tried in order for Protected Resource JWT and
introspection authentication. Authorization Code Flow always uses the ID Token's issuer and subject. Role and scope claim
paths are aggregated from all configured paths and duplicate grant names are ignored.
Dotted paths read nested objects, for example `realm_access.roles`.

Principal id and principal name claims must be strings. Role claims may be strings or string arrays. Standard `scope`
claims must be space-delimited RFC 6749 scope strings using ASCII spaces. Custom scope claim paths, such as `scp`, may be
strings or string arrays; array values are treated as individual scope tokens.

For Authorization Code Flow local authentication, scope grants come from the Token Endpoint scope value stored in the
local authentication result. ID Token scope claims are not promoted to Helidon scope grants.

`Principal.id()` is an opaque, issuer-qualified identity, not a raw token claim. Authorization Code Flow derives it from
the validated ID Token's exact `iss` and `sub` values, following
[OpenID Connect Core 1.0, section 5.7](https://openid.net/specs/openid-connect-core-1_0.html#ClaimStability).
Protected Resource authentication uses the same identity for the same issuer and `sub` by default. Issuer and subject
strings are not case-folded or normalized. Pairwise or otherwise different subject identifiers remain different identities;
the provider does not link accounts using usernames or email addresses. The opaque Helidon encoding is a local API choice,
not an OIDC wire format. Store/compare the complete ID rather than parsing it.

Protocol identity claims (`iss` and `sub`, when present) remain available as principal attributes. Bearer token credentials
also retain the parsed JWT or introspection response. `Principal.name()` remains a display name and falls back to the raw
identity claim value when no configured name claim is present. Names are not globally unique
identifiers. Changing a display name does not change the OIDC identity.

For resource-server policies that explicitly identify a client or use a provider-specific stable identifier, configure
`principal-id-claim-paths`. The selected claim path is part of the qualified identity: `sub=123` and `client_id=123` are
different identities even at the same issuer. There is no default fallback to `username` or `client_id`. Custom claims
require an application-specific uniqueness and stability contract with the authorization server; qualification cannot
make a mutable or reused claim stable. These settings do not replace the ID Token identity during browser authentication.

[RFC 7662, section 2.2](https://www.rfc-editor.org/rfc/rfc7662.html#section-2.2) permits introspection responses without `iss`
or `sub`. When `iss` is absent, the configured/discovered issuer still qualifies the identity; a returned `iss` must match
that issuer. When neither a configured nor a discovered issuer exists, configure a stable local namespace for the trusted
introspection endpoint's identities. Choose different namespaces for independent identity authorities in the application:

```yaml
subject-mapping:
  principal-id-namespace: payments-authorization-server
  principal-id-claim-paths: [ "client_id" ]
```

This example explicitly identifies the requesting client; it does not infer a client credentials grant or identify the
resource owner of a delegated token. A response without `sub` can instead use a suitable explicitly configured custom claim.
A response that cannot satisfy the chosen principal mapping is rejected as unusable for this application, not because
RFC 7662 mandates `sub`. An unknown identity authority is reported as a configuration error.
Principal mapping is required only when the access token authenticates a Protected Resource request. Browser refresh
retains the ID Token identity and does not require a principal claim in the refreshed access token or its introspection
response; the configured token-validity checks still run.

The local namespace is separate from issuer-qualified identities, never fabricates an `iss` claim, and is not selected or
changed by response claims. It is a fallback only: configured/discovered issuers take precedence. These local identities
are not automatically linked to OIDC identities. This setting is not used for JWT access tokens or browser authentication.

ID Token validation requires `sub` to be non-blank ASCII and no longer than 255 characters. This is an ID Token protocol
check; protected-resource access tokens and introspection responses keep using the configured subject mapping rules.

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
          principal-id-claim-paths: [ "sub" ]
          principal-name-claim-paths: [ "preferred_username", "email" ]
          role-claim-paths: [ "groups", "idcs_groups", "iam.groups" ]
          scope-claim-paths: [ "scope", "scp" ]
          scope-grants-enabled: true
        cookies:
          protection:
            password: "${OIDC_COOKIE_PASSWORD}"
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
          protection:
            password: "${OIDC_COOKIE_PASSWORD}"
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
                .principalIdClaimPaths(List.of("sub"))
                .principalNameClaimPaths(List.of("preferred_username", "email"))
                .roleClaimPaths(List.of("groups", "idcs_groups", "iam.groups"))
                .scopeClaimPaths(List.of("scope", "scp"))
                .scopeGrantsEnabled(true))
        .cookies(cookies -> cookies
                .protection(protection -> protection.password(System.getenv("OIDC_COOKIE_PASSWORD"))))
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
          protection:
            password: "${OIDC_COOKIE_PASSWORD}"
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

`{tenant}` must be one complete DNS label. OIDC Next normalizes both the template and request authority with Helidon's
common URI policy: DNS names become lower-case ASCII, internationalized names use their IDNA ASCII form, and one terminal
dot is removed. IPv4 and IPv6 literals are recognized but do not match a DNS host template. Ports do not participate in
template matching. Consequently, host-derived tenant map keys must use the canonical label. For example, these
authorities select the shown tenant keys:

| Request authority | Tenant key |
| --- | --- |
| `API.example.com.:8443` | `api` |
| `Bücher.example.com` | `xn--bcher-kva` |

A host template does not accept an IP-literal authority, a tenant value spanning multiple labels, a malformed authority,
or multiple `Host` header values. When the host strategy is reached, any present authority that is invalid, fails to match
the template, or identifies an unconfigured tenant prevents selection of the default tenant. Only a request with no
effective authority can fall through from host resolution to the default tenant.

OIDC Next uses the effective target URI authority when available and otherwise requires exactly one nonblank `Host`
header value. Behind a reverse proxy, that effective URI can contain trusted forwarded authority information supplied by
WebServer requested URI discovery. Configure `trusted-proxies` narrowly; an untrusted forwarded host must never control
tenant selection.

Tenant resolution order is:

1. Header.
2. Path segment.
3. Path template.
4. Host template.
5. Default tenant.

When `header-name` is configured and that header is present, the request must contain exactly one nonblank value. A
blank or repeated tenant header does not resolve a tenant and does not fall through to another resolution strategy or
the default tenant.

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
| Host-based tenant does not resolve | Check the effective target URI or single `Host` value, canonical lower-case/IDNA tenant key, complete-label host template, port syntax, and trusted-proxy requested URI discovery. Present invalid, nonmatching, or unknown authorities never use the default tenant. |
| JOSE key or client assertion initialization fails | Check that RSA moduli are at least 2048 bits, `CLIENT_SECRET_JWT` secrets meet the selected 32/48/64-octet HMAC minimum, the configured algorithm is compatible with the key type, and any declared JWK `alg` exactly matches the operation. |
| `Bearer Token is invalid` with JWT validation | Check configured `issuer`, `protected-resource.token-validation.audience`, allowed algorithms, JWKS URI, JWK Set refresh settings, token `kid`, clock skew, and whether the token is a strict RFC 9068 access token. Without `kid`, exactly one key must remain eligible after algorithm, use, operations, type, and strength filtering. |
| `Bearer Token is invalid` with introspection | Check the introspection endpoint URI, introspection client authentication method, Authorization Server policy, required audience, issuer validation, and whether the response contains `active: true` plus a configured principal claim. |
| `Bearer Token validation is unavailable` with HTTP `503` | Introspection admission capacity is exhausted. Check Introspection Endpoint latency and health, inbound request rate, and `protected-resource.token-validation.introspection.remote-work`; increase limits only within the service and Authorization Server connection budgets. |
| `OIDC authentication is unavailable` with HTTP `503` while a local session refreshes | Refresh admission capacity is exhausted or the caller was interrupted after its source access token expired. Check Token Endpoint latency and health plus `authorization-code.refresh-remote-work`. No authentication cookie is removed by this response. |
| `Bearer Token request is invalid` | Check for multiple Bearer token sources, multiple Authorization Bearer values, malformed `access_token` query parameters, or non-HTTPS transport when secure transport is required. |
| Browser login loops or callback failures | Check redirect URI registration, reverse proxy requested-URI discovery, `X-Forwarded-*` headers, cookie domain/path/SameSite settings, clock skew, JWKS availability and key selection, PKCE metadata, PAR/JAR requirements, and cookie protection setting consistency. |
| UserInfo failures | Check that `user-info-endpoint-uri` or metadata `userinfo_endpoint` is available and that the UserInfo `sub` matches the ID Token `sub`. |
| Logout failures | Check local logout path configuration, same-origin `Origin` or `Referer`, post-logout redirect allowlist, and End Session Endpoint metadata. |
| Outbound Token Propagation abstains | Check outbound target matching, HTTPS target URI, current subject `TokenCredential`, and downstream audience validation. |
| Propagation succeeds but downstream rejects a certificate-bound token | Check the actual downstream HTTP client's TLS certificate against `cnf.x5t#S256`. Tenant `webclient.tls` and the incoming caller's TLS identity do not configure outgoing proof. Without the matching private-key proof, use an explicitly authorized alternative such as Token Exchange rather than copying the token alone. |
| Client Credentials or Token Exchange fails | Check Token Endpoint URI or metadata, advertised grant and client-authentication capabilities, confidential client authentication, client credentials or assertion key material, enabled Keycloak/client permissions, resource/audience values, and outbound target configuration. Endpoint-level policies retain successfully loaded metadata for the provider lifetime; recreate the provider after a deterministic metadata capability change. For transient discovery failures, check `initialization-retry-interval`. For Token Exchange bursts, also check `token-exchange-remote-work` capacity and Token Endpoint latency. |
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

Both forms apply `initialization-retry-interval`, `initialization-max-queued`, `client-credentials-remote-work`, and
`token-exchange-remote-work` to the
effective runtime tenant. In configuration files, any of these options identifies root single-tenant configuration when
it is the only tenant option present. Root tenant options are not shared defaults for named tenants; do not combine them
with `tenants`.

| Key | Description |
| --- | --- |
| `enabled` | Whether this tenant is enabled. Defaults to `true`. |
| `initialization-retry-interval` | Minimum interval before retrying a failed well-known metadata load during tenant initialization or lazy endpoint-level outbound grant discovery. Defaults to `PT10S`. Deterministic local configuration or metadata compatibility failures are not retried. |
| `initialization-max-queued` | Maximum waiting callers per tenant initialization attempt, in addition to its one initializer. Defaults to `128`; zero rejects followers while busy. Waiting is interruptible, with no separate admission deadline. Ready contexts and held failures bypass admission. |
| `issuer` | Expected Issuer Identifier string. Issuer identity comparisons use this exact string value. |
| `client-id` | OAuth 2.0 client identifier. |
| `client-secret` | OAuth 2.0 client secret. For `CLIENT_SECRET_JWT`, its UTF-8 representation must contain at least 32, 48, or 64 octets for `HS256`, `HS384`, or `HS512`. |
| `token-endpoint-auth-method` | Token Endpoint client authentication method: `CLIENT_SECRET_BASIC`, `CLIENT_SECRET_POST`, `CLIENT_SECRET_JWT`, `PRIVATE_KEY_JWT`, `TLS_CLIENT_AUTH`, `SELF_SIGNED_TLS_CLIENT_AUTH`, or `NONE`. `TLS_CLIENT_AUTH` and `SELF_SIGNED_TLS_CLIENT_AUTH` require enabled tenant `webclient.tls` with private key plus certificate chain, an SSL context, or a custom TLS manager. |
| `client-assertion` | Client assertion signing configuration for `CLIENT_SECRET_JWT` and `PRIVATE_KEY_JWT`. Used for Token Endpoint authentication and as the default for Introspection Endpoint authentication unless `protected-resource.token-validation.introspection.client-assertion` overrides it. |
| `id-token` | ID Token validation and decryption configuration. |
| `webclient` | WebClient configuration for well-known metadata, JWKS, Token Endpoint, introspection, and UserInfo requests. For RFC 8705 mTLS client authentication, `webclient.tls` must be enabled and provide private key plus certificate chain, an SSL context, or a custom TLS manager. |
| `jwk-set` | JSON Web Key Set reload policy used for ID Token and JWT access-token signature validation. |
| `client-credentials-remote-work` | Per-tenant admission limits for Client Credentials acquisition across outbound targets and endpoint policies, including any deferred metadata resolution. |
| `token-exchange-remote-work` | Per-tenant admission limits shared by RFC 8693 Token Exchange operations for all outbound targets. |
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
| `allowed-algorithms` | Allowed JWS algorithms for signed ID Tokens. Defaults to `[ "RS256" ]`. `none` and `HS*` algorithms are rejected. Selected RSA keys require at least 2048-bit moduli. An omitted JWK `alg` remains unconstrained; a declared value must match. |
| `allowed-encryption-algorithms` | Allowed JWE `alg` algorithms for encrypted ID Tokens. Defaults to `[ "RSA-OAEP-256", "RSA-OAEP" ]`, the supported values. Unsupported values, including `RSA1_5`, are rejected. |
| `allowed-content-encryption-algorithms` | Allowed JWE `enc` algorithms for encrypted ID Tokens. Defaults to `[ "A256GCM", "A128CBC-HS256" ]`. |
| `trusted-additional-audiences` | Additional ID Token `aud` values trusted by this client. The configured `client-id` is always required and should not be listed here. Defaults to an empty list. |
| `clock-skew` | Allowed ID Token time validation clock skew. Defaults to `PT1M`. |
| `decryption-jwk` | Private JWK Set resource configuration for ID Token decryption. Supports path, classpath, and supplied content; URI sources are rejected before opening. RSA moduli must contain at least 2048 bits; a declared JWK `alg` must match the JWE header. |
| `encryption-required` | Whether signed-only ID Tokens are rejected. Defaults to `false`. An enabled tenant must configure `decryption-jwk` when this is `true`; otherwise configuration fails. |

Client assertion options:

| Key | Description |
| --- | --- |
| `algorithm` | JWS `alg` header used to sign the client assertion. Defaults to `HS256` for `CLIENT_SECRET_JWT`. For `PRIVATE_KEY_JWT`, a configured value may select a compatible algorithm when JWK `alg` is omitted; a declared JWK `alg` must match exactly. |
| `key-id` | JWS `kid` header. For `PRIVATE_KEY_JWT`, selects the signing key and is required when `jwk` contains multiple keys. For `CLIENT_SECRET_JWT`, written to the assertion header when configured. |
| `jwk` | Private JWK Set resource configuration. Supports path, classpath, and supplied content; URI sources are rejected before opening. Each consumer loads its own resource and retains its parsed key. RSA moduli must contain at least 2048 bits. JWK `alg` is optional. |
| `lifetime` | Assertion lifetime used to calculate `exp`. Defaults to `PT1M`. |

JWK Set options:

| Key | Description |
| --- | --- |
| `unknown-key-id-refresh-enabled` | Whether an unknown JWT `kid` triggers a JWK Set reload attempt. Defaults to `true`. |
| `unknown-key-id-refresh-interval` | Global minimum interval between reload attempts triggered by any unknown `kid`. Defaults to `PT5M`. |
| `refresh-interval` | Optional lazy JWK Set refresh interval. If configured, cached keys older than this interval are refreshed during token validation. No background thread is started. |
| `failure-retry-interval` | Minimum interval before retrying a failed JWK Set load. Defaults to `PT10S`; concurrent callers observe the same failure during the interval. |
| `stale-on-error` | Whether cached keys may still be used when a reload fails. Defaults to `true`; initial loading still fails when no cached keys exist. |
| `max-queued` | Maximum callers waiting for JWK Set coordination, independently per key-set manager. Defaults to `128`; zero fails fast while busy. Cache hits bypass admission. |
| `admission-timeout` | Maximum wait for admitted JWK Set coordination callers. Defaults to `PT1S`; zero fails fast while busy. Waiting is interruptible and does not cancel the shared load or replace WebClient I/O timeouts. |

Authorization Code Flow options:

| Key | Description |
| --- | --- |
| `enabled` | Whether Authorization Code Flow initiation is enabled when `authorization-code` is configured. Defaults to `true`. |
| `redirection-endpoint-uri` | Client callback URI sent as `redirect_uri`. Defaults to local path `/oidc/callback`, resolved from the incoming request origin. May also be configured as an absolute URI. |
| `scopes` | Authentication Request scopes. Defaults to `[ "openid" ]`, must contain `openid`, and each value must be one RFC 6749 `scope-token`. |
| `prompts` | Optional Authentication Request prompt values. Values are serialized into the `prompt` parameter as a space-delimited list. `none` cannot be combined with any other value. When `scopes` contains `offline_access`, the provider sends `prompt=consent` when prompts are omitted and appends `consent` to configured prompts that do not already contain it. |
| `resources` | Optional RFC 8707 resource indicators for Authorization Code Flow. Values are emitted only when configured, as repeated `resource` parameters on the Authentication Request, authorization-code token request, and refresh-token requests. Each value must be an absolute URI without a fragment; blanks, padded values, and duplicates are rejected. |
| `pushed-authorization-requests` | RFC 9126 Pushed Authorization Request mode: `DISABLED`, `AUTO`, or `REQUIRED`. Defaults to `AUTO`. `AUTO` uses PAR when a PAR endpoint is configured or already-loaded metadata advertises it, and requires PAR when loaded metadata requires it. `REQUIRED` may load metadata to discover the endpoint. |
| `request-object` | RFC 9101 signed or signed-then-encrypted Request Object configuration. Defaults to `AUTO` mode without signing key material, so no Request Object is sent unless `signing-jwk` is configured or loaded metadata requires signed Request Objects. |
| `refresh-remote-work` | Per-tenant admission limits for local-session refresh. One leader refreshes a source session and admitted same-session followers share its result. |
| `refresh-result-retention` | Grace interval for reusing a completed outcome with the exact source session. Defaults to `PT5S`; must be between `PT1S` and `PT1M`, inclusive. |
| `refresh-result-cache-capacity` | Strict maximum number of completed source-session outcomes retained during the grace interval. Defaults to `1024` and must be positive. Active operations are tracked separately. |
| `pkce-required` | Whether PKCE parameters are sent. Defaults to `true`. Public clients using `token-endpoint-auth-method: NONE` cannot disable PKCE. |
| `pkce-method` | PKCE code challenge method: `S256` or `plain`. Defaults to `S256`. Public clients using `token-endpoint-auth-method: NONE` must use `S256`; `plain` is for legacy confidential-client compatibility only. |

Request Object options:

| Key | Description |
| --- | --- |
| `mode` | Request Object mode: `DISABLED`, `AUTO`, or `REQUIRED`. Defaults to `AUTO`. `AUTO` signs when `signing-jwk` is configured and requires signing when loaded metadata has `require_signed_request_object: true`. |
| `signing-algorithm` | JWS `alg` header used to sign the Request Object. A configured value may select a compatible algorithm when JWK `alg` is omitted; a declared JWK `alg` must match exactly. When both are omitted, a compatible key-type default is used. |
| `signing-key-id` | JWS `kid` header and signing JWK selector. Required when `signing-jwk` contains more than one key. |
| `signing-jwk` | Private JWK Set resource configuration used to sign Request Objects. This is local client key material registered with the Authorization Server; it is not the OP `jwks-uri`. URI resources are rejected before resource creation. RSA moduli must contain at least 2048 bits. |
| `encryption-algorithm` | Optional JWE `alg` value enabling signed-then-encrypted Request Objects. Supported values are `RSA-OAEP-256` and `RSA-OAEP`. The public encryption key is loaded from the OP `jwks_uri` and must have a modulus of at least 2048 bits. |
| `content-encryption-algorithm` | Optional JWE `enc` value. Requires `encryption-algorithm` and defaults to `A128CBC-HS256` when omitted. |
| `encryption-key-id` | Optional exact OP encryption JWK selector. When omitted, the first eligible OP key is selected. Requires `encryption-algorithm`. |
| `lifetime` | Request Object lifetime used to calculate `exp`. Defaults to `PT1M`. |

Endpoint policy options:

| Key | Description |
| --- | --- |
| `accepted-credentials` | Accepted endpoint credentials: `bearer-token` and/or `authentication-cookie`. If omitted, inferred from enabled `protected-resource` and `authorization-code`. |
| `authentication-failure-response` | Response when no accepted credential authenticates the request: `unauthorized` or `authorization-code-redirect`. If omitted, authentication-cookie-only endpoints redirect and all other endpoint policies return `401`. |

Subject mapping options:

| Key | Description |
| --- | --- |
| `principal-id-claim-paths` | Dotted claim paths tried in order for Protected Resource JWT and introspection identities. Defaults to `[ "sub" ]`. IDs are qualified by authority and selected claim path. Browser authentication always uses the ID Token issuer and subject. |
| `principal-id-namespace` | Stable, application-controlled identity namespace required for introspection without a configured/discovered issuer. Does not create or override an `iss` claim; ignored when an issuer is known. Not used for JWT or browser identities. |
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
| `signing-algorithm` | Exact `userinfo_signed_response_alg` registered for this client. `none` and `HS*` are rejected. Selected RSA keys require at least 2048-bit moduli; an omitted JWK `alg` remains unconstrained. |
| `encryption-algorithm` | Exact `userinfo_encrypted_response_alg` registered for this client. |
| `content-encryption-algorithm` | Exact `userinfo_encrypted_response_enc`. Defaults to `A128CBC-HS256` when encryption is configured. |
| `decryption-jwk` | Confidential private RP JWK Set resource configuration for UserInfo decryption. Supports path, classpath, and supplied content; URI sources are rejected before opening. Required with `encryption-algorithm`; RSA moduli must contain at least 2048 bits and a declared JWK `alg` must match. |
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
| `verification-jwk` | Optional local JWK Set resource configuration used exclusively for JWT access-token verification. Required for HMAC algorithms. URI sources are rejected; tenant JWK refresh policies apply. No fallback to provider JWKS. |
| `allowed-algorithms` | Allowed JWS algorithms for JWT access tokens. Defaults to `[ "RS256" ]`. The `none` algorithm is rejected; HMAC algorithms require `verification-jwk`. Selected RSA keys require at least 2048-bit moduli. An omitted JWK `alg` remains unconstrained; a declared value must match. |
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
| `client-secret` | Client secret used to authenticate this protected resource to the Introspection Endpoint. Defaults to the tenant `client-secret`. For `CLIENT_SECRET_JWT`, its UTF-8 representation must meet the selected 32/48/64-octet HMAC minimum. |
| `client-assertion` | Client assertion signing configuration for Introspection Endpoint `CLIENT_SECRET_JWT` and `PRIVATE_KEY_JWT`. Defaults to the tenant `client-assertion`. |
| `remote-work` | Per-tenant admission limits for Introspection Endpoint requests. |

Remote work options are used by `authorization-code.refresh-remote-work`,
`protected-resource.token-validation.introspection.remote-work`, `client-credentials-remote-work`, and
`token-exchange-remote-work`:

| Key | Description |
| --- | --- |
| `max-concurrent` | Maximum remote HTTP operations running concurrently. Defaults to `32` and must be positive. |
| `max-queued` | Hard maximum number of callers waiting for an active permit or an existing same-key operation. Queue capacity is reserved without waiting. Defaults to `128`, must not be negative, and `0` provides fail-fast overload behavior. |
| `admission-timeout` | Time an admitted new operation may wait for an active permit. Defaults to `PT1S`, must not be negative, and `PT0S` provides fail-fast active admission. Once admitted as a same-key follower, the caller waits interruptibly for that operation to complete. |
