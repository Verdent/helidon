# OIDC Next: client-side standards support

Status checked: **2026-10-23**. This inventory describes only
`security/providers/oidc-next`: Helidon as an OpenID Connect relying party (RP),
an OAuth client, and a security provider validating requests to protected resources.
It does **not** describe the legacy OIDC provider or claim that Helidon is an
OpenID Provider / OAuth authorization server. Issuing tokens, authenticating users
at the OP, advertising server metadata, and running registration endpoints are
outside this module's role.

The editions linked below are the latest **published final specifications / RFCs**
checked against the [OpenID Foundation specification catalogue](https://openid.net/developers/specs/)
and the [IETF OAuth working group's RFC list](https://datatracker.ietf.org/wg/oauth/documents/)
on the date above. A newer *draft* is not silently treated as a published standard.
"Supported" means the indicated **client-side behavior**, not every optional
feature of a whole specification or formal certification. "Partial" means a
specific subset works but important related behavior does not; "not supported"
identifies an absent client feature and explains why. Identity-provider-dependent
capabilities also require the OP to advertise or implement them and often need
explicit tenant settings. Generic JWT/JWS/JWE/JWK and HTTP/TLS standards are
underlying dependencies, not separate OIDC/OAuth feature claims here.

Implementation references name files under `src/main/java/io/helidon/security/providers/oidc/next/`
unless another path is stated. The real-provider contract tests are in
`tests/integration/security/oidc-next-providers`; synthetic flow tests are in
`tests/integration/security/oidc-next`. References to tests describe coverage,
not conformance certification.

## At a glance

- **Ordinary path:** OIDC Authorization Code RP with OP discovery, PKCE S256,
  issuer/nonce/state checks and signed ID Token validation; outbound Bearer
  usage and protected-resource JWT or opaque-token validation.
- **Optional client capabilities:** client assertions, encrypted ID Tokens and
  UserInfo, PAR, JAR-by-value, resource indicators, mTLS/certificate-bound
  inbound tokens, outbound Client Credentials/Token Exchange, RP-initiated
  logout and configurable Back-Channel Logout.
- **Important omissions:** no end-to-end step-up assurance (`max_age` / `acr`
  result checks), DPoP, JARM, form POST callbacks, JWT introspection
  responses, OAuth token revocation, automatic client registration, or
  full FAPI/identity-assurance profile. A parameter that can be forwarded is
  not necessarily a capability that the RP independently enforces.

## OpenID Connect family

### OpenID Connect Core 1.0, incorporating errata set 2 (15 December 2023)

[Published specification](https://openid.net/specs/openid-connect-core-1_0.html)

- **Supported (authorization-code RP):** browser redirect with `response_type=code`,
  `openid` scope, state and nonce binding, code redemption over the token endpoint,
  signed ID Token validation (issuer, audience/authorized party, time, nonce,
  subject and signature), optional encrypted ID Tokens with configured decryption
  keys, refresh with ID Token continuity checks, and JSON, signed-JWT or
  configured encrypted-JWT UserInfo with matching `sub`. Configured
  `offline_access` automatically adds `prompt=consent`. Confidential and public
  client modes are supported.
  See `OidcAuthenticationRequestFactory`, `OidcAuthorizationResponseProcessor`,
  `OidcIdTokenValidator`, `OidcIdTokenDecryptor`, `OidcRefreshTokenManager`,
  `OidcUserInfoSupport` and `OidcUserInfoJwtProcessor`.
- **Optional request parameters, with an important limit:** scopes and
  prompts can be configured, and a tenant adapter may add validated
  parameters such as `login_hint`, `acr_values`, `max_age` and `claims`.
  Sending a request for `max_age`, `auth_time`
  or a particular `acr` does **not** make OIDC Next enforce the resulting
  `auth_time` freshness or `acr` value in the ID Token. Core recommends such RP
  checks when these values are requested. Treat step-up / reauthentication
  assurance as **not supported** by this module at present; applications must
  not infer that a forwarded parameter was independently verified. See
  `OidcAuthorizationParametersDecorator` and `OidcIdTokenValidator`.
- **Not supported:** implicit and hybrid response types (`id_token`, `token`,
  `code id_token`, etc.), fragment callbacks and Self-Issued OP. The implemented
  RP flow requires `code` and a query-mode callback; it does not process ID or
  access tokens from the front channel. This is a deliberately narrower,
  security-oriented RP flow, not a claim that Core removed these legacy modes.
  Unsigned (`alg=none`) ID Tokens are also rejected: the RP requires a verifiable
  signed token even though Core allows narrower unsigned-code-flow cases.
  See `OidcAuthenticationRequestFactory`, `OidcFeature` and `OidcIdTokenValidator`.

### OpenID Connect Discovery 1.0, incorporating errata set 2 (15 December 2023)

[Published specification](https://openid.net/specs/openid-connect-discovery-1_0.html)

- **Supported (provider configuration discovery):** fetch OP metadata from the
  configured issuer's `/.well-known/openid-configuration` URL or an explicitly
  configured well-known URL; require the returned issuer to match the configured
  issuer, validate HTTPS endpoints by default, and use advertised endpoints, algorithms,
  capabilities and JWK Set URI with explicit overrides where configured. See
  `OidcProviderMetadata`, `OidcEndpointUris` and `OidcJwkSetManager`; tests
  `OidcWellKnownMetadataLoadingTest` in the module's unit tests and
  `KeycloakDiscoveryIT` in `tests/integration/security/oidc-next-keycloak`.
- **Not supported (issuer discovery from an end-user identifier):** no WebFinger
  account/email/URL lookup or automatic selection of an unknown OP. Tenants are
  configured and selected explicitly; resolving arbitrary user-input issuers is
  a separate discovery and trust-management feature, not necessary for this RP
  model. See `OidcTenantResolver` and `OidcProviderMetadata`.

### OpenID Connect Dynamic Client Registration 1.0, incorporating errata set 2

[Published specification](https://openid.net/specs/openid-connect-registration-1_0.html)

- **Not supported (RP registration client):** no registration request, client
  configuration management, or automatic registration-metadata/secret lifecycle.
  Client IDs, secrets, redirect and logout URIs, signing keys and supported
  algorithms are provisioned with the OP and configured per tenant. Discovery of
  an OP's `registration_endpoint` does not register the RP. This is an optional
  provisioning protocol, not a prerequisite for pre-registered OIDC clients.
  See `OidcTenantConfigBlueprint`, `OidcClientAssertionConfigBlueprint`
  and `OidcProviderMetadata`.

### OpenID Connect RP-Initiated Logout 1.0 (12 September 2022)

[Published specification](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)

- **Supported when enabled:** local POST logout clears the RP browser session;
  if an OP end-session endpoint is available, the RP redirects the browser to it
  with the configured `id_token_hint`, optional `client_id`, and an allow-listed
  `post_logout_redirect_uri`. A caller-supplied `state` can be forwarded. The
  post-logout destination must be registered with the OP separately. See
  `OidcLogoutHandler`, `OidcEndSessionConfigBlueprint` and `OidcLogoutFlowIT`.
- **Boundary:** this is *RP-to-OP* logout, not reception of an OP-initiated
  front-channel notification. OIDC Next does not create a separate automatic
  post-logout callback handler that validates returned `state`: if the
  application relies on that response, it must handle it itself. Logout can
  clear the RP session even when OP end-session support is absent.

### OpenID Connect Back-Channel Logout 1.0, incorporating errata set 1

[Published specification](https://openid.net/specs/openid-connect-backchannel-1_0.html)

The OpenID Foundation catalogue labels this entry “Second Errata”, but the
linked **published specification itself** says “incorporating errata set 1”;
this inventory follows the actual final document, not the catalogue label.

- **Supported when configured (OP-to-RP):** a per-tenant POST endpoint accepts
  a form-encoded signed, optionally encrypted Logout Token, checks the OP
  signature and issuer, audience, times, `jti`, `events`, absence of `nonce`,
  and `sub` and/or `sid`, and invalidates matching RP browser sessions.
  Session-ID-required mode and replay handling are available. See
  `OidcBackChannelLogoutHandler`, `OidcLogoutTokenValidator`,
  `OidcBackChannelSessionSupport` and `KeycloakOidcIT`.
- **Deployment limit / why it matters:** the default revocation store is
  process-local and nonpersistent. On restart it forgets logout events (and
  previously issued unexpired RP cookies can still be used); across replicas
  one instance cannot see another's events. A shared implementation of
  `spi.OidcBackChannelLogoutStore` is required for distributed or durable
  enforcement. This logout invalidates Helidon's RP sessions; it does not
  revoke access tokens at the OP. See `OidcInMemoryLogoutStore` and
  `OidcBackChannelLogoutConfigBlueprint`.

### OpenID Connect Front-Channel Logout 1.0 (12 September 2022)

[Published specification](https://openid.net/specs/openid-connect-frontchannel-1_0.html)

- **Not supported (OP-to-RP):** no front-channel logout GET endpoint or
  registration metadata. The local POST logout and Back-Channel Logout receiver
  are different protocols and cannot stand in for the OP's user-agent/iframe
  notification. Implementing this optional mode would require browser-facing
  notification handling and session binding; it has not been added. See
  `OidcFeature` (registered routes).

### OpenID Connect Session Management 1.0 (12 September 2022)

[Published specification](https://openid.net/specs/openid-connect-session-1_0.html)

- **Not supported:** no `session_state` handling, OP `check_session_iframe`
  polling, or RP iframe. This optional browser session-check protocol needs
  browser-side logic outside the current server-side RP feature; local cookies
  and Back-Channel Logout do not implement that protocol.

### OAuth 2.0 Multiple Response Type Encoding Practices (25 February 2014)

[Published OpenID Foundation specification](https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html)

- **Partial:** the RP uses the single `code` response type and query response
  mode. Multiple response-type combinations, `id_token`-only, `none`, and
  fragment responses are **not supported** because this RP implements only
  Authorization Code Flow. See `OidcAuthenticationRequestFactory` and
  `OidcFeature`.

### OAuth 2.0 Form Post Response Mode (27 April 2015)

[Published OpenID Foundation specification](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html)

- **Not supported:** authorization callbacks register GET and consume URL query
  parameters; there is no form POST callback parser. `form_post` cannot simply
  be enabled with `response_mode`, which the request factory restricts to
  `query` for this flow. See `OidcFeature` and
  `OidcAuthenticationRequestFactory`.

### JWT Secured Authorization Response Mode (JARM), incorporating errata set 1

[Published OpenID Foundation specification (17 August 2025)](https://openid.net/specs/oauth-v2-jarm.html)

- **Not supported:** the callback processes plain `code`, `state` and optional
  `iss` query parameters, not a signed/encrypted JWT Authorization Response
  (`response` / `query.jwt` / `form_post.jwt`). JAR (a *request* JWT) and
  encrypted ID Tokens do not add JARM response validation. See
  `OidcAuthorizationResponseProcessor` and `OidcFeature`.

### OpenID Connect Client-Initiated Backchannel Authentication (CIBA) Core 1.0

[Published specification (1 September 2021)](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html)

- **Not supported:** no backchannel authentication request, CIBA grant,
  polling, ping or push client mode. This is a different, asynchronous RP
  authentication flow from the implemented browser Authorization Code Flow.
  See `OidcAuthorizationCodeConfigBlueprint` and `OidcAuthenticationRequestFactory`.

### Other published RP-oriented OpenID extensions

- [OpenID Federation 1.1](https://openid.net/specs/openid-federation-1_1.html)
  and [OpenID Federation for OpenID Connect 1.1](https://openid.net/specs/openid-federation-connect-1_1.html)
  (both final, May 2026): **not supported**. The RP trusts configured issuers,
  not federation entity statements, trust anchors/chains, metadata policies or
  automatic federation registration. These protocols need a separate trust
  resolver and lifecycle; ordinary multi-tenancy is not federation support.
- [OpenID Connect RP Metadata Choices 1.0](https://openid.net/specs/openid-connect-rp-metadata-choices-1_0-final.html)
  (final, March 2026): **not supported**. No Dynamic Client Registration or
  federation client metadata negotiation; per-tenant settings specify one
  selected client configuration directly.
- [Initiating User Registration via OpenID Connect 1.0](https://openid.net/specs/openid-connect-prompt-create-1_0.html)
  (final, December 2022): **wire-level support only**. `prompt=create` can be
  requested using configurable `prompts`; the OP must implement registration.
  There is no dedicated registration UI or policy in Helidon, since user
  creation belongs to the OP. See `OidcAuthorizationCodeConfigBlueprint`.
- [OpenID Connect Core Error Code `unmet_authentication_requirements`](https://openid.net/specs/openid-connect-unmet-authentication-requirements-1_0.html)
  (final): **generic error handling only**. A correctly state-bound OP error is
  rejected as an authorization error, but there is no special retry or
  step-up UX for this value. The RP does not automatically enforce requested
  `acr` assurance (see Core above). See `OidcAuthorizationResponseProcessor`.
- [OpenID Connect Extended Authentication Profile ACR Values 1.0](https://openid.net/specs/openid-connect-eap-acr-values-1_0.html)
  (final, June 2025): **not supported as an assurance profile**. The RP can
  forward `acr_values` but does not verify that the ID Token's `acr` satisfies
  the requested phishing-resistant level. Do not use a forwarded value alone
  to authorize sensitive operations. See `OidcAuthorizationParametersDecorator`
  and `OidcIdTokenValidator`.
- [OpenID Connect for Identity Assurance 1.0, errata set 1](https://openid.net/specs/openid-connect-4-identity-assurance-1_0-errata1.html)
  and its [Schema Definition 1.0, errata set 1](https://openid.net/specs/openid-ida-verified-claims-1_0-errata1.html)
  (final, July 2026): **not supported as verified-identity processing**.
  Requests can carry a custom `claims` JSON object, but OIDC Next does not
  interpret or verify `verified_claims`, evidence, trust frameworks or
  verification constraints. Such claims must be evaluated by an application
  that understands the profile; forwarding a claim does not establish its
  assurance level. See `OidcAuthorizationParametersDecorator` and
  `OidcSubjectMapper`.
- [OpenID Connect for Identity Assurance Claims Registration 1.0](https://openid.net/specs/openid-connect-4-ida-claims-1_0-final.html)
  (final, October 2024): **generic claim handling only**. Validated ID Token
  and UserInfo claims, including additional person-identity claim names,
  are exposed as principal attributes. OIDC Next does not validate special
  identity-data schemas or treat their mere presence as proof of verification;
  that decision needs application policy and the Identity Assurance profile
  above. See `OidcSubjectMapper`.
- [FAPI 2.0 Security Profile](https://openid.net/specs/fapi-security-profile-2_0-final.html)
  (final, February 2025): **no full-profile support or conformance claim**.
  OIDC Next implements individual building blocks such as PKCE, PAR, mTLS
  and certificate-bound tokens, but does not enforce all mandatory FAPI
  client/resource combinations or sender-constrained downstream API calls.
  For example, its token-endpoint `private_key_jwt` assertion uses the token
  endpoint URI as `aud`, while FAPI requires the issuer identifier for this
  client-authentication mode. **DPoP is an alternative to mTLS, not a
  mandatory FAPI requirement**; its absence alone is not the reason for
  the lack of full-profile support. Partial feature overlap must not be
  advertised as FAPI compliance. See `OidcClientAuthenticationSupport`.
- [FAPI 2.0 Message Signing](https://openid.net/specs/fapi-message-signing-2_0-final.html)
  (final, September 2025): **not supported as a profile**. It adds choices
  for signed authorization responses (JARM), signed introspection results,
  and non-repudiation beyond signing a JAR request/validating an ID Token;
  those end-to-end requirements are not implemented. See JARM above and RFC
  9701 below.
- [OpenID Shared Signals Framework 1.0](https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html),
  [CAEP 1.0](https://openid.net/specs/openid-caep-1_0-final.html) and
  [RISC 1.0](https://openid.net/specs/openid-risc-1_0-final.html)
  (all final, August 2025): **not supported as a receiver**. These are
  separate security-event stream and risk/continuous-access protocols;
  OIDC Next does not subscribe to or validate their events. Its Back-Channel
  Logout receiver handles OIDC Logout Tokens only and must not be presented
  as a generic CAEP/RISC signal handler.

## OAuth standards relevant to an RP, OAuth client or protected resource

### RFC 6749 — OAuth 2.0 Authorization Framework (updated by RFC 9700)

[Published RFC](https://www.rfc-editor.org/info/rfc6749)

- **Supported client grant paths:** Authorization Code Flow with confidential or
  public client, token-endpoint code redemption, refresh-token grant for an
  existing browser session (including rotated refresh tokens), and outbound
  Client Credentials Grant. A server-side outbound policy can propagate an
  existing access token instead of requesting one. See `OidcEndpointClient`,
  `OidcRefreshTokenManager`, `OidcClientCredentialsTokenManager`,
  `OidcOutboundOrchestrator`, and `OidcProvider.refresh`.
- **Not supported:** the implicit grant/other front-channel access-token flows
  and the Resource Owner Password Credentials grant. They are inappropriate
  for this server-side RP and discouraged or forbidden, respectively, by the
  current OAuth Security BCP (RFC 9700); the user's credentials must remain
  with the authorization server. OIDC Next is **not** itself an authorization
  server; its token endpoint is an outbound *client* call.

### RFC 6750 — OAuth 2.0 Bearer Token Usage (updated by RFC 9700)

[Published RFC](https://www.rfc-editor.org/info/rfc6750)

- **Supported:** accept `Authorization: Bearer` for protected resources;
  validate bearer credentials using JWT validation or introspection;
  provide Bearer `WWW-Authenticate` challenges for missing/invalid requests;
  use the Authorization header to send tokens to configured outbound targets.
  HTTPS is required by default. See `OidcBearerTokenExtractor`,
  `OidcResponseFactory`, `OidcOutboundOrchestrator`, and
  `OidcTokenTransportConfigBlueprint`.
- **Deliberately off by default:** inbound `access_token` URI query parameter
  transport can be explicitly enabled for compatibility; it leaks into URL
  logs and caches and should normally stay disabled. There is no form-body
  bearer-token extraction. The TLS requirement also has an explicit opt-out
  for controlled deployments: do not weaken it on a public network. No
  automatic HTTP proxy or API endpoint is implied by outbound token support.

### RFC 9700 / BCP 240 — Best Current Practice for OAuth 2.0 Security

[Published BCP (January 2025)](https://www.rfc-editor.org/info/rfc9700)

- **Implemented client-side defenses:** authorization code rather than an
  implicit/token-in-URL flow; PKCE S256 by default, high-entropy state and
  nonce bound to the request, exact callback and issuer checks for multiple
  tenants, HTTPS by default, carefully scoped outbound token attachment,
  and authenticated session cookies. RFC 9207 covers the issuer response
  defense specifically. See `OidcAuthenticationRequestFactory`,
  `OidcAuthorizationResponseProcessor`, `OidcMixUpProtection`,
  `OidcOutboundOrchestrator`, and `OidcCookieStateHandler`.
- **Configuration can intentionally weaken the profile:** authenticated
  confidential clients can opt out of PKCE or choose `plain` for legacy OPs;
  transport/endpoint TLS checks have explicit opt-outs. These choices do
  **not** satisfy the default security posture. OAuth Server obligations in
  this BCP (issuing tokens, rotating refresh tokens, exact registration of
  redirect URIs) belong to the OP, not to this client implementation; this
  entry is not a blanket BCP certification.

### RFC 10017 / BCP 212 — OAuth 2.0 for Browser-Based Applications

[Published BCP (August 2026)](https://www.rfc-editor.org/info/rfc10017)

- **Relevant integration guidance, not complete built-in BFF support:** the
  browser in OIDC Next's Authorization Code Flow is *not* a JavaScript OAuth
  client; Helidon handles tokens server-side and uses `Secure`, `HttpOnly`,
  `SameSite=Lax` session cookies. A host application can build a Backend for
  Frontend on this basis, but the module does not proxy all browser API calls,
  enforce an application's complete outbound destination allowlist or provide
  application-wide CSRF protection. The BCP recommends `SameSite=Strict` for
  BFF cookies; the module uses `Lax` for redirect-based OIDC flow. Do **not**
  describe OIDC Next alone as a fully conformant BFF or as an SPA OAuth SDK.
  See `OidcCookieStateHandler`, `OidcProvider`, and `OidcOutboundOrchestrator`.

### RFC 7636 — Proof Key for Code Exchange (PKCE)

[Published RFC](https://www.rfc-editor.org/info/rfc7636)

- **Supported by default:** per-request 256-bit random `code_verifier`, S256
  challenge in the authorization request and verifier in the code redemption;
  public clients cannot disable PKCE or select `plain`. Provider metadata is
  checked for S256, or an administrator can explicitly assure S256 support
  when the OP omits the metadata field. See
  `OidcAuthenticationRequestFactory`, `OidcTenantContextFactory`, and
  `OidcAuthorizationCodeConfigBlueprint`.
- **Explicit nonconformant compatibility switches:** an authenticated
  confidential client can disable PKCE, or explicitly select `plain` for an
  older server. `plain` transmits the verifier in the authorization request;
  an S256-capable client using it does **not** meet RFC 7636 section 4.2's
  requirement to use S256. Both choices sacrifice protections and are not
  claims of PKCE conformance for those configurations.

### RFC 9207 — OAuth 2.0 Authorization Server Issuer Identification

[Published RFC](https://www.rfc-editor.org/info/rfc9207)

- **Supported:** when `iss` appears in an authorization response, compare it
  exactly to the issuer recorded with the protected authentication request
  *before* sending a code to the token endpoint. Require `iss` if the OP
  advertises support or configured tenants with distinct authorization
  servers can share the same callback. When safe distinct callback URIs are
  available, RFC 9700 also permits that anti-mix-up defense. The tenant is
  chosen using protected request state, not an untrusted callback hint. See
  `OidcAuthorizationResponseProcessor` and `OidcMixUpProtection`.
- **Deployment requirement:** an OP without issuer response support cannot
  simply share an ambiguous callback with another issuer; use separate
  redirect endpoints or an OP that supplies `iss`.

### RFC 9126 — OAuth 2.0 Pushed Authorization Requests (PAR)

[Published RFC](https://www.rfc-editor.org/info/rfc9126)

- **Supported:** send authorization parameters directly to the discovered
  or configured HTTPS PAR endpoint, authenticate as configured, require a
  successful creation response, then redirect with the one-time server-issued
  `request_uri` and `client_id`. A Request Object (JAR) can be pushed as the
  `request` parameter. The `AUTO` mode uses PAR when available or required
  by OP metadata; `REQUIRED` insists on it. See
  `OidcAuthenticationRequestFactory`, `OidcEndpointClient`, and
  `OidcPushedAuthorizationResponse`.
- **Boundary:** OIDC Next consumes the OP-issued PAR URI; it does not itself
  host a request-object URL. Explicit `DISABLED` is a compatibility setting
  and cannot be used with a provider that requires PAR.

### RFC 9101 — JWT-Secured Authorization Request (JAR)

[Published RFC](https://www.rfc-editor.org/info/rfc9101)

- **Supported by value:** when a signing key is configured or the OP requires
  signed requests, create a signed Request Object carrying authorization
  parameters, with optional nested encryption to the OP's advertised JWK;
  send it as `request` in a normal authorization redirect or with PAR. The
  client signing key must be registered with the OP. See
  `OidcRequestObjectProcessor`, `OidcRequestObjectConfigBlueprint`, and
  `OidcAuthenticationRequestFactory`.
- **Not supported:** RP-hosted JAR `request_uri` by reference (distinct from
  an OP-issued PAR `request_uri`); no client-hosted fetch endpoint or key
  publishing/registration lifecycle is provided. Signing is needed only if
  the OP requires it or this tenant elects it. JAR secures the **request**, not
  the authorization **response** (JARM, separately documented above).

### RFC 8707 — Resource Indicators for OAuth 2.0

[Published RFC](https://www.rfc-editor.org/info/rfc8707)

- **Supported as a client:** configured resource URIs are sent as repeated
  `resource` parameters with the authorization request, code redemption,
  refresh and outbound Client Credentials Grant. Resource values must be
  absolute URIs without fragments; outbound Token Exchange also supports
  a resource target. The OP ultimately decides whether and how to restrict
  the issued token's audience. See `OidcAuthenticationRequestFactory`,
  `OidcEndpointClient`, `OidcResourceIndicators`, and
  `OidcOutboundPolicyConfigBlueprint`.
- **Boundary:** providing a resource indicator is **not** evidence that the
  returned token is restricted to it. Configure and enforce appropriate
  audience checks when validating inbound tokens or using outbound ones.

### RFC 9396 — OAuth 2.0 Rich Authorization Requests (RAR)

[Published RFC](https://www.rfc-editor.org/info/rfc9396)

- **Partial (parameter transport):** a tenant adapter can add a typed
  `authorization_details` JSON array to an authorization request, including
  JAR and PAR transport; the core checks that entries are objects with a
  nonblank `type`. See `OidcAuthorizationParametersDecorator` and
  `OidcAuthenticationRequestFactory`.
- **Not supported as a full RAR workflow:** there is no public per-tenant
  policy/type registry, OP-specific authorization-detail semantics, or
  verification that granted details in issued tokens meet what the app
  requested. Treat this as an extensibility hook, not assurance that the
  requested fine-grained permissions were granted. The application and OP
  must agree on each detail type and validate the result separately.

### RFC 8414 — OAuth 2.0 Authorization Server Metadata

[Published RFC](https://www.rfc-editor.org/info/rfc8414)

- **Supported for configured issuers:** explicitly supply an RFC 8414
  `/.well-known/oauth-authorization-server` URL and verify its relationship
  to the issuer and the returned issuer value, or use an OIDC Discovery URL.
  Consume relevant endpoints, grant and authentication methods, PKCE
  capabilities, mTLS aliases, PAR and issuer-response flags where advertised.
  See `OidcEndpointUris`, `OidcProviderMetadataLoader`, and
  `OidcProviderMetadata`.
- **Limit:** automatic well-known URL construction from an issuer chooses
  *OIDC* `/.well-known/openid-configuration`; an OAuth-only metadata URL
  must be configured explicitly. Configuring OAuth server metadata does not
  make an OAuth-only server an OP for OIDC browser login: ID Token and OP
  keys/claims are still necessary for that flow.

### RFCs 7521 and 7523 — Assertion Framework and JWT Client Authentication

[RFC 7521](https://www.rfc-editor.org/info/rfc7521) ·
[RFC 7523](https://www.rfc-editor.org/info/rfc7523)

- **Supported client-authentication subset:** `private_key_jwt` and
  `client_secret_jwt` signed assertions with bounded expiration, issuer and
  subject bound to `client_id`, audience, and unique `jti`, for the token,
  PAR and configured introspection endpoints. Also available: standard
  `client_secret_basic`, `client_secret_post`, mTLS and `none` where
  appropriate. See `OidcClientAuthenticationSupport` and
  `OidcClientAssertionConfigBlueprint`.
- **Not supported (assertion authorization grants):** a JWT bearer token
  cannot be submitted as `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`
  to obtain tokens. That is distinct from using a JWT to **authenticate this
  client** while exercising a supported grant. Nor is the SAML assertion
  client/grant profile ([RFC 7522](https://www.rfc-editor.org/info/rfc7522))
  implemented: the provider does not create or manage SAML assertions.

### RFC 8705 — OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Tokens

[Published RFC](https://www.rfc-editor.org/info/rfc8705)

- **Supported when configured:** `tls_client_auth` and
  `self_signed_tls_client_auth` with a client certificate provided through
  the tenant's WebClient TLS configuration; include `client_id` and prefer
  advertised `mtls_endpoint_aliases` for applicable OP endpoints. As a
  protected resource, optionally require or conditionally validate an access
  token's `cnf.x5t#S256` against the **verified peer certificate** for JWT
  access tokens and introspection responses. A bound token is not accepted
  as an ordinary unbound Bearer token. See `OidcClientAuthenticationSupport`,
  `OidcEndpointClient`, `OidcIntrospectionAccessTokenValidator`, and
  `OidcCertificateBoundAccessTokenSupport`.
- **Deployment boundary:** certificate-bound inbound validation is disabled
  by default and must have a trustworthy, TLS-layer peer certificate; a
  forwarded certificate header is not proof of possession. The module's
  outbound token propagation sets a Bearer header but does **not** provision
  the application's downstream connection with the token's client
  certificate; applications using mTLS-bound outbound tokens must supply
  that connection themselves.

### RFC 7662 — OAuth 2.0 Token Introspection

[Published RFC](https://www.rfc-editor.org/info/rfc7662)

- **Supported as a protected resource:** validate opaque (or other selected)
  access tokens by authenticated POST (HTTPS by default) to the configured
  or discovered OP introspection endpoint, with the `access_token` type hint;
  process a JSON `active` response, reject inactive tokens, verify configured audience and
  any present issuer/time/confirmation claims, then map a principal. HTTP
  errors and malformed responses are treated as **unavailable**, not as
  evidence that the token is inactive. Introspection authentication can use
  its own credentials and client-auth method. See
  `OidcIntrospectionAccessTokenValidator`, `OidcValidatedIntrospection`,
  and `OidcIntrospectionConfigBlueprint`.
- **Boundary:** an active response only authenticates the token for the
  configured protected resource; the application still applies scope and
  authorization rules to the operation. Do not confuse live token
  introspection with Helidon's local logout store or assume it works when
  the OP's endpoint is unreachable.

### RFC 9701 — JWT Response for OAuth Token Introspection

[Published RFC (January 2025)](https://www.rfc-editor.org/info/rfc9701)

- **Not supported:** RFC 7662 handling specifically requests and accepts
  `application/json` with a plain JSON object. There is no negotiation,
  signature/decryption verification or `token-introspection+jwt` response
  processing for the distinct RFC 9701 format. A signed JWT access token
  validated locally under RFC 9068 is **not** the same thing as an RFC 9701
  *introspection response*. Use an OP's ordinary JSON introspection endpoint
  or add an explicit signed-response validator before relying on this profile.
  See `OidcIntrospectionAccessTokenValidator`.

### RFC 9068 — JWT Profile for OAuth 2.0 Access Tokens

[Published RFC](https://www.rfc-editor.org/info/rfc9068)

- **Supported by default when JWT validation is selected:** require a signed
  JWT with `at+jwt` / `application/at+jwt` type and the required access-token
  claims (`iss`, `sub`, `aud`, `exp`, `iat`, `jti`, `client_id`); check the
  trusted signing keys, configured issuer and protected-resource audience,
  times, scope syntax and optional certificate binding. Non-RFC-9068 token
  layouts can instead select the `CUSTOM` profile, with an explicit token
  discriminator so an ID Token is not accepted as an access token. See
  `OidcJwtAccessTokenValidator`, `OidcJwtAccessTokenConfigBlueprint`, and
  `OidcTokenValidationConfigBlueprint`.
- **Important configuration limit:** the RFC 9068 profile **requires**
  audience verification. `token-validation.audience-validation-enabled=false`
  is an explicit compatibility/testing opt-out; with it, do not claim RFC
  9068-conformant resource-server validation. Custom token layouts likewise
  need a trusted issuer, appropriate signature keys and resource policy.

### RFC 7009 — OAuth 2.0 Token Revocation

[Published RFC](https://www.rfc-editor.org/info/rfc7009)

- **Not supported as an OAuth client:** no outbound revocation endpoint call
  for access or refresh tokens. RP-initiated logout clears the local browser
  session (and can redirect the browser for OP logout); Back-Channel Logout
  invalidates matching RP sessions. Neither is an RFC 7009 request to revoke
  a token at the OP. Add an explicit OP token-revocation call in an
  application if its policy requires it. Introspection can observe a token
  that the OP has already marked inactive; offline JWT validation cannot
  learn OP-side revocation without an additional mechanism. See
  `OidcLogoutHandler`, `OidcEndpointClient`, and
  `OidcIntrospectionAccessTokenValidator`.

### RFC 8693 — OAuth 2.0 Token Exchange

[Published RFC](https://www.rfc-editor.org/info/rfc8693)

- **Supported outbound subset:** for a selected tenant and outbound target,
  exchange a `TokenCredential` expected to contain the authenticated request
  subject's **access token** for a new **Bearer access token**. A confidential
  client authenticates at the token endpoint; configured scope, resource and
  audience may target the recipient.
  The exchange response must declare the expected issued token type and
  Bearer usage. See `OidcOutboundOrchestrator`, `OidcEndpointClient`,
  `OidcTokenExchangeTokenManager`, and `OidcTokenExchangeResponse`.
- **Not supported:** exchanging ID/SAML/refresh tokens, requesting other
  issued-token types, using an `actor_token` for delegation, or a general
  security-token-service API. These are distinct variants and do not follow
  merely from the implemented access-token-to-access-token outbound policy.

### RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession (DPoP)

[Published RFC](https://www.rfc-editor.org/info/rfc9449)

- **Not supported (client or protected resource):** no DPoP key/proof
  generation for token and resource requests, and no DPoP proof validation,
  request/URI/HTTP-method binding or DPoP nonce/replay tracking on inbound
  requests. An incoming token with `cnf.jkt` is explicitly **rejected as a
  Bearer token**, rather than silently accepted without a proof. This profile
  requires end-to-end sender-constrained transport; it cannot be enabled by
  changing just a token-type string. See
  `OidcCertificateBoundAccessTokenSupport` and `OidcBearerTokenExtractor`.

### RFC 9728 — OAuth 2.0 Protected Resource Metadata

[Published RFC (April 2025)](https://www.rfc-editor.org/info/rfc9728)

- **Not supported as a built-in protected-resource feature:** OIDC Next does
  not publish a `/.well-known/oauth-protected-resource` document or a
  `resource_metadata` link in a Bearer challenge. Nor does outbound policy
  automatically fetch this metadata to pick an authorization server. The
  protected application's resource identifier and expected token audience
  are normally configured (audience validation is enabled by default); an
  application may publish its own endpoint if clients need dynamic resource
  discovery. Do not confuse this resource-server metadata with RFC 8414
  *authorization-server* discovery. See
  `OidcFeature`, `OidcResponseFactory`, and `OidcTokenValidationConfigBlueprint`.

### RFC 9470 — OAuth 2.0 Step Up Authentication Challenge Protocol

[Published RFC](https://www.rfc-editor.org/info/rfc9470)

- **Not supported end-to-end:** no protected-resource
  `insufficient_user_authentication` Bearer challenge with specified `acr_values`
  / `max_age`, automatic client step-up retry, or verification of the stronger
  ID Token authentication evidence. A tenant adapter can forward OIDC
  `acr_values` / `max_age` in an authorization request, but this is **not**
  RFC 9470 challenge processing or proof that an authentication level was met.
  Add both response validation and an application-specific reauthentication
  policy before using this protocol for sensitive operations. See
  `OidcResponseFactory`, `OidcAuthorizationParametersDecorator`, and
  `OidcIdTokenValidator`.

### Other client-facing RFCs not implemented by this module

- [RFC 7591](https://www.rfc-editor.org/info/rfc7591) (OAuth Dynamic Client
  Registration) and [RFC 7592](https://www.rfc-editor.org/info/rfc7592)
  (Experimental registration management): **not supported as a client**.
  Provision the client and its credentials with the OP outside Helidon, then
  configure the tenant. No registration POST, read/update/delete API or
  automatic secret/key rollover is included. OIDC Dynamic Client
  Registration is described in the OIDC section above.
- [RFC 8628](https://www.rfc-editor.org/info/rfc8628) (Device Authorization
  Grant): **not supported**. No device-code initiation, polling or approval
  UX; the implemented interactive login is a browser redirect on the same
  RP. The newer [RFC 10027 / BCP 247](https://www.rfc-editor.org/info/rfc10027)
  (August 2026) covers security of this and other *cross-device* flows,
  including CIBA; those flows are not implemented here, so this BCP is
  not a conformance claim for the existing browser code flow.
- [RFC 8252 / BCP 212](https://www.rfc-editor.org/info/rfc8252) (OAuth for
  Native Apps): **not applicable as a native client SDK**. OIDC Next runs on
  the server; it does not control mobile app external-user-agent invocation
  or loopback/custom-scheme redirect URI handling. An application acting as
  a native client needs an appropriate separate native OAuth library.

## Publication and scope notes

- [OAuth 2.1](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/) was
  `draft-ietf-oauth-v2-1-16` in September 2026, **not an RFC** on the date
  of this inventory. Likewise the [JWT assertion audience update](https://datatracker.ietf.org/doc/draft-ietf-oauth-rfc7523bis/)
  (`draft-ietf-oauth-rfc7523bis-11`) was still in the RFC Editor queue. This
  inventory bases normative status on the published RFCs and current RFC
  9700 security BCP, not on draft numbers. The assertion update is relevant
  to future `private_key_jwt` audience interoperability and should be
  revisited when it receives an RFC number.
- The older [RFC 6819 threat model](https://www.rfc-editor.org/info/rfc6819)
  has been updated by RFC 9700; use the current security BCP above for
  client-side mitigations. General-purpose JOSE/JWT, TLS and HTTP RFCs are
  intentionally not counted as separate OIDC Next protocol features.
- Server-only obligations in the linked specs (publishing OP metadata,
  issuing/revoking tokens, hosting client registration and PAR endpoints)
  are **not** unsupported Helidon *client* features. OIDC Next consumes
  these endpoints; an application's own protected-resource metadata endpoint
  is separately identified above as absent. OpenID 2.0 migration, credential
  wallet/issuance and presentation protocols, native/mobile SSO, and
  standalone JOSE/JWT algorithms are outside this OIDC RP/security-provider
  inventory; this is not a claim about other Helidon modules.
