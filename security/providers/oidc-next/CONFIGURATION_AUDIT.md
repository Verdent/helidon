# OIDC Next configuration surface audit

Independent audit started 2026-10-08. This document records each section as it is checked against the implementation,
tests, and applicable specifications. Earlier review documents are not used as input.

For each option: identify the actual runtime consumer; decide whether it controls a distinct security, interoperability,
or operational behavior; check its default and validation; and distinguish an unnecessary public knob from an option
needed for a real deployment. A missing test or uncertain provider need is a question, not evidence to remove a feature.

Summary: all 25 OIDC Next configuration blueprints and the optional IDCS adapter's four configured values have been
examined by subtree. JWKS-01 identified a remote-key cache default that could trust removed keys indefinitely; the
bounded refresh and failure policy is implemented and tested. OUT-01 replaced mutually exclusive outbound strategy
flags with one strategy selection. An internal refresh-cache tuning question needs separate workload evidence.

## Progress

| Section | Status |
| --- | --- |
| Cookie state and session storage | Reviewed below |
| Provider, tenant, and tenant selection | Reviewed below |
| Endpoints, metadata, and JWK Set management | Reviewed below; JWKS-01 addressed and tested |
| Authorization Code, Request Objects, client assertions, and ID Tokens | Reviewed below |
| Protected resource, token validation, introspection, and token transport | Reviewed below |
| Outbound policies and remote-work limits | Reviewed below; OUT-01 addressed |
| UserInfo, logout, and end-session | Reviewed below |
| Subject mapping and endpoint policy | Reviewed below |
| Optional IDCS adapter values | Reviewed below |

## Cookie state and session storage

Source: `src/main/java/io/helidon/security/providers/oidc/next/OidcCookieConfigBlueprint.java`,
`OidcCookieStateHandler.java`, `OidcTenantConfigDecorator.java`, and `OidcProviderConfigDecorator.java`.
Coverage: `OidcCookieStateHandlerTest`, `OidcStateCookiesTest`, `OidcSessionCookiesTest`, and
`OidcProviderConfigTest`. The 2026-10 simplification removed public salt and PBKDF2 iteration settings;
`cookies.password` is now the only key-derivation input configured by the application.

| Option (default) | Actual role and distinct reason to expose it | Decision |
| --- | --- | --- |
| `authentication-request-cookie-name` (`__Host-helidon-oidc-state`) | Names transaction cookies and their numbered chunks. Custom names avoid clashes with app/other tenant cookie namespaces; the provider checks collisions. | Keep |
| `local-authentication-cookie-name` (`__Host-helidon-oidc-auth`) | Names session cookies and numbered chunks; the browser-generation name derives from it. Separate name is needed for multi-tenant/host coexistence and cleanup. | Keep |
| `authentication-request-lifetime` (`PT5M`) | Bounds how long a callback can use protected login state; separate from the browser session lifetime. | Keep |
| `local-authentication-lifetime` (`PT1H`) | Limits protected browser-session validity and the generation cookie lifetime; applications need different session policies. | Keep |
| `max-cookie-size` (`3800`) | Bounds each serialized Set-Cookie including framing and attributes; chunking uses this size as a per-cookie capacity. [RFC 6265 section 6.1](https://www.rfc-editor.org/rfc/rfc6265.html#section-6.1) discusses the 4096-byte per-cookie interoperability floor. | Keep |
| `max-chunks` (`4`) | Separately bounds the number of cookies accepted or emitted per logical state/session, including the reader and cleanup namespace. A byte cap alone does not bound cookie count. | Keep |
| `max-total-size` (`12288`) | Bounds aggregate inbound OIDC Cookie and outgoing Set-Cookie/deletion contribution. This is distinct from per-cookie size and chunk count; server/header budgets vary. | Keep |
| `compression` (`NONE`) | Enables optional GZIP only for large sessions when it helps. Large provider tokens can exceed one cookie; authenticated decompression is bounded by `max-session-size`. | Keep |
| `max-session-size` (`65536`) | Bounds uncompressed authentication/session JSON and authenticated decompression, independent of the smaller encoded header budget. | Keep |
| `password` (absent) | Needed for browser login and protected cookies, but unnecessary for an API-only tenant. It is confidential in the generated config; key derivation retains internal fixed parameters. | Keep |

Finding: no further cookie option is redundant after the password-only simplification. The transport budgets, decompressed
payload bound, lifetimes, and names are separate controls with distinct consumers. Neither the `__Host-` defaults nor
the cookie-framing implementation should be changed merely to reduce the option count. Cookie-bound Authorization
Request state also supports the CSRF binding required by [RFC 9700 section 2.1](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1).

## Provider, tenant, and tenant selection

Sources: `OidcProviderConfigBlueprint`, `OidcTenantConfigOptionsBlueprint`, `OidcTenantResolutionConfigBlueprint`,
`OidcProviderConfigDecorator`, `OidcTenantRuntimeRegistry`, `OidcTenantResolver`, and `OidcFeature`.
Coverage includes configuration, resolution, feature-socket, and concurrent tenant-initialization tests.

| Option(s) | Actual role and reason to expose them | Decision |
| --- | --- | --- |
| `provider-name`, `optional` | Distinct Helidon Security integration choices: name when selecting/combining providers; optional missing-credential outcome for composite authentication. | Keep |
| `socket`, `socket-required` | Select callback/logout WebServer socket. Missing named sockets fail by default; explicit false permits fallback to the default socket. This is the WebServer feature's own contract, not a duplicate outbound endpoint setting. | Keep |
| `tenants`, `default-tenant`, root single-tenant shorthand | Support multi-IDP selection and simple one-tenant configuration. Root tenant options are copied into a tenant before validation; combining root options with an explicit tenant map is rejected. | Keep |
| `issuer-uniqueness-validation-enabled` (true) | Explicit, nonconformant escape hatch for servers that publish the same issuer. Distinct callbacks and pinned endpoints remain necessary. [RFC 9207 section 4](https://www.rfc-editor.org/rfc/rfc9207.html#section-4) requires unique issuer identifiers for distinct authorization servers. Existing intentional compatibility policy; do not enable implicitly. | Keep |
| `tenant-resolution.header-name` | Explicit header-based tenant selection, with duplicate or invalid values rejected instead of silently falling back. | Keep |
| `tenant-resolution.path-segment`, `path-template` | Not equivalent: a segment index selects a tenant from arbitrary longer paths; a path template must match the whole path with literal segments. | Keep both |
| `tenant-resolution.host-template` | DNS-label tenant selection, canonical host parsing, no fallback on malformed or unknown presented host; separate from path/header strategies. | Keep |
| `enabled`, `adapter` | Per-tenant enablement and explicit opt-in to a trusted extension; unselected adapter modules cannot change normal tenants. | Keep |
| `initialization-retry-interval` (10 s), `initialization-max-queued` (128) | Different operational limits: retry backoff after transient metadata failure and bounded followers during a single tenant's lazy initialization. The former also gates deferred outbound metadata resolution. Both are enforced in the runtime registry. | Keep |
| `issuer`, `client-id`, `client-secret`, `token-endpoint-auth-method` | Distinct protocol identity and client authentication settings. The method's inferred default depends on whether a secret is present; public, JWT, and mTLS clients need explicit overrides. | Keep |
| `outbound-mutual-tls` (false) | Enables mTLS endpoint selection independently of TLS client **authentication**, including certificate-bound tokens acquired with Basic or JWT auth, as required by [RFC 8705 section 5](https://www.rfc-editor.org/rfc/rfc8705.html#section-5). | Keep |
| `webclient` | Full Helidon `WebClientConfig` is reused for tenant protocol traffic (metadata, JWKS, token, introspection, UserInfo). No parallel timeout/TLS/proxy settings in this group. | Keep |
| Root `outbound` targets | Reuses Helidon's common `OutboundTarget`; OIDC-specific target flags are audited under outbound policies below. | Defer details |

Finding: no removal is supported in this section. The superficially similar `path-segment` and `path-template` do
different things; the initialization limits are backpressure and retry controls, not duplicate knobs. The issuer
uniqueness opt-out is an exceptional nonconformant choice with a safe default, not a second default issuer policy.

## Endpoints, metadata, and JWK Set management

Sources: `OidcEndpointConfigBlueprint`, `OidcJwkSetConfigBlueprint`, `OidcProviderMetadata`,
`OidcTenantContextFactory`, `OidcJwkSetManager`, and the endpoint/JWK Set validation and concurrency tests.

| Option(s) | Actual role and reason to expose them | Decision |
| --- | --- | --- |
| `endpoints.well-known-uri` | Otherwise derived from the issuer. An explicit URI is needed for provider-specific metadata locations and setups that obtain the issuer from the metadata document. Static endpoint overrides take precedence over discovered values while the discovered issuer is still checked. | Keep |
| `endpoints.authorization-endpoint-uri`, `token-endpoint-uri`, `jwks-uri` | Individually pin the OP/AS URLs when Discovery is unavailable or incomplete. The actual enabled flows still require their necessary endpoints or signing keys. | Keep |
| `endpoints.pushed-authorization-request-endpoint-uri` | Separate PAR HTTP API, not the Authorization Endpoint; [RFC 9126 section 2](https://www.rfc-editor.org/rfc/rfc9126.html#section-2) requires an HTTPS PAR URI even for non-TLS test exceptions. | Keep |
| `endpoints.introspection-endpoint-uri`, `user-info-endpoint-uri`, `end-session-endpoint-uri` | Independently optional features and distinct metadata fields; explicit URIs support non-discovery providers. | Keep |
| `endpoints.tls-required` (true) | One scoped non-production compatibility/testing escape for endpoint URLs and selected outbound targets; HTTPS remains mandatory for PAR. It is not a duplicate of inbound token transport's separate secure-transport rule. | Keep, secure default |
| `jwk-set.max-queued` (128), `admission-timeout` (1 s) | Separately bound waiting callers and waiting time during one shared JWK load. Neither changes tenant WebClient I/O timeout or tenant initialization's own queue. | Keep |
| `jwk-set.unknown-key-id-refresh-enabled` (true), `unknown-key-id-refresh-interval` (30 s) | Decide whether an unknown `kid` can request keys and bound how often it can force a new load; the first unknown `kid` can refresh immediately after a completed initial load. | Keep |
| `jwk-set.refresh-interval` (absent; remote HTTP keys default to 5 min) | Caps lazy remote JWKS freshness after considering HTTP cache headers, without a background worker. Local/file sources still have no age refresh unless configured. | Keep, finite remote default |
| `jwk-set.failure-retry-interval` (10 s), `max-stale-on-error` (0) | Independently control retry storms and a bounded, opt-in grace period for previously loaded keys if an allowed refresh fails. A zero grace fails closed. | Keep, secure defaults |

Finding: explicit endpoint locations correspond to separate protocol features; using the whole tenant `webclient`
avoids parallel HTTP timeout or proxy knobs. The JWK Set controls have separate consumers in the manager, so none
can be removed merely because there are several durations.

JWKS-01 (resolved): Previously, an absent `refresh-interval` left a successfully loaded remote JWK Set trusted without
age refresh; a known `kid` could remain valid even after its issuer removed a compromised key. `stale-on-error: true`
also kept old keys usable through repeated refresh failures without an upper bound. The manager now uses a five-minute
maximum by default for HTTP keys, shortened by `Cache-Control` / `Expires` and existing `Age` / `Date`; a source response
already older than the allowed lifetime cannot restore a key. `no-cache`, `no-store`, and `must-revalidate` constrain
reuse, while local/file keys retain their separate explicit age-refresh policy. An unfamiliar `kid` can prompt an
immediate rate-limited refresh, and `max-stale-on-error` defaults to zero or allows only an explicit bounded grace where
the issuer permits it. A successful reload replaces all old keys. See `OidcJwkSetHttpCacheTest` and the JWT, redirect,
concurrency, and configuration tests. [OIDC Core section 10.1.1](https://openid.net/specs/openid-connect-core-1_0.html#RotateSigKeys)
describes key rollover and removal; it does not set a mandatory numeric refresh interval or promise instant revocation.

## Authorization Code Flow

Sources: `OidcAuthorizationCodeConfigBlueprint`, `OidcAuthorizationCodeConfigDecorator`,
`OidcAuthenticationRequestFactory`, `OidcTenantContextFactory`, `OidcRefreshCoordinator`, and the browser and refresh
tests. Request Object signing/encryption, client assertion, and ID Token details are audited separately below.

| Option(s) | Actual role and reason to expose them | Decision |
| --- | --- | --- |
| `authorization-code.enabled` (true when block exists) | Explicitly disables a configured/inherited browser feature without affecting a protected-resource tenant. Merely omitting the whole block is the ordinary way to leave browser login off. | Keep |
| `redirection-endpoint-uri` (`/oidc/callback`) | Exact OAuth redirect binding and callback route; registered URI may be a different path or absolute origin. | Keep |
| `scopes` (`openid`), `prompts` (empty) | OIDC/OAuth Authentication Request values; `openid` is required, and `offline_access` requires consent handling. Provider-specific prompt and scope choices vary. | Keep |
| `resources` (empty) | RFC 8707 Authorization Request indicators also inform the corresponding code and refresh token requests; distinct from outbound-target resources. [RFC 8707 section 2](https://www.rfc-editor.org/rfc/rfc8707.html#section-2). | Keep |
| `pushed-authorization-requests` (`AUTO`) | Selects disabled, metadata/static auto-use, or required PAR; `REQUIRED` prevents falling back when the server or client registration mandates it. Distinct from Request Object signing. | Keep |
| `request-object` (disabled by default) | Optional signed and optionally encrypted by-value JAR, also usable through PAR; signing/encryption options below. | Review subtree next |
| `refresh-remote-work` | Bounds concurrent refresh calls, queued followers, and admission waiting separately from Token Endpoint WebClient timeouts. | Keep |
| `refresh-result-retention` (`PT5S`), `refresh-result-cache-capacity` (1024) | Different limits of the completed-refresh single-flight cache. Reuse lets an in-flight request carrying a stale rotating refresh token share the prior outcome; capacity bounds retained sessions during high-volume refresh bursts. The retention window is short and validated to 1–60 s. | Keep for now; see note |
| `pkce-required` (true), `pkce-method` (`S256`) | Default code-injection protection; public clients cannot disable PKCE or choose `plain`. Confidential clients have explicit legacy compatibility overrides. [RFC 9700 section 2.1.1](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1.1). | Keep safe defaults |
| `pkce-s256-support-assured` (false) | Explicit out-of-band proof when an otherwise trusted AS omits `code_challenge_methods_supported`. RFC 9700 permits deployment-specific ways to establish support; missing RFC 8414 metadata alone does not authorize silent downgrade. | Keep |

Potential simplification question, not an approved removal: the completed-refresh retention and capacity are internal
coordination parameters, unlike protocol wire values. However a fixed cache cap could evict outcomes during large
refresh bursts, and a fixed grace window could be wrong for genuinely in-flight requests. Preserve them unless a
bounded operational policy can replace both without introducing login failures or refresh-token replay exposure.

### Request Objects and client assertions

Sources: `OidcRequestObjectConfigBlueprint`, `OidcRequestObjectProcessor`, `OidcClientAssertionConfigBlueprint`,
`OidcClientAuthenticationSupport`, tenant validation, and JAR/PAR/client-authentication tests. These are separate
messages: a JAR Request Object is an Authorization Request signed for the OP; a JWT client assertion authenticates
the client to Token/PAR/Introspection endpoints. They may use different keys or registered algorithms.

| Option(s) | Distinct use | Decision |
| --- | --- | --- |
| `request-object.mode` (`AUTO`) | Configure optional, explicitly required, or disabled JAR while still handling server metadata requiring a signed request. [RFC 9101 section 4](https://www.rfc-editor.org/rfc/rfc9101.html#section-4). | Keep |
| `request-object.signing-jwk`, `signing-key-id`, `signing-algorithm` | Local client private key material, key selection for multi-key sets, and the registered signing algorithm; defaults cover only unambiguous keys and supported algorithms. | Keep |
| `request-object.encryption-algorithm`, `content-encryption-algorithm`, `encryption-key-id` | Separate JWE key-management algorithm, content-encryption algorithm, and OP public-key selection. OIDC client registration defines the default `enc` when `alg` is set; explicit algorithms/key IDs support registered combinations and multiple eligible keys. [OIDC Registration, request object encryption](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata). | Keep |
| `request-object.lifetime` (`PT1M`) | Request Object expiration window, which may need to match authorization-server clock tolerance and PAR processing time. Not the client-assertion expiration below. | Keep |
| `client-assertion.algorithm`, `key-id`, `jwk` | Independently configure Token/PAR/Introspection JWT client authentication and private signing key. Shared key policy and validation code are reused, not separate ad hoc JOSE implementations. | Keep |
| `client-assertion.lifetime` (`PT1M`) | Expiration of fresh per-request client assertions; independent from JAR Request Object lifetime. | Keep |

Finding: similar signing-key fields are not duplicate configuration for the same protocol action. Do not merge them
just because the defaults match; the OP may require different registration credentials and signing algorithms for
JAR and client authentication. Private JWK inputs use Helidon's `ResourceConfig`, not custom file/URL knobs.

### ID Token validation and decryption

Sources: `OidcIdTokenConfigBlueprint`, `OidcIdTokenValidator`, `OidcIdTokenDecryptor`,
`OidcIdTokenConfigDecorator`, tenant validation, and ID Token/JWE tests.

| Option(s) | Distinct use | Decision |
| --- | --- | --- |
| `allowed-algorithms` (`RS256`) | Explicit JWS verification allow-list; provider registration and supported signing algorithms vary. Does not allow unsigned tokens. | Keep |
| `allowed-encryption-algorithms`, `allowed-content-encryption-algorithms` | Independently constrain JWE `alg` and `enc` when receiving encrypted tokens, including the registered defaults. They are not interchangeable or copies of the JAR *outgoing* encryption choices. | Keep |
| `trusted-additional-audiences` (absent) | Allows explicitly trusted additional `aud` members while always requiring this tenant's client id. The optional list also distinguishes a user's deliberate empty override from an adapter-supplied default. | Keep |
| `clock-skew` (`PT1M`) | Bounded clock tolerance while validating ID Token times; independent of bearer-token and signed-UserInfo clock policy. | Keep |
| `decryption-jwk` (absent), `encryption-required` (false) | Local private key needed to decrypt JWE; independently require *every* received ID Token to be encrypted when registered, preventing silent signed-only downgrade. Registration distinguishes JWE `alg` from `enc`. [OIDC Registration client metadata](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata). | Keep |

Finding: no redundant ID Token option. Different JOSE algorithm lists apply at separate inbound/outbound security
boundaries. The key is supplied as Helidon's `ResourceConfig` rather than a bespoke URI/file mechanism.

## Protected resources and bearer-token transport

Sources: `OidcProtectedResourceConfigBlueprint`, `OidcTokenTransportConfigBlueprint`,
`OidcTokenValidationConfigBlueprint`, `OidcBearerTokenExtractor`, bearer validators, and tenant validation.
JWT layout, introspection credentials/caching, and certificate binding receive their own checks below.

| Option(s) | Actual role and reason to expose them | Decision |
| --- | --- | --- |
| `protected-resource.enabled`, `token-validation.method` | Presence enables protected-resource behavior, and the method chooses signed JWT validation versus authenticated introspection of an opaque token. A disabled resource can still configure validation for refreshed Code Flow access tokens. | Keep |
| `protected-resource.challenge-realm` | Names the Bearer protection space in `WWW-Authenticate`, which an API may need to identify itself. [RFC 6750 section 3](https://www.rfc-editor.org/rfc/rfc6750.html#section-3). | Keep |
| `token-transport.authorization-header-enabled` (true), `query-parameter-enabled` (false) | Independently allow the standard header or explicitly enable the discouraged query transport; at least one is required for an enabled protected resource. [RFC 6750 section 2.3](https://www.rfc-editor.org/rfc/rfc6750.html#section-2.3) calls out query leakage risks. | Keep safe defaults |
| `token-transport.secure-transport-required` (true) | Enforces TLS for inbound bearer requests, not for outbound OP endpoints; distinct from `endpoints.tls-required`. Explicit false is for isolated non-TLS testing. | Keep secure default |
| `token-validation.issuer` (absent) | Independently pins the access-token authority when it differs from the OIDC ID Token issuer; independent signing keys are required for different issuers. | Keep |
| `token-validation.audience`, `audience-validation-enabled` (true) | Configure the resource identifier and an explicit, risk-accepted compatibility opt-out. RFC 9068 requires a JWT resource server to check `aud`; RFC 7662 makes introspection `aud` optional. [RFC 9068 section 4](https://www.rfc-editor.org/rfc/rfc9068.html#section-4), [RFC 7662 section 2.2](https://www.rfc-editor.org/rfc/rfc7662.html#section-2.2). | Keep safe default |
| `token-validation.verification-jwk`, `jwks-uri` | Mutually exclusive local and remote *access-token* signing keys. Local provisioning is necessary for HMAC; independent remote URI is necessary when access tokens use an issuer/key set different from the OP's ID Token keys. | Keep |
| `token-validation.allowed-algorithms` (`RS256`), `clock-skew` (`PT1M`) | Signed access-token key policy and time tolerance, separate from ID Token validation and provider registration. | Keep |
| `token-validation.jwt`, `introspection`, `certificate-bound-access-tokens` | Typed policy for distinct JWT profiles, introspection credentials/remote work, and sender constraints. | Review each below |

Finding: no redundant top-level bearer setting. In particular, `token-validation.issuer` and the independent access-token
key source must not be folded into the OP issuer/JWKS: that would allow keys for one authority to verify another's token.

### JWT access-token layout

Sources: `OidcJwtAccessTokenConfigBlueprint`, its decorator, `OidcJwtAccessTokenValidator`, and the Keycloak/IDCS
layout tests. RFC 9068 is the secure default; a separately selected `CUSTOM` profile supports real providers that
issue signed access-token JWTs with different layouts. [RFC 9068 sections 2 and 4](https://www.rfc-editor.org/rfc/rfc9068.html#section-2).

| Option(s) | Distinct use | Decision |
| --- | --- | --- |
| `jwt.profile` (`RFC_9068`) | Selects normative access-token layout or an explicit provider-specific one without changing signature/issuer checks. | Keep |
| `jwt.allowed-types` (`at+jwt`, `application/at+jwt`), `typ-header-required` (true) | Separately select permitted JOSE header values and whether it can be absent. IDCS can omit the header; only a CUSTOM layout with an exact signed claim discriminator can allow that. | Keep |
| `jwt.required-claims`, `required-string-claims` | Presence-only checks versus exact signed value matches. The latter is important to separate provider-specific access tokens from ID Tokens signed by the same issuer. | Keep both |

Finding: no duplicate between presence-only claims and exact discriminator claims. Their input validation prevents
accidentally accepting unspecified JWT types just to support a provider with a missing `typ` header.

### Introspection and certificate-bound tokens

Sources: `OidcIntrospectionConfigBlueprint`, `OidcClientAuthenticationSupport`,
`OidcIntrospectionAccessTokenValidator`, `OidcCertificateBoundAccessTokenConfigBlueprint`,
`OidcCertificateBoundAccessTokenSupport`, and both JWT/opaque certificate-bound tests.

| Option(s) | Distinct use | Decision |
| --- | --- | --- |
| `introspection.auth-method` | May differ from the Token Endpoint client-auth method. An authenticated resource server, not necessarily the RP OAuth client, requests introspection. `NONE` is rejected. | Keep |
| `introspection.client-id`, `client-secret`, `client-assertion` | Optional Introspection Endpoint credential override; each otherwise inherits the appropriate tenant-level setting. This supports different registered resource-server credentials without duplicating JWT assertion configuration. | Keep |
| `introspection.remote-work` | Bounds active and queued remote introspection requests and their admission waiting; applies only to opaque-token validation, not to WebClient I/O. | Keep |
| `certificate-bound-access-tokens.mode` (`DISABLED`) | `DISABLED` rejects bound access tokens on an ordinary Bearer path; `IF_PRESENT` verifies a binding when advertised; `REQUIRED` enforces it for every token. Different resource-server policies under [RFC 8705 section 3](https://www.rfc-editor.org/rfc/rfc8705.html#section-3). | Keep |

Finding: the introspection credentials are fallback overrides, not copies that users must configure twice. The single
certificate-binding mode is necessary to distinguish optional from mandatory sender-constrained validation.

## Outbound policies and remote-work limits

Sources: `OidcOutboundPolicyConfigBlueprint`, `OidcOutboundPolicyConfigDecorator`, `OidcOutboundPolicy`,
`OidcOutboundOrchestrator`, `OidcRemoteWorkConfigBlueprint`, `OidcRemoteWorkLimiter`, and outbound tests. Outbound
targets themselves reuse Helidon's `OutboundTarget` rather than a second matcher implementation.

| Option(s) | Actual role and reason to expose them | Decision |
| --- | --- | --- |
| `strategy` (`NONE`) | One selector for Token Propagation, Client Credentials, or Token Exchange per policy. `NONE` at endpoint level preserves matching-target fallback; strategies remain independently selectable for different targets. | Keep; OUT-01 resolved |
| `client-credentials-scopes`, `client-credentials-resources` | OAuth scope string and repeated RFC 8707 target-resource URIs for the new client-credentials grant; independently affect the request and token cache key. | Keep |
| `token-exchange-scopes`, `token-exchange-resource`, `token-exchange-audience` | Distinct [RFC 8693 request parameters](https://www.rfc-editor.org/rfc/rfc8693.html#section-2.1); `resource` is a URI, `audience` can name a logical service. | Keep |
| `audience`, `audience-validation-enabled` (true) | Local destination check before propagating an existing token, not the `audience` requested from Token Exchange or the current protected resource's inbound audience. Explicit false allows risk-accepted opaque propagation. | Keep safe default |
| `remote-work.max-concurrent` (32), `max-queued` (128), `admission-timeout` (1 s) | Separately bound active remote calls, waiting callers, and waiting duration; one reusable implementation backs refresh, introspection, client credentials, and Token Exchange. Not outbound HTTP I/O timeouts. | Keep |

OUT-01 (resolved): `strategy: NONE | TOKEN_PROPAGATION | CLIENT_CREDENTIALS | TOKEN_EXCHANGE` replaces the three
mutually exclusive booleans. `NONE` preserves the previous all-false behavior: no strategy at that level, so an
endpoint policy can still fall back to a matching configured target. Incompatible strategy-specific settings remain
configuration errors. Grant-specific scopes/resources and the independent token-propagation audience check remain
separate settings.

## UserInfo, logout, and End Session

Sources: `OidcUserInfoConfigBlueprint`, `OidcUserInfoJwtConfigBlueprint`, `OidcUserInfoSupport`,
`OidcLogoutConfigBlueprint`, `OidcEndSessionConfigBlueprint`, `OidcLogoutHandler`, and the UserInfo/logout route tests.

| Option(s) | Actual role and reason to expose them | Decision |
| --- | --- | --- |
| `user-info.enabled`, `logout.enabled`, `logout.end-session.enabled` | Separate switches for an optional UserInfo fetch, the local logout endpoint, and the OP logout redirect. `end-session.enabled: false` keeps local cookie clearing. The nested booleans also allow an environment to disable an inherited feature without deleting its settings. | Keep |
| `user-info.jwt` (absent) | Require JSON or the exact signed/encrypted JWT response negotiated with the OP. The core still matches UserInfo `sub` to the validated ID Token before using claims. | Keep |
| `user-info.storage-policy` (`MAPPED`), `attribute-claim-paths` | Distinguish minimal stored claims, all claims, or validated-but-discarded UserInfo. Additional paths preserve attributes not needed for subject mapping while keeping the default cookie small. | Keep |
| `user-info.jwt.signing-algorithm`, `encryption-algorithm`, `content-encryption-algorithm`, `decryption-jwk`, `clock-skew` | Independently describe registered JWS/JWE response shape, local decryption key, and time tolerance; do not conflate OP signing keys with RP decryption keys. [OIDC Registration client metadata](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata). | Keep |
| `logout.local-endpoint-uri` (`/oidc/logout`) | Application-visible local POST route; independent of the OP's discovered End Session URI. | Keep |
| `logout.end-session.id-token-hint-required` (true) | A controlled exception for OPs permitting logout without a local ID Token; core still clears local cookies. | Keep |
| `logout.end-session.post-logout-redirect-uri`, `allowed-post-logout-redirect-uris` | Default RP return URI versus allow-list for a caller-selected one. Keep the exact allow-list to prevent user-input open redirects. [OIDC RP-Initiated Logout section 2](https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout). | Keep both |

Finding: there is no duplicate OP/local logout URI and no redundant JWS/JWE algorithm setting. The three `enabled`
flags govern *different* operations, unlike the mutually exclusive outbound strategy booleans in OUT-01.

## Subject mapping and endpoint policy

Sources: `OidcSubjectMappingConfigBlueprint`, `OidcSubjectMapper`, `OidcEndpointPolicyConfigBlueprint`,
`OidcEndpointPolicyResolver`, and the browser/JWT/introspection subject and endpoint-policy tests.

| Option(s) | Actual role and reason to expose them | Decision |
| --- | --- | --- |
| `subject-mapping.principal-id-claim-paths` (`sub`) | Selects a stable ID for *bearer* subjects, qualified by trusted issuer and claim path; browser identity remains ID Token `iss`/`sub`. Providers vary in resource-subject claims. | Keep |
| `subject-mapping.principal-id-namespace` (absent) | Explicit local authority for introspection without a pinned/discovered issuer; prevents equal `sub` values from different authorities sharing identities. Ignored when issuer is known. | Keep |
| `subject-mapping.principal-name-claim-paths` (`preferred_username`, `username`) | Display name lookup, deliberately independent of stable principal ID and issuer qualification. | Keep |
| `subject-mapping.role-claim-paths` (`groups`), `scope-claim-paths` (`scope`) | Map distinct provider-specific role and OAuth-scope sources to different grants. | Keep |
| `subject-mapping.scope-grants-enabled` (true) | Disables scope grants from both browser session scopes and bearer claims. Setting only `scope-claim-paths` empty would not disable browser scope grants. | Keep |
| `endpoint-policy.accepted-credentials` (inferred) | Per-route choice between Bearer token, protected authentication cookie, or both; follows enabled tenant features when omitted. | Keep |
| `endpoint-policy.authentication-failure-response` (inferred) | Independently chooses 401 versus starting a browser Code Flow when authentication fails. Redirect requires an enabled cookie flow. | Keep |

Finding: user identity versus display name, roles versus scopes, and credential acceptance versus failure behavior are
genuinely different settings. This section does not warrant a removal. The issuer/namespace rule and per-route policy
validation prevent a configuration shortcut from silently changing identity or authentication semantics.

## Optional IDCS adapter values

Sources: `../oidc-next-idcs/src/main/java/io/helidon/security/providers/oidc/next/idcs/IdcsTenantAdapter.java`,
the IDCS adapter README, configuration tests, and protected-JWKS HTTPS tests. The adapter is opt-in for each tenant;
its `name` is SPI registration identity, not a separate YAML setting.

| Option (default) | Distinct use | Decision |
| --- | --- | --- |
| `adapter.idcs.domain-uri` (required) | Primary HTTPS identity-domain URL from which missing documented endpoint paths and the tenant-specific local identity namespace are derived. | Keep |
| `adapter.idcs.secure-domain-uri` (absent) | Additional trusted origin for the certificate-based grant's token and protected signing-key endpoints when it differs from the primary IDCS domain. Not an arbitrary JWKS redirect. | Keep |
| `adapter.idcs.jwks-grant` (`CLIENT_CREDENTIALS`) | Chooses standard client credentials versus Oracle's vendor-specific `tls_client_auth` grant for protected signing-key access. | Keep |
| `adapter.idcs.jwks-scope` (`urn:opc:idm:__myscopes__`) | Requests authorization for an otherwise inaccessible signing-key API. A narrow explicitly permitted scope may be needed per tenant. | Keep; see note |

Default-policy note: Oracle documents `__myscopes__` as all permitted identity-domain scopes, and its
[security checklist](https://docs.oracle.com/en/cloud/paas/identity-cloud/idcsa/SecurityChecklist.html) warns that it
can grant more scope than a request needs. This adapter uses the resulting access token only for one trusted JWKS URI,
but a narrower grant would be preferable if the deployment supports one. Verify actual IDCS signing-key permissions
before changing the default; retaining the configurable scope supports least privilege without inventing a grant.

## Next actions

1. JWKS-01 is resolved in code and tests; verify real provider cache headers and rotation behavior when live test tenants
   are available. No offline cache guarantees immediate revocation of already-issued tokens.
2. Only if a realistic workload calls for it, reconsider whether the completed-refresh retention/cache-capacity knobs
   should remain public; no safe removal has been established.
3. Confirm whether a narrower IDCS signing-key scope exists for the target tenant/registration before changing the
   adapter's documented default. Do not assume it from synthetic tests.
4. Once the shape is agreed, update the currently untracked and outdated `MIGRATION.md` separately and rerun live
   provider scenarios. No earlier review document was consulted for this audit.
