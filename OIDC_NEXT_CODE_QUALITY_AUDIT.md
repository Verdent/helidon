# oidc-next Code Quality Audit

Date: 2026-06-18

Scope: current `security/providers/oidc-next` provider implementation. This file is a live audit log and should be
updated as files are reviewed and cleanup decisions are made.

## Audit Intent

Review the provider one file at a time for code quality, API shape, and unnecessary implementation surface. The main
criteria are:

- no helper methods that only wrap a simple expression or hide readable code;
- no helper methods that reduce readability by forcing unnecessary indirection;
- no package-private factories or constructors kept only for old compatibility shapes;
- no pointless types, result wrappers, or enum methods;
- names must be reviewed for length, precision, and domain meaning;
- long names must earn their length by removing ambiguity, especially in protocol/config API;
- short names and abbreviations must be standard in the domain (`OIDC`, `JWK`, `JWT`, `PAR`, `URI`) or clearly local;
- config option names, generated builder names, enum text values, and Java identifiers must describe the same concept;
- no unrelated refactors while applying cleanup;
- keep protocol/spec-driven separation where it improves correctness and reviewability.

This provider is new. Backward compatibility is not a constraint for internal/package-private code, and public API can
still be adjusted when the current design is visibly worse than the simpler shape.

## Current Status

Inventory completed:

- `security/providers/oidc-next/src/main/java`: 103 Java files.
- Public user-facing surface identified: `OidcProvider`, `OidcFeature`, generated config types, and public config enums.
- Largest implementation files identified: `OidcTenantConfigDecorator`, `OidcTenantContextFactory`,
  `OidcProviderMetadata`, `OidcEndpointClient`, `OidcClientAuthenticationSupport`, `OidcEndpointUris`,
  `OidcAuthenticationRequestFactory`, `OidcSubjectMapper`, `OidcIdTokenValidator`.

Reviewed so far:

- API entry points: `OidcProvider`, `OidcFeature`, `OidcProviderService`, `module-info.java`.
- Config blueprints: provider, tenant, authorization code, request object, client assertion, endpoints, ID token,
  JWK set, token validation, introspection, endpoint policy, certificate-bound token config.
- Runtime/config internals: `OidcTenantContextFactory`, `OidcTenantRuntimeRegistry`, `OidcTenantContext`,
  the extracted config decorators and validators, `OidcProviderMetadata`.
- Token endpoint and protocol result types: `OidcEndpointClient`, `OidcTokenEndpointResult`,
  `OidcPushedAuthorizationRequestResult`, `OidcTokenExchangeResult`, `OidcTokenResponse`,
  `OidcTokenExchangeResponse`, `OidcTokenErrorResponse`, `OidcAuthorizationResponseResult`,
  `OidcValidationResult`, `OidcBearerTokenExtractionResult`.
- Client/auth/token helpers: `OidcClientAuthenticationSupport`, `OidcOutboundPolicy`,
  `OidcAuthenticationRequestFactory`, `OidcBearerTokenExtractor`, `OidcJwtAccessTokenValidator`,
  `OidcIntrospectionAccessTokenValidator`, `OidcCertificateBoundAccessTokenSupport`,
  `OidcResponseFactory`, `OidcRefreshTokenManager`.
- Local authentication cookie state/value types: `OidcCookieStateHandler`, `OidcAuthenticationRequestState`,
  `OidcLocalAuthenticationResult`.
- Compact support helpers: `OidcRequestObjectSigner`, `OidcIdTokenDecryptor`, `OidcBearerTokenExtractor`,
  `OidcScopeSupport`, `OidcUri`, `OidcOAuthErrorFields`, `OidcHttpResponseValidation`.
- Authorization-code request orchestration: `OidcAuthenticationRequestFactory`, `OidcAuthenticationRequest`,
  `OidcAuthenticationOrchestrator`.
- User-flow handlers: `OidcAuthorizationResponseProcessor`, `OidcAuthorizationResponseResult`,
  `OidcLogoutHandler`, `OidcUserInfoSupport`.
- Outbound policy and token caches: `OidcOutboundPolicy`, `OidcOutboundOrchestrator`,
  `OidcClientCredentialsTokenManager`, `OidcTokenExchangeTokenManager`.
- Request/provider wrappers: `OidcRequestContext`, `OidcProvider`, `OidcFeature`, `OidcProviderService`.
- Tenant resolution/runtime wrappers: `OidcTenantResolver`, `OidcTenantRuntimeRegistry`.

Applied cleanup:

- Removed unused `OidcTenantContextFactory`, `OidcJwkSetManager`, `OidcClientAuthenticationSupport`, and
  `OidcResponseFactory` delegation overloads.
- Replaced internal stateless validator `create()` factories with package-private constructors and direct `new`
  call sites.
- Removed duplicate outbound scope serialization wrappers and the unused token-exchange bearer-token constant.
- Changed `OidcEndpointCredential` and `OidcAuthenticationFailureResponse` from `toString()`-backed config text to
  explicit `text()` methods; renamed the stored enum field to `text` and added explicit config-text tests.
- Collapsed `OidcProviderMetadata` construction to the three real sources: static config, well-known JSON, and merge.
  Test-only convenience moved to test helpers or existing source-specific factories.
- Naming cleanup applied where it improved readability without hiding protocol meaning:
  `wellKnownMetadata` method parameters were shortened to `wellKnown` inside metadata merge/validation, because the
  method names already supply the metadata context and the shorter name keeps protocol-long expressions readable.
- Replaced overloaded `OidcLocalAuthenticationResult.create(...)` factories with source-specific factories:
  `fromTokenResponse(...)` and `fromStoredValues(...)`. Optional stored fields are now represented internally as
  `Optional` values instead of nullable fields wrapped by getters.
- Removed a one-line `OidcHttpResponseValidation.headerValues(...)` helper and inlined the direct header access.
- Tightened key-id local naming in request-object signing and ID-token decryption; the local `id` now carries the
  unwrapped value instead of repeatedly unwrapping `keyId`.
- Renamed the bearer-token character predicate to `validB64TokenCharacter(...)`, which is a clearer boolean name while
  still using the RFC `b64token` term.
- Reworked token/authorization response values and small result wrappers to store optional payload fields as `Optional`
  internally rather than nullable fields wrapped by getters.
- Removed the pure `OidcValidatedIntrospection.create(...)` factory and use its package-private constructor directly.
- Removed pure internal `create()` factories from `OidcAuthenticationRequestFactory` and `OidcRefreshTokenManager`;
  direct package-private constructors now express the same construction without indirection.
- Removed pure `create(...)` factories from callback/logout handlers and use package-private constructors directly.
- Reworked callback `ParameterValue` and UserInfo `Result` helpers to store optional state as `Optional` values with
  non-null compact constructor checks.
- Made endpoint-level `OidcOutboundPolicy` public because README and tests intentionally support attaching it through
  `EndpointConfig.customObject(...)`; removed the misleading no-arg token-propagation factory from the public shape.
- Updated README endpoint-level outbound examples and fixed stale Token Exchange cache-key wording.
- Removed pure `create(...)` factories from `OidcRequestContext` and `OidcOutboundOrchestrator`.
- Removed pure `OidcTenantResolver.create(...)` and construct the resolver directly from the runtime registry.
- Removed generated `@Option.AllowedValue` checks from endpoint-policy text-backed enums because generated builder
  validation compares the mapped enum object string, while config text values are exposed through explicit `text()`.
- Split `OidcConfigSupport` into named package-private owners and removed the generic support class. Builder decorators
  now use direct decorator classes, URI validation lives in `OidcEndpointUris`, client-auth config validation lives in
  `OidcClientAuthenticationConfigValidator`, WebClient defaulting lives in `OidcWebClientFactory`, endpoint-policy
  resolution lives in `OidcEndpointPolicyResolver`, and shared resource indicator validation lives in
  `OidcResourceIndicators`.

## Cleanup Candidates To Apply

### CQ-1: Collapse `OidcProviderMetadata` package-private `create` overload ladder

File:

- `security/providers/oidc-next/src/main/java/io/helidon/security/providers/oidc/next/OidcProviderMetadata.java`

Issue:

`OidcProviderMetadata` has a long chain of package-private static `create(...)` overloads that grew as metadata fields
were added. Current production construction is already centralized through `fromStaticConfig`,
`fromWellKnownMetadataJson`, and `mergeWellKnownMetadata`; most overloads exist for tests or as internal delegation.

Decision:

Remove the overload ladder from production. Keep one direct internal construction path, preferably a private constructor
or a single private static factory used by production methods. Move any test convenience into test helpers.

Status:

Done. Production now constructs metadata directly from static tenant config, well-known JSON, or a merge operation.
`OidcProviderMetadata.create(...)` no longer exists, and tests no longer depend on production overloads.

Rationale:

This is not public API. A long optional-parameter overload chain is hard to read and makes adding metadata fields risky.
Tests should not force production to carry construction helpers that users do not need.

### CQ-2: Remove unused `OidcTenantContextFactory` factory overloads

File:

- `security/providers/oidc-next/src/main/java/io/helidon/security/providers/oidc/next/OidcTenantContextFactory.java`

Issue:

`create()` and `create(boolean outboundTargetClientCredentialsGrant)` are unused pure delegation methods.

Decision:

Remove them. Keep the two-boolean factory used by `OidcTenantRuntimeRegistry`, and keep the `TenantInitializer` factory
used by tests for lifecycle behavior.

Status:

Done.

### CQ-3: Remove unused `OidcJwkSetManager` factory overloads

File:

- `security/providers/oidc-next/src/main/java/io/helidon/security/providers/oidc/next/OidcJwkSetManager.java`

Issue:

The default-config WebClient and Clock factory overloads are unused pure delegation methods.

Decision:

Remove:

- `create(String, OidcProviderMetadata, WebClient)`
- `create(String, OidcProviderMetadata, Clock)`

Keep the explicit config overloads used by production and tests.

Status:

Done.

### CQ-4: Make endpoint policy enums use explicit `text()` instead of `toString()`

Files:

- `OidcEndpointCredential.java`
- `OidcAuthenticationFailureResponse.java`

Issue:

These public enums override `toString()` to return config text. Other recently reviewed config enums use explicit
`text()` methods, which avoids making diagnostics depend on config serialization.

Decision:

Replace `toString()` overrides with public `text()` methods and adjust validation/error messages that need config text.

Status:

Done. Added explicit tests for the two config text mappings.

### CQ-5: Remove duplicate scope wrapper helpers

Files:

- `OidcConfigSupport.java`
- `OidcOutboundPolicy.java`

Issue:

`clientCredentialsScope(List<String>)` and `tokenExchangeScope(List<String>)` are identical wrappers around
`OidcScopeSupport.serializeScopes(scopes)` with only an empty-list special case that `String.join` already handles.

Decision:

Inline the serialization into `OidcOutboundPolicy` and remove both helpers.

Status:

Done.

### CQ-6: Trim unused internal client-auth factory/helper

File:

- `OidcClientAuthenticationSupport.java`

Issue:

`create(OidcTenantConfig)` is just an alias for `tokenEndpoint(OidcTenantConfig)` and has one caller. The explicit
method name is clearer at the call site. `defaultClientSecretJwtAlgorithm()` is unused.

Decision:

Use `tokenEndpoint(tenantConfig)` directly and remove both methods.

Status:

Done.

### CQ-7: Remove unused token exchange constant

File:

- `OidcTokenExchangeResponse.java`

Issue:

`BEARER_TOKEN_TYPE` is unused.

Decision:

Remove it. Keep `ACCESS_TOKEN_TYPE`, which is used by request construction and token exchange caching.

Status:

Done.

### CQ-8: Simplify repeated `Optional<URI>.orElseThrow()` in endpoint client

File:

- `OidcEndpointClient.java`

Issue:

`pushedAuthorizationRequest` and token endpoint `submit` resolve endpoint `Optional<URI>` and then call
`orElseThrow()` repeatedly.

Decision:

Resolve the URI once into a local variable after the empty check and use that variable for WebClient URI and
authentication calls.

Status:

Done.

### CQ-9: Remove unused default-realm response factory overloads

File:

- `OidcResponseFactory.java`

Issue:

Several default-realm overloads are unused and only delegate:

- `missingBearerToken()`
- `missingBearerToken(Optional<String>)`
- `bearerTokenValidationNotConfigured()`
- `invalidBearerToken(String)`
- `invalidBearerTokenRequest(String)`

Decision:

Remove unused overloads. Keep call-site-specific overloads that are used and improve readability.

Status:

Done.

### CQ-10: Replace stateless validator `create()` factories with constructors where internal-only

Files:

- `OidcJwtAccessTokenValidator.java`
- `OidcIntrospectionAccessTokenValidator.java`
- `OidcIdTokenValidator.java`
- `OidcRefreshTokenManager.java`

Issue:

Some package-private `create()` factories only hide `new` for stateless/internal classes. That adds indirection without
clear construction semantics.

Decision:

Where constructor injection remains simple and package-private, use direct construction. Keep factories that assemble
multiple collaborators or represent a meaningful runtime construction boundary.

Status:

Done for the stateless access-token and ID-token validators.

### CQ-11: Continue explicit naming audit

Files:

- all remaining provider production files

Issue:

The provider has several protocol-heavy identifiers that are naturally long. Some are justified because they name exact
OAuth/OIDC concepts (`pushedAuthorizationRequestEndpointUri`, `requestObjectSigningAlgorithmsSupported`), but others
may be accidental verbosity or legacy layering. Names must be checked independently of behavior.

Decision:

During the remaining file-by-file pass, record names that are too long, too generic, misleading, or inconsistent with
config keys. Rename only when the replacement is clearly more precise or shorter without losing protocol meaning.

Initial naming notes:

- Keep standard protocol abbreviations and terms: `Oidc`, `Jwt`, `Jwk`, `Jwks`, `Pkce`, `Par` when used in type names,
  and wire names such as `request_uri`, `id_token`, `jwks_uri` in docs/spec comments.
- Long generated/config names are acceptable when they mirror official metadata names or prevent ambiguity between
  Token Endpoint, Introspection Endpoint, UserInfo Endpoint, and Authorization Endpoint.
- Avoid generic method names such as `create` for package-private internals when a more specific construction name
  exists (`tokenEndpoint`, `introspectionEndpoint`, `fromStaticConfig`, `fromWellKnownMetadataJson`).
- `OidcProviderMetadata` intentionally keeps long metadata field names such as
  `introspectionEndpointAuthenticationSigningAlgorithmsSupported`; they mirror official metadata names and avoid
  ambiguity between endpoint-specific authentication capabilities.

### CQ-12: Replace overloaded local-authentication result factories with source-specific names

File:

- `OidcLocalAuthenticationResult.java`

Issue:

The type had five overloaded package-private `create(...)` methods. Some existed only to forward default arguments,
and the rest accepted long positional argument lists without telling callers whether the value came from a fresh Token
Endpoint response, a refreshed token set, or a protected local-authentication cookie.

Decision:

Use two construction names:

- `fromTokenResponse(...)` for the authorization-code callback path, where expiration and fallback scope are computed
  from the Token Endpoint response, requested scopes, and configured cookie lifetime.
- `fromStoredValues(...)` for already-materialized local-authentication values, including cookie restore and refresh
  replacement.

Store optional refresh token, scope, userinfo, and access-token expiration as `Optional` fields.

Status:

Done.

Naming rationale:

The names are longer than `create`, but they remove a real ambiguity. `fromTokenResponse` points to protocol data that
still needs interpretation, while `fromStoredValues` points to a fully materialized authentication state being stored
or restored. Adding one more production overload just to hide `Optional.empty()` in tests would recreate the same
delegation problem this audit is removing.

### CQ-13: Trim compact helper indirection and predicate names

Files:

- `OidcHttpResponseValidation.java`
- `OidcRequestObjectSigner.java`
- `OidcIdTokenDecryptor.java`
- `OidcBearerTokenExtractor.java`

Issue:

`OidcHttpResponseValidation.headerValues(...)` wrapped one direct response-header call and was used once. Request-object
and ID-token key selection carried an `Optional<String> keyId` and then unwrapped it more than once. Bearer-token parsing
had a boolean helper named `b64TokenCharacter(...)`, which was short but did not read like a predicate.

Decision:

Inline the one-line header accessor. Resolve present `kid` values into a local `id` before lookup and error-message
construction. Rename the token-character predicate to `validB64TokenCharacter(...)`.

Status:

Done.

Naming rationale:

The `b64` abbreviation is acceptable here because `b64token` is the exact RFC 6750 grammar term. The method still needs
the `valid` predicate prefix so callers can read the condition without opening the helper.

### CQ-14: Remove nullable optional state from response/result values

Files:

- `OidcTokenResponse.java`
- `OidcTokenExchangeResponse.java`
- `OidcTokenErrorResponse.java`
- `OidcTokenEndpointResult.java`
- `OidcPushedAuthorizationRequestResult.java`
- `OidcTokenExchangeResult.java`
- `OidcValidationResult.java`
- `OidcBearerTokenExtractionResult.java`
- `OidcAuthorizationResponseResult.java`

Issue:

Several immutable internal values had fields such as optional token response payloads, error descriptions, causes,
refresh tokens, scopes, and authorization response details stored as nullable references. Getters converted them to
`Optional`, but the object invariant still allowed hidden null state.

Decision:

Store optional values as `Optional` fields internally and keep status-specific factories responsible for setting the
valid combinations. Public/package-private getters keep the same shape.

Status:

Done.

Rationale:

These are immutable value/result objects. Optional fields are appropriate here because absence is part of the protocol
state, and the result factories remain the place where status combinations are enforced.

### CQ-15: Remove pure validated-introspection factory

File:

- `OidcValidatedIntrospection.java`

Issue:

`OidcValidatedIntrospection.create(rawToken, claims)` only returned `new OidcValidatedIntrospection(rawToken, claims)`.
The type is package-private and the factory did not express a special construction mode.

Decision:

Make the constructor package-private and call it directly.

Status:

Done.

### CQ-16: Remove pure internal collaborator factories

Files:

- `OidcAuthenticationRequestFactory.java`
- `OidcRefreshTokenManager.java`
- `OidcAuthenticationOrchestrator.java`

Issue:

`OidcAuthenticationRequestFactory.create()` only constructed a default `SecureRandom`, and
`OidcRefreshTokenManager.create(...)` only supplied a default `OidcIdTokenValidator`. Both methods were package-private
and had single production callers.

Decision:

Use package-private constructors for these small internal collaborators. Keep `OidcAuthenticationOrchestrator.create(...)`
because it assembles the runtime collaborator graph and remains the provider entry point for authentication wiring.

Status:

Done.

### CQ-17: Remove pure handler factories and nullable flow helper state

Files:

- `OidcAuthorizationResponseProcessor.java`
- `OidcLogoutHandler.java`
- `OidcFeature.java`
- `OidcUserInfoSupport.java`

Issue:

The callback processor and logout handler exposed package-private `create(...)` methods that only delegated to
constructors. The callback processor's `ParameterValue` and UserInfo `Result` helpers also encoded invalid/failure state
with nullable strings.

Decision:

Use package-private constructors for the handlers. Store helper absence/failure state as `Optional` values and enforce
non-null optionals in compact constructors.

Status:

Done.

### CQ-18: Align endpoint-level outbound policy API with documented usage

Files:

- `OidcOutboundPolicy.java`
- `OidcOutboundOrchestrator.java`
- `security/providers/oidc-next/README.md`

Issue:

The README describes endpoint-level `OidcOutboundPolicy`, and the provider looks for it in `EndpointConfig`, but the type
and its factories were package-private. The no-arg `tokenPropagation()` factory also produced a policy with audience
validation enabled and no expected audience, which could never propagate a token when a subject was present.

Decision:

Make `OidcOutboundPolicy` public and expose only intentional endpoint-level factories. Audience-validated Token
Propagation now requires an audience through `tokenPropagation(String)`. The no-audience form is explicitly named
`tokenPropagationWithoutAudienceValidation()`. Optional outbound policy fields are stored as `Optional` internally.

Status:

Done.

Naming rationale:

The longer `tokenPropagationWithoutAudienceValidation()` name is deliberate. It makes the weaker security mode visible at
the call site and matches the configured warning path for `audience-validation-enabled=false`.

### CQ-19: Remove remaining pure request/outbound factories

Files:

- `OidcRequestContext.java`
- `OidcAuthenticationOrchestrator.java`
- `OidcOutboundOrchestrator.java`
- `OidcProvider.java`
- `OidcTenantLifecycleTest.java`

Issue:

`OidcRequestContext.create(...)` and `OidcOutboundOrchestrator.create(...)` only delegated to internal constructors.

Decision:

Use package-private constructors directly. Keep public `OidcProvider.create(...)` and `OidcFeature.create(...)`
factories, because those are the documented runtime entry points.

Status:

Done.

### CQ-20: Remove pure tenant resolver factory

Files:

- `OidcTenantResolver.java`
- `OidcTenantRuntimeRegistry.java`

Issue:

`OidcTenantResolver.create(config)` only returned `new OidcTenantResolver(config)`.

Decision:

Make the constructor package-private and use it directly from `OidcTenantRuntimeRegistry`.

Status:

Done.

### CQ-21: Keep text-backed endpoint enums independent from generated enum string validation

File:

- `OidcEndpointPolicyConfigBlueprint.java`

Issue:

After replacing enum `toString()` with explicit `text()`, generated `@Option.AllowedValue` validation compared direct
Java enum values as `BEARER_TOKEN`, `AUTHENTICATION_COOKIE`, and `UNAUTHORIZED` against config text values such as
`bearer-token`, `authentication-cookie`, and `unauthorized`.

Decision:

Remove the generated allowed-value annotations for these two endpoint-policy options. The enum mappers continue to cover
config text parsing, and `EndpointPolicyDecorator` continues to validate contextual support and duplicates.

Status:

Done.

## Reviewed And Kept As-Is

### `OidcRequestObjectConfigSupport`

Decision:

Keep for now.

Rationale:

The helper is tiny, but it adds a user-facing generated builder method that lets users configure a `ResourceConfig`
through a consumer while preserving URI rejection before building the resource. This is API ergonomics rather than only
an internal one-line wrapper.

### Protocol result types

Files:

- `OidcTokenEndpointResult`
- `OidcPushedAuthorizationRequestResult`
- `OidcTokenExchangeResult`
- `OidcValidationResult`
- `OidcBearerTokenExtractionResult`

Decision:

Keep separate result types.

Rationale:

They encode different protocol states and keep endpoint/user-facing error handling type-specific. A generic result type
would reduce local clarity and force more ambiguous names.

### `OidcEndpointClient.submit`

Decision:

Keep the generic token endpoint submit path.

Rationale:

It removes duplicated WebClient setup, client authentication, response validation, token error parsing, and exception
handling across authorization-code, refresh-token, client-credentials, and token-exchange requests while still returning
specific result types.

### `OidcConfigSupport`

Decision:

Split and remove the generic support class.

Rationale:

The class had become a mixed bucket for builder decorators, root-tenant folding, URI validation, endpoint-policy
resolution, WebClient defaulting, resource indicator validation, and client-auth validation. Splitting it along those
real ownership boundaries improves names and reviewability without scattering individual one-line helpers. Spec quotes
were moved with the validation code they justify.

### JSON parsing helpers in token responses

Files:

- `OidcTokenResponse`
- `OidcTokenExchangeResponse`

Decision:

Keep local duplication.

Rationale:

The helper logic is similar but the failure messages and required fields are protocol-specific. Extracting a shared JSON
helper would create another type for small duplication and make the protocol parsers less direct.

## Residual Notes

- `OidcTenantConfigDecorator` is intentionally still the largest extracted validator because tenant-level feature
  validation is the real owner for authorization-code, UserInfo, logout, protected-resource, and subject-mapping config
  rules. Further splitting should happen only if a feature sub-area develops independent lifecycle or reuse pressure.
- Claim-path extraction appears in subject mapping, scope validation, and UserInfo mapped storage. A shared helper type
  was not added in this pass; the duplication is small and extracting it now would create another abstraction without a
  clear user-facing or correctness gain.
- `OidcTenantContext.ready(...)` convenience factories remain. They name tenant state directly and are used heavily by
  tests; unlike the removed `create(...)` wrappers, they model tenant lifecycle states rather than hiding `new`.

## Validation

Latest validation:

- `mvn -B -q -f security/providers/pom.xml -pl oidc-next test` passed.
- `git diff --check` passed.
- Long-line scan over provider production sources and touched tests found one existing long string line in
  `OidcAuthorizationResponseProcessorTest`; no touched production source long lines were reported.
