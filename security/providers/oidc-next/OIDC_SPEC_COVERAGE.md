# OIDC specification coverage

Assessment period: 2026-09-23–2026-09-25. Implementation baseline: `e015f55ebe74d68032f3af20adacff7683c5d689`.

This document maps OIDC features to the built-in `oidc-next` implementation. It describes capabilities, limitations,
and possible reasons for exclusions, not certification or blanket conformance. An optional feature being absent is not,
by itself, a specification violation. Application-written integrations are not counted as built-in support.

All eight supplied OIDC specifications have been assessed individually, with incremental saves. The 227 entries
distinguish built-in support, reusable primitives, missing features, scope choices and OP-only responsibilities.

## Scope and status

The initial inventory follows the eight directly OIDC-related specifications supplied in `oidc-specs/`. Standalone
JWT/JWS/JWE/JWK specifications and general OAuth specifications/profiles are not coverage entries here. Cryptographic
handling is discussed only where it is part of an OIDC feature, such as ID Tokens or Request Objects. Companion
response-mode specifications are distinct from Core; a Core assessment does not imply their implementation.

| Specification | Assessment result |
| --- | --- |
| OpenID Connect Core 1.0, errata set 2 | Assessment complete: 44 feature/role/policy entries below; implementation is intentionally a subset. |
| OpenID Connect Discovery 1.0, errata set 2 | Assessment complete: 26 entries, including all 35 section-3 metadata names. |
| OpenID Connect Dynamic Client Registration 1.0, errata set 2 | Assessment complete: 26 entries map all 30 client-metadata and six response fields; no dynamic protocol client. |
| OpenID Connect Session Management 1.0 | Assessment complete: 14 entries; no browser-monitoring protocol, with adjacent local session behavior distinguished. |
| OpenID Connect RP-Initiated Logout 1.0 | Assessment complete: 22 entries; all six request parameters and both metadata fields, with application/OP duties separated. |
| OpenID Connect Front-Channel Logout 1.0 | Assessment complete: 16 entries; no receiver; four metadata fields, both query parameters and session-claim role mapped. |
| OpenID Connect Back-Channel Logout 1.0, errata set 1 | Assessment complete: 30 entries; no receiver/session invalidation; complete field inventory and all 11 validation steps mapped. |
| OpenID Connect Client-Initiated Backchannel Authentication Flow - Core 1.0 (CIBA) | Assessment complete: 49 entries; no client mode implemented; complete request/result/error inventory and role boundaries mapped. |

Status meanings:

- **Implemented:** built-in handling exists for the stated feature, with any restrictions stated explicitly.
- **Partial:** only a subset, transport mechanism, or application-assisted portion is available.
- **Missing:** no built-in implementation was found. This does not mean Helidon cannot support it.
- **Deliberately excluded:** the documented scope or explicit code guard excludes it.
- **Outside the component's role:** an OP/issuer responsibility, not a missing RP capability.
- **Not consumed:** a metadata field is ignored; this is not a verdict that the underlying advertised feature is absent.
- **Static counterpart only:** local configuration/runtime behavior relates to a registration setting, but no registration exchange is performed.

Reasons attributed to the implementation must have source evidence. Other architectural observations are labelled as
assessment, not as a recorded project decision. Nothing here claims a missing feature is technically impossible merely
because this provider does not implement it.

## Overview for reuse and planning

- Implemented RP foundations include code-flow login, selected ID Token/UserInfo/Request Object protection profiles,
  local cookie sessions and refresh, selected Discovery metadata handling, and the main RP-Initiated Logout path.
  The per-feature restrictions and application responsibilities below still apply.
- Partial areas include Discovery beyond issuer-based configuration loading and several Core hint, freshness,
  assurance and individual/external-claim features. A value that can be carried manually is not necessarily a validated,
  first-class feature. Local configuration is not an OP registration exchange.
- Missing protocol clients/workflows include Dynamic Client Registration, Session Management browser monitoring,
  Front-Channel/Back-Channel logout notification reception and CIBA. The missing integration is described per spec;
  existing HTTP, JOSE, token/error parsing and cookie helpers are not counted as complete implementations.
- Recorded scope choices and explicit code guards include code-only browser login and selected algorithm/transport
  profiles. These are distinguished from specification prohibitions, such as CIBA Core's unsupported encrypted
  authentication-request JWTs. Missing optional functionality is not automatically a conformance or security defect.
- OP token issuance, authentication/consent services, logout fan-out and CIBA authentication-device interaction are
  outside this RP component's role. Helidon applications could host such services separately; this is not a limitation
  of the framework's ability to serve HTTP or perform cryptography.

Assessment: several absent RP features are feasible extensions, but some need explicit application/browser or
transaction/session-state integration. Reuse the existing primitives without assuming that a different protocol's
complete message or lifecycle contract is interchangeable. This is an inventory of the eight supplied specifications,
not a claim to cover every OIDC-related extension or certify any deployment.

## 1. OpenID Connect Core 1.0

Source: [Core 1.0 incorporating errata set 2](https://openid.net/specs/openid-connect-core-1_0.html), matching the supplied
`oidc-specs/openid-connect-core-1_0.html` (15 December 2023). Code and tests, rather than the README alone, determine
implementation status.

Core describes authentication flows, ID Tokens, end-user claims and UserInfo, Request Objects, client authentication,
offline access, refresh, subject identifiers, and the self-issued model. This provider acts as a server-side Relying
Party (RP). Its Helidon name `OidcProvider` does **not** mean it is an OpenID Provider (OP).

[Core section 15.4](https://openid.net/specs/openid-connect-core-1_0.html#RPMTI) makes the distinction between selecting
RP features and satisfying the requirements of the features selected. Not implementing every optional flow/extension
does not by itself make a code-flow RP nonconformant.

At a glance: code-flow login, signed/encrypted ID Tokens, JSON/protected UserInfo, signed Request Objects, the named
Core client-authentication methods, and browser-session refresh are covered. Important gaps include first-class
hints/locales, freshness/assurance/individual-claim request policy, third-party initiation, external claim sources, and
the self-issued RP model. OP responsibilities and deliberately unimplemented flows are separated from these gaps.

### Authentication role and flows

| ID / Core feature | What the feature provides | Current support and evidence | Gap or exclusion rationale |
| --- | --- | --- | --- |
| C-01 — OP role; sections 1, 3.1.2.2–4, 3.1.3.2, 15.1–2 | Authenticate users, obtain consent, issue tokens, and serve OP endpoints. | **Outside the component's role.** OIDC-next consumes an external OP. [README: supported standards boundary](README.md#supported-standards-boundary). | An OP implementation would be a separate identity-server product/concern. This is not a technical claim that a Helidon application could never host one. |
| C-02 — Code-flow request; sections 3.1, 3.1.2.1 | Start browser authentication using an authorization code. | **Implemented.** Builds `response_type=code`, client ID, callback URI, `openid` scopes, state, and nonce. [Request factory], [authorization configuration], [provider tests]. | The flow is deliberately fixed to code; token redemption and validation are assessed separately below. |
| C-03 — Implicit Flow; section 3.2 | Return identity/access tokens through the browser. | **Deliberately excluded.** README explicitly excludes Implicit Flow; the request factory emits only `code`. [Request factory], [README](README.md#supported-standards-boundary). | Assessment: a server-side RP can redeem a code through its back channel. Supporting another flow is technically possible, but is outside the chosen implementation scope; Core itself defines this flow. |
| C-04 — Hybrid Flow; section 3.3 | Combine a code with front-channel ID/access tokens. | **Deliberately excluded.** No hybrid response-type selection or front-channel token-processing path. [Request factory], [README](README.md#supported-standards-boundary). | Same documented code-only boundary. Not inherently impossible or nonsensical for Helidon; a concrete integration requirement would be needed to justify implementing it. |
| C-05 — Authentication Request transport; sections 3.1.2.1, 13 | Convey the request to the OP. | **Implemented subset.** Ordinary login redirects the browser to an authorization URI. The factory also supports secured requests/PAR, assessed separately. [Request factory]. | No built-in HTML form POST to the Authorization Endpoint. Core lets an RP choose GET or POST; this is not an RP requirement to implement both. This is separate from accepting a `form_post` response. |
| C-06 — State and nonce creation; sections 3.1.2.1, 15.5.2 | Bind the login transaction and subsequent identity response. | **Implemented.** Random state/nonce, expected issuer, callback URI, and expiry are retained in protected request state. [Request factory: create], [provider tests]. | Callback and token-side checks are assessed separately; generating a nonce alone is not the entire feature. |

### Authentication Request options and callback

Spec references: [Authentication Request](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest),
[third-party initiation](https://openid.net/specs/openid-connect-core-1_0.html#ThirdPartyInitiatedLogin),
[response validation](https://openid.net/specs/openid-connect-core-1_0.html#AuthResponseValidation), and
[Token Response](https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse).

| ID / Core feature | What the feature provides | Current support and evidence | Gap or exclusion rationale |
| --- | --- | --- | --- |
| C-07 — Scopes; sections 3.1.2.1, 5.4 | Request identity and profile claim groups. | **Implemented.** Configurable scopes, `openid` required, including ordinary `profile`, `email`, `address`, and `phone` requests. [Authorization configuration], [tenant validation], [request factory]. | The OP decides which requested claims to release. Requesting a scope is not a guarantee that all corresponding claims will appear. |
| C-08 — `prompt`; section 3.1.2.1 | Ask for login, consent, account selection, or non-interactive OP processing. | **Implemented parameter handling.** Configured prompt values are serialized; duplicates, invalid tokens, and combining `none` with other prompts are rejected. [Tenant validation: validateAuthorizationCodePrompts], [provider tests]. | This is an initiation-time tenant setting, not a built-in per-request step-up API or iframe silent-login manager. OP errors terminate the callback with a generic HTTP 400; there is no automatic interactive retry. |
| C-09 — `display`, `ui_locales`, `login_hint`, authentication `id_token_hint`; section 3.1.2.1 | Customize the OP UI and identify a likely user/session. | **Partial/manual transport only.** No dedicated configuration or dynamic per-login option exists in the request builder. It preserves preconfigured Authorization Endpoint query text. [Authorization configuration], [request factory: authorizationUri], [code exchange tests: endpoint query preservation]. | Static URL parameters are not first-class feature handling, and are not automatically included in a signed Request Object or PAR payload. Useful server-side RP features; no evidence that they were rejected as unsuitable for Helidon. Logout `id_token_hint` is a separate feature, not authentication-hint support. |
| C-10 — Response mode; sections 3.1.2.1, 3.1.2.5 | Return authorization response parameters to the RP. | **Implemented default code/query path only.** The request omits `response_mode`; the feature registers GET callbacks and reads query parameters. [HTTP feature], [callback processor]. | No built-in form-body callback or fragment-token handling, and no response-mode selector. Query is sufficient for the implemented default code flow; companion response-mode specifications are not thereby covered. |
| C-11 — Third-party-initiated login; section 4 | Accept an external login-initiation request naming an OP and optional return target/hint. | **Missing.** No `initiate_login_uri` handler or processing of initiation `iss`, `login_hint`, and `target_link_uri`. The configured callback is a response endpoint, not an initiation endpoint. [HTTP feature: setup], [request factory]. | Feasible and potentially useful for enterprise application launchers. It would need trusted issuer selection and safe target handling; absence is not a Helidon platform limitation. Ordinary navigation to a protected page is not the complete section 4 protocol. |
| C-12 — Callback validation and authorization errors; sections 3.1.2.6–7 | Correlate the OP reply and handle success/error. | **Implemented.** Matches protected request state, tenant, issuer policy, expiry and callback URI; accepts a code or an error, clears verified request state, and does not redeem a code for an error reply. [Callback processor], [callback tests], [HTTP feature]. | Built-in error UX is generic rather than a structured application callback for every `login_required`/`consent_required` case. No claim is made here of a global server-side replay ledger; this is the cookie-backed transaction design. |
| C-13 — Code redemption / Token Response; sections 3.1.3.1–5 | Redeem the code and obtain identity/access/refresh credentials. | **Implemented Bearer-token path.** Posts the code, original redirect URI and PKCE verifier where configured; requires the initial ID Token, access token and supported token type, parses token errors, then validates identity before storing a local session. [Endpoint client], [token response], [HTTP feature], [code exchange tests]. | Negotiating other access-token types is not implemented. This is the selected Bearer profile, not an OP token-issuance implementation. |

### ID Tokens and authentication policy

Spec references: [ID Token](https://openid.net/specs/openid-connect-core-1_0.html#IDToken),
[ID Token validation](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation), and
[code-flow access-token validation](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowTokenValidation).

| ID / Core feature | What the feature provides | Current support and evidence | Gap or exclusion rationale |
| --- | --- | --- | --- |
| C-14 — Basic signed ID Token validation; sections 2, 3.1.3.7 | Verify the identity assertion and its intended RP. | **Implemented for the configured signed profile.** Issuer, client audience, subject, expiration, issue time, optional not-before, configured clock skew, signature and allowed algorithm are checked. `RS256` is the default. [ID Token validator], [ID Token configuration], [ID Token tests]. | This does not imply every optional ID Token claim or signing algorithm is supported; the following rows state important boundaries. |
| C-15 — Additional audiences / `azp`; section 3.1.3.7 | Restrict which client(s) may rely on the assertion. | **Implemented, with a stricter local policy.** Extra audiences require explicit trust; multiple audiences require `azp`; any present `azp` must equal the client ID. [ID Token validator: validateAudience], [ID Token tests]. | Core errata set 2 does not universally require `azp` merely because `aud` has several values. This is an interoperability restriction of the implementation, not a universal Core MUST. |
| C-16 — Returned nonce; sections 3.1.3.7, 15.5.2 | Bind the ID Token to the initiating transaction. | **Implemented.** The initial token must contain the exact nonce retained in protected request state. Missing/mismatched nonce is rejected. [ID Token validator: validateNonce], [ID Token tests]. | Refresh has its own nonce rules; see the refresh assessment below. |
| C-17 — Unsigned ID Tokens / TLS-only validation shortcut; sections 2, 3.1.3.7 | Permit narrowly negotiated code-flow alternatives to normal signature verification. | **Deliberately excluded.** `none` is rejected in configuration and token validation; signatures are always verified, including tokens received directly from the Token Endpoint. [Tenant validation: validateIdToken], [ID Token validator]. | A stricter local trust policy. Core permits specific negotiated/transport-based alternatives; do not describe this restriction as Core banning every such alternative. |
| C-18 — MAC-based ID Tokens (`HS*`); section 3.1.3.7 | Validate an ID Token using the RP's client secret. | **Deliberately excluded by configuration.** `HS*` ID Token algorithms are rejected; the ID Token verification path uses OP public keys. [Tenant validation: validateIdToken], [ID Token validator], [configuration tests]. | The required client-secret MAC-validation path is not implemented. Technically feasible if needed; this is not a Core prohibition. Support for `client_secret_jwt` client authentication is a different feature. |
| C-19 — Encrypted ID Tokens; sections 2, 3.1.3.7, 10.2 | Keep the identity assertion confidential to the RP. | **Implemented subset.** Decrypts a signed-then-encrypted ID Token using explicit local RP private keys, then applies signed-token validation; encryption can be required. Supported key management is RSA-OAEP/RSA-OAEP-256; content encryption is configurable among supported AES modes. [ID Token decryptor], [ID Token configuration], [ID Token tests], [encryption configuration tests]. | No universal encryption-suite support or automatic RP private-key provisioning. Core's encrypted ID Token format is nested; encryption-only UserInfo is a separate supported feature (C-24). The OP's public keys are not a source of the RP private key. |
| C-20 — `max_age` / initial `auth_time` freshness policy; sections 3.1.2.1, 3.1.3.7 | Limit how long ago the OP authenticated the user. | **Missing end-to-end handling.** No request option or retained maximum-age policy, and no initial ID Token `auth_time` freshness check/re-authentication decision. [Authorization configuration], [ID Token validator: claimValidator]. | Useful and feasible for sensitive operations; not intrinsically unsuitable for Helidon. Putting `max_age` in a static endpoint URL does not implement RP-side enforcement. Refresh-time `auth_time` consistency is separate. |
| C-21 — Requested assurance (`acr`) / authentication methods (`amr`); sections 2, 3.1.2.1, 3.1.3.7, 5.5.1.1 | Request and interpret the strength/method of authentication. | **Missing built-in request-and-enforcement policy.** No `acr_values` or Essential-ACR request API, no expected ACR value in transaction state, and no dedicated ACR/AMR acceptance policy. [Request factory], [ID Token validator: claimValidator]. | Feasible step-up/assurance functionality. Meaning and acceptable values require application/provider policy; merely receiving a claim does not mean MFA or a particular assurance level has been enforced. |
| C-22 — Code-flow `at_hash`; section 3.1.3.8 | Optionally bind the returned access token to the ID Token. | **Missing optional check.** The ID Token validator receives no access-token value and does not verify `at_hash`; the callback uses the token response after identity validation. [ID Token validator], [HTTP feature: processTokenEndpointExchange]. | Core makes this check optional for Code Flow. Not a proven protocol defect. Mandatory front-channel token/code hash rules from other flows must not be used to claim those flows are supported. |

### UserInfo, claims, and identity

Spec references: [UserInfo](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo),
[individual claim requests](https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter),
[claim representations](https://openid.net/specs/openid-connect-core-1_0.html#ClaimTypes),
[claim uniqueness](https://openid.net/specs/openid-connect-core-1_0.html#ClaimStability), and
[subject identifier types](https://openid.net/specs/openid-connect-core-1_0.html#SubjectIDTypes).

| ID / Core feature | What the feature provides | Current support and evidence | Gap or exclusion rationale |
| --- | --- | --- | --- |
| C-23 — JSON UserInfo; sections 5.3.1–4 | Retrieve additional claims about the authenticated user. | **Implemented, opt-in.** GET with the Bearer access token, explicit content-type handling, and exact `sub` comparison with the validated ID Token. Failed/mismatched replies prevent login when UserInfo is enabled. [UserInfo support], [endpoint client: userInfo], [feature route tests]. | GET/header transport is the Core-recommended client choice; not implementing client-side POST here is not a missing mandatory RP feature. Error handling is generic, without automatic challenge-driven retries. |
| C-24 — Signed/encrypted UserInfo; sections 5.3.2–4, 10 | Protect UserInfo integrity and/or confidentiality. | **Implemented subset.** Supports signed, encryption-only, and signed-then-encrypted responses according to explicit local registration expectations. Signed replies validate signature, issuer, audience and subject; encryption uses local RP keys. Format/algorithm mismatches fail. [UserInfo JWT processor], [UserInfo JWT validator], [feature route tests]. | Configurable supported asymmetric signing/encryption profiles, not arbitrary algorithms; `HS*` UserInfo signing is rejected. Unlike the selected ID Token profile, encryption-only UserInfo is supported. This is not automatic registration or algorithm negotiation. |
| C-25 — Normal, standard and custom claims; sections 5.1, 5.6.1, 17.1 | Expose profile data, including structured/custom values. | **Implemented data handling.** Claims become principal attributes; configured claim paths drive display name/roles. UserInfo storage defaults to `MAPPED`, with extra paths, `ALL`, or `NONE` available. Core identity/security claims from the ID Token are not overwritten by UserInfo. [Subject mapper], [UserInfo support], [UserInfo configuration], [feature route tests]. | The OP supplies claim meaning/content; this is not independent verification of each profile value. UserInfo minimization does not mean every ID Token claim is discarded from the protected local session. |
| C-26 — `claims` request parameter / Essential and value-constrained claims; section 5.5 | Request particular claims in UserInfo or the ID Token. | **Missing first-class/end-to-end handling.** No request builder option for the JSON `claims` object, Essential/Voluntary selections, or requested `value`/`values` constraints. Scope-based requests are supported instead. [Authorization configuration], [request factory]. | Potentially useful and technically feasible; not a Helidon limitation. Static endpoint-query text is not a supported claims-policy/transaction-validation API. A requested claim is not automatically an application authorization condition. |
| C-27 — Aggregated / Distributed Claims; section 5.6.2 | Consume claims asserted by another Claims Provider, embedded or referenced. | **Missing.** No `_claim_names`/`_claim_sources` resolution, embedded Claims Provider assertion verification, or distributed-claim endpoint retrieval. Ordinary JSON may retain these members as data; it does not interpret them. [UserInfo support], [subject mapper]. | Core makes these claim forms optional. Assessment: implementation would need additional issuer trust, validation and safe retrieval policy; useful for some integrations, not inherently impossible on a server. |
| C-28 — Languages/scripts and `claims_locales`; sections 5.2, 5.5.2 | Request and consume localized claim variants. | **Partial data handling.** Generic claim storage and exact claim-path selection can retain/select language-tagged names. No automatic locale negotiation/fallback or first-class `claims_locales` request option. [UserInfo support: mappedUserInfo], [subject mapper], [authorization configuration]. | Application-specific presentation policy is reasonable, but the protocol request option is still an implementable gap. Do not count opaque retention as a complete localization feature. |
| C-29 — Public/pairwise subjects and stable identity; sections 5.7, 8 | Identify users without assuming globally unique usernames. | **Implemented RP consumption.** Treats the OP's `sub` as an opaque value and derives the local browser identity from issuer plus subject, separately from display-name mapping. Public and pairwise values require no distinct RP-side generation algorithm. [Subject mapper: localIdentity], [subject mapper tests]. | Pairwise-ID generation, sector-identifier management, and preventing OP-side correlation are OP responsibilities. Automatically linking accounts across issuers/pairwise subjects is not implemented or implied. |

### Request Objects and client authentication

Spec references: [Request Objects](https://openid.net/specs/openid-connect-core-1_0.html#JWTRequests) and
[client authentication](https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication).

| ID / Core feature | What the feature provides | Current support and evidence | Gap or exclusion rationale |
| --- | --- | --- | --- |
| C-30 — By-value signed/encrypted Request Objects; sections 6.1, 6.1.1, 10 | Protect the authentication request before it reaches the OP. | **Implemented signed subset.** Sends generated request parameters in `request`, signed with a configured client RSA/EC private key and optionally encrypted with an OP RSA public key. Required outer code/client/scope parameters are retained for the ordinary by-value redirect. [Request Object processor], [request factory], [code exchange tests]. | Explicit local keys/configuration and the OP's corresponding registration/capability are required. Only parameters the generator actually supports are included; this is not a generic implementation of every optional Core request parameter. |
| C-31 — Unsigned, MAC-based, or encryption-only Request Objects; section 6.1 | Alternative Request Object protection profiles. | **Deliberately excluded by the selected signed-request profile.** No `none`, shared-secret Request Object signing, or encryption without the configured private signing key. [Tenant validation: validateRequestObject], [Request Object processor]. | Core allows broader choices; the implemented path uses the stricter signed JAR-style profile. These alternatives are technically implementable, not all mandated RP capabilities. |
| C-32 — RP-hosted Request Objects via `request_uri`; section 6.2 | Let the OP retrieve a Request Object from a referenced location. | **Deliberately excluded.** No RP-hosted object endpoint/lifecycle or configurable hosted `request_uri`. [README](README.md#supported-use-cases), [request factory], [Request Object configuration]. | PAR's returned `request_uri` is supported as a separate mechanism but does not implement this Core-hosted-object feature. Assessment: hosting requires retrieval/lifetime/publication handling; it could be useful for particular OP integrations, not impossible for Helidon. |
| C-33 — Token Endpoint authentication methods; section 9 | Authenticate a confidential RP, or identify a public client. | **Implemented for all named Core methods.** `client_secret_basic`, `client_secret_post`, `client_secret_jwt`, `private_key_jwt`, and `none`. Basic credentials are form-encoded; assertions use client ID issuer/subject, Token Endpoint audience, fresh identifier and expiry. [Client authentication], [authentication methods], [code exchange tests]. | Client-secret assertions support HS256/384/512; private-key assertions support the implemented RSA/EC algorithm set. This does not imply arbitrary future algorithms. Public clients additionally require S256 PKCE under local configuration policy; that is not a rule invented by Core section 9. |
| C-34 — Client credentials / registration ownership; sections 9, 10, 15.3 | Associate the RP with its identifier, credentials and negotiated settings. | **Implemented with externally provisioned registration.** Client ID/secret, private assertion/request-signing keys, and response protection expectations are supplied through configuration. [Client authentication], [authorization configuration], [ID Token configuration]. | The provider does not itself become a registration server or OP. Automated Dynamic Client Registration is a separate specification and is intentionally left for its own assessment, not claimed by these configuration options. |

### Offline access and refresh

Spec references: [offline access](https://openid.net/specs/openid-connect-core-1_0.html#OfflineAccess) and
[refresh responses](https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse).

| ID / Core feature | What the feature provides | Current support and evidence | Gap or exclusion rationale |
| --- | --- | --- | --- |
| C-35 — `offline_access` request; section 11 | Request refresh capability with appropriate consent. | **Implemented request handling.** Accepts the scope, adds `prompt=consent` when absent, and rejects incompatible `prompt=none`. Refresh tokens are retained in the protected browser session when issued. [Request factory: prompts], [tenant validation], [provider tests]. | Always adding consent is a conservative local choice; Core also recognizes other conditions permitting offline access. The implementation does not model an exemption for those conditions. The OP, not the RP, decides whether to issue a refresh token. |
| C-36 — Refresh request/rotation/errors; sections 12.1–3 | Obtain replacement access credentials without a new authentication request. | **Implemented for the active local session.** Posts `refresh_token` with the configured client authentication, retains/replaces rotated refresh tokens, preserves omitted scope/refresh-token values, and handles failures. Enabled UserInfo is fetched again. Concurrent refreshes share coordinated work. [Refresh manager], [endpoint client], [refresh tests]. | Renewal is request-driven, not a background offline job/vault API. It needs known access-token expiry; successful renewal currently requires `expires_in`. There is no dedicated scope-subset selector for refresh requests. |
| C-37 — Refreshed ID Tokens; section 12.2 | Maintain identity continuity when the OP returns a new ID Token. | **Implemented with conservative continuity checks.** ID Token omission is allowed. A returned token is validated, keeps issuer/subject/audience, and must preserve any returned nonce/authentication time; `azp` is also kept stable. [ID Token validator: validateRefresh], [refresh manager], [refresh tests]. | `azp` stability is imposed uniformly by local policy; Core describes extension-dependent rules. A newly introduced `auth_time` cannot be matched when the stored token lacked it and is rejected. These restrictions should be considered when integrating an OP. |
| C-38 — Local session lifetime versus offline token lifetime; sections 11–12 | Decide how long the RP remains logged in and retains usable credentials. | **Partial offline-use scope / explicit local lifetime policy.** Initial local expiry is capped by both configured session lifetime and initial ID Token expiry. Refresh does not extend that original deadline; expired local state is not recovered merely because a refresh token might still work. [Local authentication result], [refresh manager], [cookie state handler], [refresh tests]. | This is not a Core requirement to tie all RP sessions to ID Token expiry. Indefinite sliding login or durable background access would need a different credential/session lifecycle; technically possible in Helidon, but not supplied by this cookie-backed flow. |

### Keys, self-issued identities, and deployment boundaries

Spec references: [signatures/encryption](https://openid.net/specs/openid-connect-core-1_0.html#SigEnc),
[self-issued OP](https://openid.net/specs/openid-connect-core-1_0.html#SelfIssued),
[serializations](https://openid.net/specs/openid-connect-core-1_0.html#Serializations),
[string comparisons](https://openid.net/specs/openid-connect-core-1_0.html#StringOps), and
[TLS](https://openid.net/specs/openid-connect-core-1_0.html#TLSRequirements).

| ID / Core feature | What the feature provides | Current support and evidence | Gap or exclusion rationale |
| --- | --- | --- | --- |
| C-39 — OP public keys / rotation; sections 10.1–2 | Follow the OP's signing/encryption key changes. | **Implemented with configurable cache policy.** OP key loading, key-ID selection, unknown-key refresh and optional interval-based lazy refresh; used for identity/UserInfo signature verification and Request Object encryption. [OP key manager], [OP key configuration], [shared key-refresh tests]. | Refresh is not unconditional on every request. Throttling, retry and stale-on-error policies affect behavior; no promise of immediate revocation detection or a background refresh daemon. |
| C-40 — RP private keys and their public distribution; sections 10.1–2 | Supply client signing/decryption keys and make corresponding public keys available to the OP. | **Partial / operator-managed.** Explicit local private keys and multi-key decryption sets are supported. Assertion/request-signing keys and decryption sets are loaded into their consumer instances. No built-in RP JWKS publication endpoint or automatic private-key hot reload. [Client authentication], [Request Object processor], [JWE decryptor], [HTTP feature: setup]. | The application/deployment owns public-key registration/publication and coordinated rotation. Serving a JWKS is feasible in Helidon, but not necessary for every registration method; do not treat the absence of an SDK-hosted endpoint as universal nonconformance. |
| C-41 — Core's self-issued model; section 7 | Rely on a personal/self-issued OP rather than a conventional issuer. | **Missing RP mode.** No `openid:` initiation, ID-Token-only response flow, `sub_jwk` trust/thumbprint validation, or self-issued redirect-URI audience rules. Ordinary issuer/JWKS/client-ID validation is not a substitute. [Request factory], [ID Token validator], [endpoint URI validation]. | This is a distinct optional integration. It is technically possible for a Helidon application, but is not the implemented code-flow RP model. Acting as the self-issued OP itself is also outside this component's role. This row does not assess newer wallet/SIOP specifications. |
| C-42 — Native/custom-scheme callbacks; section 3.1.2.1 | Deliver login results into a native application. | **Outside the built-in HTTP integration / missing native adapter.** Callback handling uses WebServer HTTP routes; URI validation accepts HTTPS and explicitly relaxed HTTP, not arbitrary native schemes. [HTTP feature], [endpoint URI validation]. | A native OS callback is not a WebServer request. Helidon can participate in a larger native-login integration, but `none` client authentication does not provide a native-app SDK or deep-link handler. |
| C-43 — Query/form/JSON and exact strings; sections 13–14 | Encode messages and compare identity/protocol values consistently. | **Implemented in the supported flows.** Uses Helidon query/form/JSON facilities; code/token request serialization and exact issuer, audience, nonce and subject comparisons are present. [Request factory], [endpoint client], [ID Token validator], [code exchange tests], [subject mapper tests]. | A form-encoded Token Endpoint request does not mean `form_post` callbacks or every response serialization are supported. This is flow-level coverage, not a separate JSON/JWT specification assessment. |
| C-44 — Transport/security/privacy responsibilities; sections 16–17 | Protect authentication traffic and minimize unnecessary identity exposure. | **Implemented defaults, deployment-dependent coverage.** HTTPS is required by default for configured OP endpoints, TLS is delegated to the configured Helidon WebClient, transaction/session state is protected, and UserInfo retention is selectable. [Endpoint configuration], [WebClient factory], [cookie state handler], [UserInfo support]. | Operators still own TLS trust/proxy deployment, registration, key lifecycle and application data policy. Explicit insecure compatibility/test settings are not evidence of a secure Core deployment. This table is not a complete deployment security or privacy certification. |

### Core overview: what is worth considering next

The implemented center of gravity is a code-flow server-side RP: code redemption, signed/encrypted ID Tokens,
JSON/protected UserInfo, normal claims, signed Request Objects, the named Core client-authentication methods,
browser-session refresh, and OP public-key refresh.

The clearest **potentially useful missing/partial RP features**, rather than OP responsibilities, are:

1. First-class per-login request options and matching policy: hints/locales, `max_age`/`auth_time`, ACR requirements,
   and JSON `claims` requests (C-09, C-20, C-21, C-26, C-28).
2. Third-party-initiated login and more application-friendly interaction-error handling (C-08, C-11, C-12).
3. A different credential/session lifecycle if durable offline access or sliding login is a requirement (C-36–38).
4. Aggregated/distributed claims, hosted Request Objects, and the self-issued model when a concrete integration needs
   those optional capabilities (C-27, C-32, C-41).

Important **compatibility choices to know before choosing an OP** are the asymmetric-only identity/UserInfo signing
profiles, code/query-only response path, extra multi-audience `azp` rule, refresh continuity restrictions, and non-sliding
local session deadline. These are not all Core requirements. Supplying a parameter through an endpoint URL, preserving
an unknown JSON member, or supporting the underlying cryptography does not establish end-to-end feature support.

The strongest **role-based exclusions** are OP login/consent/token issuance and pairwise subject generation. Native OS
callbacks require a different integration layer. None of the optional RP protocol gaps above has been shown to be
intrinsically impossible for Helidon. Architectural observations here are not commitments to implement the features.

Core assessment is complete for this baseline. Further specifications are assessed in separate sections below.

### Assessment method and limits

This is a source-based feature inventory against the supplied Core errata-set-2 text, whose edition was checked against
the official publication. Each entry was saved incrementally with implementation and, where available, regression-test
references. The final pass checked feature distinctions, source paths and specification anchors.

The baseline's existing validation passed 1,558 module tests and 42 synthetic integrations before the BUILD-01 commit.
Those are implementation regressions, not an official OpenID conformance certification or proof of every optional
feature. No production behavior was changed and no new runtime tests were run for this documentation pass. Missing
optional features, stricter interoperability policies, and deployment responsibilities have not been silently promoted
into new security findings. The earlier deferred items remain deferred.

## 2. OpenID Connect Discovery 1.0

Source: [Discovery 1.0 incorporating errata set 2](https://openid.net/specs/openid-connect-discovery-1_0.html), matching
the supplied `oidc-specs/openid-connect-discovery-1_0.html` (15 December 2023). The implementation baseline is unchanged.

Discovery has two distinct parts: locating an issuer from an end-user identifier, and obtaining configuration/capability
metadata for an issuer. This implementation mainly covers the second part. A metadata field being parsed does not
necessarily mean its capability is implemented, selected automatically, or exposed as public configuration.

At a glance: configured-issuer configuration loading, selected endpoint/algorithm compatibility checks, and relevant
metadata defaults are supported. WebFinger issuer discovery and periodic metadata re-discovery are absent. Of the 35
metadata names defined in section 3, 19 are consumed and 16 are not. The tables distinguish those omissions from missing
Core features and OP-only responsibilities; this is not a claim of complete Discovery conformance.

### Starting point, retrieval, and issuer binding

Spec references: [issuer discovery](https://openid.net/specs/openid-connect-discovery-1_0.html#IssuerDiscovery),
[configuration requests](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest),
[configuration responses](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse), and
[validation](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationValidation).

| ID / Discovery feature | What the feature provides | Current support and evidence | Gap or exclusion rationale |
| --- | --- | --- | --- |
| D-01 — Out-of-band issuer selection; sections 2, 4 | Begin discovery with an already known OP. | **Implemented.** The issuer and/or well-known URI come from tenant configuration; tenant routing selects configured tenants. [Discovery metadata model], [tenant resolver]. | Issuer discovery through WebFinger is optional when the issuer is already known. A controlled set of configured enterprise issuers is a legitimate RP model, not a requirement to accept arbitrary user-supplied issuers. |
| D-02 — WebFinger and end-user identifier normalization; sections 2–2.2 | Resolve email-like, URL, host/port or `acct:` input into an issuer. | **Missing.** No end-user discovery form/API, identifier-normalization pipeline, WebFinger request or issuer-link selection. Configuring an issuer URL or selecting a tenant by host is not this protocol. [Discovery metadata model: fromStaticConfig], [tenant resolver]. | Feasible for a server-side RP and useful for open-ended login-by-identifier scenarios. It would need input/trust/network policy. No evidence establishes that Helidon cannot support it, and the spec permits skipping it for known issuers. |
| D-03 — Well-known URL construction; sections 4–4.1 | Locate configuration, including issuers with path components. | **Implemented.** Appends `/.well-known/openid-configuration` after removing trailing slash characters from the configured issuer; preserves its path. An explicit well-known URI takes precedence. [Discovery metadata model: wellKnownUri], [discovery loading tests]. | For example, `https://op.example/tenant` maps to `https://op.example/tenant/.well-known/openid-configuration`. An explicit alternative URL is configuration, not automatic discovery of every other metadata convention. |
| D-04 — Configuration HTTP/JSON response; sections 4.1–4.2 | Retrieve a provider configuration document. | **Implemented with media-type tolerance.** HTTP GET, JSON Accept header, exact HTTP 200 requirement, JSON content-type check, and JSON-object parsing. Automatic redirects are disabled. [Discovery loader], [HTTP response checks], [shared JSON predicate], [discovery loading tests]. | The shared JSON predicate also accepts `+json` suffix types, while Discovery specifies `application/json`; this is receiver tolerance, not an alternative publishing rule for OPs. Successful parsing is not complete metadata conformance validation. |
| D-05 — Issuer and string binding; sections 3, 4.3, 5 | Bind metadata and identity assertions to the expected OP. | **Implemented for an explicitly configured issuer; partial bootstrap boundary.** Loaded metadata must contain an issuer; a configured issuer must match it exactly. ID Token validation subsequently uses that trusted metadata/configured value. [Discovery metadata model: validateWellKnownMetadataIssuer], [ID Token validator], [discovery loading tests]. | With only an explicit well-known URI and no configured issuer, the returned issuer is adopted; there is no independent expected-issuer comparison or derivation from that arbitrary URL. Section 4.3 requires issuer-prefix binding for the standard discovery procedure; this custom URI-only bootstrap does not implement that independent check. Configure the expected issuer for issuer-pinned discovery; do not call the two modes equivalent. |

### Metadata actively used by the implementation

The fields in this table are defined by [Discovery section 3](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata).
Presence checks generally apply to the effective configuration of enabled features, after static/discovered values
have been merged. They are not a complete audit of everything a conforming OP must advertise.

| ID / Discovery metadata | What the fields describe | Current support and evidence | Boundary or rationale |
| --- | --- | --- | --- |
| D-06 — `issuer`, `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint` | OP identity and protocol endpoint locations. | **Implemented consumption.** Endpoints are parsed and used by the configured flows. Code login requires its authorization/token endpoints; enabled UserInfo requires its endpoint. URI helpers check the configured TLS policy and prohibited query/fragment components as appropriate. [Discovery metadata model], [tenant metadata validation], [endpoint URI validation], [discovery loading tests]. | Explicit endpoint overrides can take precedence. Missing an unused endpoint does not necessarily fail initialization. This is selected-role validation, not proof the raw document contains every required OP field. |
| D-07 — `jwks_uri` | OP public verification keys and optional public encryption keys. | **Implemented consumption.** Supplies the OP key manager for ID Token/UserInfo verification and Request Object encryption. Code login needs an effective key source. Provider key sets reject private/symmetric key material. [Tenant metadata validation: validateIdTokenMetadata], [OP key manager], [OP public-key loader], [OP key-source tests]. | This does not provision RP private signing/decryption keys. Public-key caching/rotation has its own policy (C-39); Discovery parsing is not a separate comprehensive certificate/JWK-format conformance certification. |
| D-08 — `response_types_supported`, `grant_types_supported` | Available response types and grants. | **Implemented for the configured grants.** Loaded code-flow metadata must advertise `code`; an omitted grant list uses `authorization_code`/`implicit`, not unrestricted support. Explicit lists are checked for the selected grant, including outbound grants that share this metadata model. [Tenant metadata validation: validateAuthorizationCodeCapabilityMetadata], [discovery loading tests], [token exchange tests]. | Advertising Implicit/Hybrid does not enable those client flows. The default applies to an omitted member of loaded metadata, not a demand that fully static configurations fetch discovery first. |
| D-09 — `token_endpoint_auth_methods_supported`, `token_endpoint_auth_signing_alg_values_supported` | Token Endpoint client-authentication methods and assertion algorithms. | **Implemented compatibility checks.** Method omission defaults to `client_secret_basic`. The configured method must be supported. For JWT client authentication, the validator requires the signing list, rejects `none`, and requires the selected algorithm. [Tenant metadata validation: validateTokenEndpointAuthenticationMetadata], [discovery loading tests]. | The Discovery table marks the signing-list member OPTIONAL; the shared validator imposes a stronger conditional requirement when a JWT method is selected. Do not attribute that condition solely to Discovery. It does not automatically choose/change client authentication or credentials. |
| D-10 — `id_token_signing_alg_values_supported`, `id_token_encryption_alg_values_supported`, `id_token_encryption_enc_values_supported` | OP ID Token protection capabilities. | **Implemented compatibility checks.** Code-flow discovery requires a signing list intersecting the local allowlist. Present encryption lists are checked for an intersection when decryption/encryption-required configuration makes them relevant; omitted optional encryption lists are accepted. [Tenant metadata validation: validateIdTokenMetadata], [tenant metadata validation: validateOptionalIdTokenEncryptionMetadata], [discovery loading tests]. | An advertised algorithm does not enable encryption, provision keys, or perform registration. Runtime acceptance remains governed by local allowlists, not an automatically narrowed metadata intersection. The validator does not independently enforce the OP-wide requirement to advertise RS256 if another configured algorithm matches. |
| D-11 — `userinfo_signing_alg_values_supported`, `userinfo_encryption_alg_values_supported`, `userinfo_encryption_enc_values_supported` | OP UserInfo protection capabilities. | **Implemented when protected UserInfo is configured.** Present lists must contain the locally selected signing/encryption algorithms, including the effective content-encryption default. Missing optional lists are tolerated. [Tenant metadata validation: validateUserInfoMetadata], [discovery loading tests]. | No automatic switch from JSON to protected UserInfo, algorithm negotiation, or client registration. These metadata fields do not themselves enable UserInfo. |
| D-12 — `request_parameter_supported`, `request_object_signing_alg_values_supported`, `request_object_encryption_alg_values_supported`, `request_object_encryption_enc_values_supported` | By-value Request Object support and protection capabilities. | **Implemented for the selected Request Object path.** Without PAR, loaded metadata must set `request_parameter_supported` true; omission is false. Present algorithm lists must contain the configured choices; optional absent algorithm lists are tolerated. [Tenant metadata validation: validateRequestObjectMetadata], [discovery loading tests]. | The `request_parameter_supported` check is not used as a prohibition on the separate PAR transport. Metadata does not add unsigned, hosted, or otherwise unimplemented Request Object features, nor does it change the configured keys/profile. |

### Metadata not consumed

These fields complete the inventory of all 35 metadata names in Discovery section 3. The metadata model has no
corresponding members/parsing for the following 16 names. Lack of a metadata consumer must be distinguished from the
underlying Core feature status and from an OP's obligation to publish a required member.

| ID / Discovery metadata | What the fields describe | Current support and evidence | Boundary or rationale |
| --- | --- | --- | --- |
| D-13 — `registration_endpoint` | Location for automated client registration. | **Not consumed.** No registration endpoint is retained or selected by discovery. [Discovery metadata model]. | Useful if automated registration is added. This entry assesses the metadata field only; the Dynamic Client Registration protocol is the next separate specification. Static client configuration is not automated registration. |
| D-14 — `subject_types_supported` | Public/pairwise subject identifier capabilities. | **Not consumed or validated**, despite being a required OP metadata member. Existing RP handling still accepts opaque public/pairwise subjects (C-29). [Discovery metadata model], [subject mapper]. | The provider has no metadata-driven subject-type selection. It should not be described as validating every required OP advertisement, but ignoring this field is not the same as lacking pairwise-subject consumption. |
| D-15 — `response_modes_supported` | Available ways of returning authorization responses. | **Not consumed.** No advertised-mode compatibility check or mode selection; the client uses its code/query callback path. [Discovery metadata model], [request factory], [HTTP feature]. | Discovery's omitted default for Dynamic OPs is query/fragment; the RP does not implement fragment processing merely because that is an OP default. Supporting other response modes would require the Core/companion transport work described in C-10. |
| D-16 — `scopes_supported`, `claims_supported` | Advertised scopes and potentially available claims. | **Not consumed.** Configured scopes and received claims are handled without using these lists as allowlists. [Discovery metadata model], [authorization configuration], [UserInfo support]. | These lists are not guaranteed exhaustive; rejecting a scope/claim solely because it is absent would be an incorrect assumption. Optional diagnostics/capability display could still be useful. |
| D-17 — `acr_values_supported`, `claims_parameter_supported`, `claim_types_supported` | Assurance values, individual-claims request support, and normal/aggregated/distributed claim forms. | **Not consumed.** No capability-driven ACR/claims request policy or external-claim resolver. [Discovery metadata model], [request factory], [UserInfo support]. | Aligns with the related partial/missing Core features (C-21, C-26, C-27), not a Helidon impossibility. Discovery defaults an omitted claims-parameter flag to false and an omitted claim-type list to normal; no parser/default-selection logic is implemented for these fields. |
| D-18 — `display_values_supported`, `claims_locales_supported`, `ui_locales_supported` | OP UI and claim localization capabilities. | **Not consumed.** No automatic display/language negotiation or metadata API for these lists. [Discovery metadata model], [authorization configuration]. | Would be useful alongside first-class hints/locales or application presentation logic (C-09, C-28). There is no evidence of a deliberate policy that servers must never support them. |
| D-19 — `request_uri_parameter_supported`, `require_request_uri_registration` | Hosted Request Object references and whether they must be registered. | **Not consumed.** RP-hosted Request Objects are outside the implemented profile (C-32). [Discovery metadata model], [Request Object configuration]. | Discovery's omitted defaults are respectively true and false; they are not applied by a hosted-object implementation here. PAR's returned reference is a separate mechanism, not evidence of these Core-hosted-reference capabilities. |
| D-20 — `service_documentation`, `op_policy_uri`, `op_tos_uri` | Operator documentation and registration-time policy/terms links. | **Not consumed/exposed by this metadata model.** [Discovery metadata model]. | Primarily relevant to operator tooling or a registration UI rather than request authentication. Exposing them could be useful, but automatic display/legal acceptance is not a role this runtime component performs. |

### Validation scope, lifecycle, and component responsibilities

Spec references: [metadata extensibility](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata),
[configuration validation](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationValidation),
and [transport/impersonation protection](https://openid.net/specs/openid-connect-discovery-1_0.html#Security).

| ID / Discovery feature | What the feature provides | Current support and evidence | Boundary or rationale |
| --- | --- | --- | --- |
| D-21 — Extensible metadata and validation scope; sections 3–4 | Process useful metadata while allowing additional members. | **Implemented selected-member parsing, not a complete OP schema validator.** Unknown members are ignored rather than retained in a public extension map. Known members are read as their expected JSON types; malformed known optional fields can fail parsing even when the corresponding feature is disabled. [Discovery metadata model: fromWellKnownMetadataJson], [discovery loading tests]. | Required OP advertisements and every OP-wide constraint are not all checked (for example D-14 and the RS256 distinction in D-10). The model also recognizes selected extension metadata, but parsing those fields is not blanket support for every related protocol. |
| D-22 — Static/discovered configuration and overrides; section 4 integration | Combine deployment configuration with learned endpoints/capabilities. | **Implemented, selectively.** Metadata is loaded when a configured use needs missing information; fully configured static paths can avoid discovery. Conventional explicitly configured endpoints win the merge. [Tenant metadata validation: needsWellKnownMetadata], [Discovery metadata model: mergeWellKnownMetadata], [discovery loading tests]. | Merely configuring an issuer or well-known URI does not force a fetch. In particular, optional PAR discovery does not by itself trigger one. Unloaded capability flags cannot influence behavior. Extension-specific endpoint aliases have their own selection rules; a conventional endpoint override is not a universal override of those rules. |
| D-23 — Metadata caching/re-discovery | Keep configuration useful over a long-running RP lifetime. | **Snapshot reuse implemented; periodic re-discovery missing.** Successful tenant metadata, including deferred outbound resolution, is retained for that runtime. There is no metadata refresh interval, conditional-request/ETag strategy, or automatic endpoint/capability re-negotiation in this component. [Tenant runtime registry], [outbound metadata resolver], [Discovery loader]. | Changed discovery endpoints/capabilities require a new runtime to be picked up after successful initialization. JWKS refresh reloads keys at the already selected key URL; it is not discovery refresh. This is an operational limitation, not a claim Discovery prescribes a particular background polling schedule. |
| D-24 — Invalid/unavailable metadata; section 4.3 | Avoid using information that failed validation. | **Implemented for the checks performed.** Loading/parsing failures make initialization unavailable and can be retried on later use after the configured interval. Deterministic issuer/capability validation failures remain failed; rejected data is not silently used as valid metadata. [Discovery loader], [tenant metadata validation], [tenant runtime registry], [discovery loading tests]. | Retry policy is an implementation choice. This does not compensate for fields the parser/validator does not inspect, nor prove that every possible invalid OP document is rejected. |
| D-25 — TLS and retrieval boundaries; sections 3, 7 | Authenticate and protect metadata/key retrieval. | **Implemented defaults with deployment responsibilities.** HTTPS is required by default; the tenant WebClient supplies TLS/trust configuration. Metadata redirects are disabled even when the configured WebClient normally follows redirects. [Endpoint configuration], [WebClient factory], [Discovery loader], [discovery loading tests]. | Operators must preserve certificate verification and trust boundaries. Insecure test/compatibility settings are not fully protected Discovery. A deployment relying on an HTTP redirect must configure the final metadata URL; this is not WebFinger redirect processing. |
| D-26 — OP/WebFinger publication and browser CORS; sections 2–4 | Publish issuer/configuration documents and allow browser clients to access OP services. | **Outside this component's RP role.** OIDC-next consumes configuration; it does not expose an OP discovery document, issuer WebFinger service, or OP endpoint CORS policy. [HTTP feature: setup], [Discovery loader]. | These belong to an OP or separate server/operator tooling. A Helidon application can host such endpoints, but that would be a separate responsibility, not a missing authentication-consumer method. |

Additional metadata understood by the shared model includes PKCE/PAR settings, assertion/endpoint metadata for other
OAuth operations, selected mTLS aliases, authorization-response issuer support, and an end-session endpoint. These
are extensions to the Discovery document, not additional fields defined by Discovery 1.0 section 3. Their complete
protocols are not assessed here. In particular, recognizing a logout endpoint does not establish support for all logout
or session-management specifications, which are assessed separately below.

### Discovery overview: gaps and deliberate boundaries

The useful implemented center is **configuration discovery for known issuers**, with exact issuer matching when an
issuer is configured and compatibility checks for selected operations. Its deliberately static deployment mode and
its metadata-driven mode should not be confused: having a well-known URL available does not guarantee it was loaded.

Potential improvements depend on the intended RP use case:

- **Open-ended issuer selection:** WebFinger and its identifier-normalization/trust workflow, if login-by-identifier is
  required. Controlled-issuer applications need not implement that optional step.
- **Additional capability use:** response-mode/subject-type checks, ACR/claims/localization capability exposure, and
  discovery of a registration endpoint alongside the corresponding runtime features. Scopes/claims advertisements
  should not become falsely exhaustive allowlists.
- **Long-lived configuration:** metadata refresh or an explicit invalidation/reload mechanism for changes to endpoints
  and capabilities. Current key refresh is not sufficient for that purpose.
- **Sharper conformance boundaries:** review the URI-only issuer-bootstrap behavior and selected-field validation
  before making a broader Discovery compliance claim. Not every limitation is merely an absent optional UI feature.

OP-side publication/CORS and displaying registration-time documentation/terms normally belong in other components.
No assessed missing RP feature is intrinsically impossible for Helidon. These observations are a capability inventory,
not new authorized implementation work or a claim that every omission is exploitable.

### Discovery assessment method and limits

All 35 metadata names were extracted from the supplied specification and matched against the parser and feature tables:
19 parsed/consumed, 16 unconsumed, none omitted or duplicated in the field inventory. Sources, existing regression tests,
defaults, role boundaries, and section anchors were cross-checked. The completed Core feature assessments were preserved.
No production changes, new runtime probes, test-suite reruns, or certification checks were performed in this pass.
Existing tests are evidence for the cases they exercise, not proof of every capability or every metadata combination.

Discovery assessment is complete for this baseline. The separate Dynamic Client Registration assessment follows.

## 3. OpenID Connect Dynamic Client Registration 1.0

Source: [Dynamic Client Registration 1.0 incorporating errata set 2](https://openid.net/specs/openid-connect-registration-1_0.html),
matching the supplied `oidc-specs/openid-connect-registration-1_0.html` (15 December 2023). The implementation baseline
is unchanged.

This specification describes sending RP metadata to an OP to obtain a client identifier and optional credentials,
processing the effective registration returned by the OP, and reading the resulting client configuration. OIDC-next
has **no built-in dynamic registration client or registration-read client**. It uses locally provisioned client settings.
It also does not act as the OP's registration server; that is a separate role, not a reason an RP registration client
would be impossible or inappropriate for Helidon.

### Registration protocol and bootstrap

Spec references: [registration endpoint](https://openid.net/specs/openid-connect-registration-1_0.html#ClientRegistration),
[registration request](https://openid.net/specs/openid-connect-registration-1_0.html#RegistrationRequest), and
[registration response](https://openid.net/specs/openid-connect-registration-1_0.html#RegistrationResponse).

| ID / Registration feature | What the feature provides | Current support and evidence | Gap or exclusion rationale |
| --- | --- | --- | --- |
| R-01 — Using an already registered client; sections 1, 8 | Supply the identity/credentials needed for OIDC requests. | **Static counterpart only.** Tenant configuration supplies client ID/secret and client-authentication settings; enabled code flow requires a client ID rather than creating one. [Tenant client settings], [tenant validation]. | Manual/out-of-band provisioning can support a valid OIDC RP deployment. It is not this specification's dynamic exchange. Protected-resource-only use is a different role and need not always have a client ID. |
| R-02 — Registration endpoint and JSON POST; section 3.1 | Submit client metadata and create a registration at the OP. | **Missing.** No registration endpoint setting/consumer, JSON registration-request model, or registration operation in the endpoint client. Discovery's `registration_endpoint` is not retained (D-13). [Discovery metadata model], [endpoint client], [tenant client settings]. | Technically feasible for a Helidon RP, for example in automated onboarding. It would need a registration workflow and credential/state ownership; the README's exclusion of a registration server must not be read as proof that an RP client is inherently out of scope. |
| R-03 — Open versus Initial-Access-Token-protected registration; section 3 | Apply the OP's policy for who may register. | **Missing.** Neither unauthenticated registration nor an Initial Access Token bootstrap path exists. [Endpoint client], [tenant client settings]. | The OP may require an out-of-band Initial Access Token. Token Endpoint client authentication, public-client `none`, and ordinary end-user access tokens are not automatic substitutes for registration authorization. |
| R-04 — Registration response and effective settings; section 3.2 | Adopt the client ID, optional secret, and metadata actually accepted/provisioned by the OP. | **Missing protocol handling.** No registration-response parser, response-to-tenant configuration mapping, or persistence/association of the resulting registration. [Endpoint client], [tenant client settings], [provider configuration]. | A future client must validate the returned effective settings and not assume requested values were accepted; the OP can substitute most metadata, but not the requested redirect-URI set. Existing local settings can be populated externally, but there is no built-in registration-result import. |

### Client metadata and existing local counterparts

Source: [Client Metadata, section 2](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata).
There is no registration serializer or response importer for these fields. The following inventory distinguishes local
runtime counterparts from actual registration support; setting a corresponding Helidon option does not send that
metadata to the OP or update an existing registration.

| ID / Registration metadata | What the fields describe | Current support and evidence | Boundary or rationale |
| --- | --- | --- | --- |
| R-05 — `redirect_uris` | The client's registered set of callback URIs. | **Static counterpart only.** A tenant has an outgoing code-flow callback URI; a local-path shorthand is resolved against the request origin. No registered URI array is submitted/read from the OP. [Authorization configuration], [request factory], [endpoint URI validation]. | The operator must register the actual externally resolved callback URI(s) at the OP. Configuring the callback is not permission to use an arbitrary unregistered URI, and multiple tenants do not create remote registrations automatically. |
| R-06 — `response_types`, `grant_types` | The response types/grants this client declares it will use. | **Static counterpart only.** Login uses `code`; runtime code/refresh/outbound grant selection is configured separately. No client registration list is generated or reconciled. [Request factory], [endpoint client], [Tenant client settings]. | Registration omission defaults to `code` and `authorization_code` respectively. Do not substitute Discovery's two-element default for `grant_types_supported` here. Using refresh or another grant locally does not authorize/register it with the OP. |
| R-07 — `application_type` | Web/native registration profile and associated callback constraints. | **No registration setting; web-server runtime boundary.** The built-in callback integration is HTTP(S)/WebServer, not a native deep-link handler. [HTTP feature], [endpoint URI validation]. | The registration default is `web`. Selecting Token Endpoint authentication `none` does not select/register `native` or implement native callback handling. A native integration would be separate work, not impossible in the wider Helidon ecosystem. |
| R-08 — `contacts`, `client_name`, `logo_uri`, `client_uri`, `policy_uri`, `tos_uri` | Contact, consent-screen branding, home page and policy/terms information. | **Missing registration metadata handling.** No input/output registration model or transmission of these values. [Tenant client settings], [provider configuration], [endpoint client]. | Normally supplied through OP/deployment provisioning today. Helidon's provider name is a local component name, not OP consent-screen branding. These fields could be useful in a future registration client; they are not needed to process each login after external registration. |
| R-09 — `jwks_uri`, `jwks` | Advertise the client's public signing/encryption keys by URL or by value. | **Missing public-key registration/publication.** Local client private signing/decryption material is supported, but no public registration payload or RP JWKS publication endpoint is created. [Client authentication], [Request Object configuration], [ID Token configuration], [HTTP feature: setup]. | Registration's client `jwks_uri` is not OIDC-next's `endpoints.jwks-uri`, which points to the OP's keys. Private local key resources must not be published as registration JWKS. The spec treats URL/value forms as alternatives, not a combined field pair. |
| R-10 — `sector_identifier_uri`, `subject_type` | Select public/pairwise subjects and a sector grouping for pairwise identifiers. | **Missing registration controls; ordinary subject consumption supported.** No sector document hosting/submission or subject-type registration. The RP consumes an opaque issuer/subject identity. [Tenant client settings], [subject mapper]. | Operator/OP registration determines the issued identifier type. The OP computes pairwise identifiers and validates sector documents; accepting an existing pairwise `sub` is not implementation of that registration workflow. |
| R-11 — `id_token_signed_response_alg`, `id_token_encrypted_response_alg`, `id_token_encrypted_response_enc` | Register the ID Token protection expected for this client. | **Static counterpart only.** Local signing/encryption allowlists, decryption keys and `encryption-required` govern validation, but are not sent to the OP. The signing default is RS256; the local encryption allowlist includes the registration default A128CBC-HS256. [ID Token configuration], [ID Token decryptor], [ID Token validator]. | A local allowlist is not a single negotiated registration algorithm. Supplying decryption keys alone neither requests encryption nor requires it. Align local policy with the registration actually accepted by the OP; unsupported local profiles remain unsupported (C-17–19). |
| R-12 — `userinfo_signed_response_alg`, `userinfo_encrypted_response_alg`, `userinfo_encrypted_response_enc` | Register the protection expected for UserInfo replies. | **Static counterpart only.** `user-info.jwt` supplies exact local signing/encryption expectations and private decryption keys; protected/plain response mismatches are rejected. Missing content encryption defaults to A128CBC-HS256 when encryption is configured. [UserInfo JWT configuration], [UserInfo JWT processor], [UserInfo support]. | These settings must agree with externally registered values. They neither submit a registration nor import the OP's answer. Unconfigured JWT protection expects ordinary JSON; not every algorithm permitted by the spec is implemented locally (C-24). |
| R-13 — `request_object_signing_alg`, `request_object_encryption_alg`, `request_object_encryption_enc` | Declare Request Object signing and possible encryption choices. | **Static counterpart only.** Local Request Object settings select signing keys/algorithms and optional encryption; the implemented content-encryption default is A128CBC-HS256. [Request Object configuration], [Request Object processor]. | Registration signing is a binding algorithm selection, whereas its encryption field declares what the RP may use. The local encryption option actively encrypts generated objects; it is not merely that declaration. No registration/negotiation is performed, and unsigned/shared-secret alternatives remain outside the chosen profile. |
| R-14 — `token_endpoint_auth_method`, `token_endpoint_auth_signing_alg` | Register Token Endpoint authentication and an optional fixed assertion algorithm. | **Static counterpart only.** The named Core methods and selected assertion algorithms can be configured and used locally. [Tenant client settings], [Client authentication], [client assertion configuration]. | Registration defaults the omitted method to `client_secret_basic`. Helidon's local omitted-method default is Basic when a secret exists, otherwise `NONE`; that local default must not be mistaken for the wire-registration default. An omitted registration assertion algorithm permits a mutually supported choice; none of these values is automatically registered. |
| R-15 — `default_max_age`, `require_auth_time`, `default_acr_values` | Register default freshness, required authentication time and preferred assurance values. | **Missing registration controls and no dedicated imported enforcement policy.** No registration defaults are stored/adopted, and the Core request/initial-token freshness and ACR gaps remain (C-20–21). [Authorization configuration], [ID Token configuration], [ID Token validator]. | Cookie/session lifetime is not maximum OP authentication age. These controls could be useful in Helidon, but external OP defaults or merely exposing received claims do not constitute built-in RP policy handling. `default_acr_values` requests a voluntary claim, not an Essential-ACR guarantee. |
| R-16 — `initiate_login_uri` | Register an endpoint for third-party-initiated login. | **Missing registration and built-in initiation endpoint.** Ordinary callback/login-challenge handling is not a section-4 Core initiation endpoint. [HTTP feature: setup], [request factory]. | This registration feature requires a corresponding RP handler for GET/POST and the initiation parameters; C-11 records that gap. It is feasible, not an OP-only feature or the same thing as the code callback URI. |
| R-17 — `request_uris` | Pre-register hosted Request Object references where required by the OP. | **Missing registration/hosted-object workflow.** No registered URI list or RP-hosted Request Object publication/cache-invalidation lifecycle is supplied. [Request Object configuration], [request factory]. | This is the Core hosted-object feature (C-32), not PAR's per-request returned `request_uri`. A manually hosted application resource/static URL does not establish automatic registration or lifecycle support. |

All 30 base client-metadata names in section 2 are included in R-05 through R-17. None is dynamically submitted or
imported by the provider; a static counterpart is not a percentage of the registration protocol implemented. Metadata
defined by other specifications, such as logout registration extensions, will be covered with those specifications.

### Registration result, credential lifecycle, and Client Read

Spec references: [registration response](https://openid.net/specs/openid-connect-registration-1_0.html#RegistrationResponse),
[Client Configuration Endpoint](https://openid.net/specs/openid-connect-registration-1_0.html#ClientConfigurationEndpoint),
[Client Read](https://openid.net/specs/openid-connect-registration-1_0.html#ReadRequest), and
[read response](https://openid.net/specs/openid-connect-registration-1_0.html#ReadResponse).

| ID / Registration response or operation | What the feature provides | Current support and evidence | Boundary or rationale |
| --- | --- | --- | --- |
| R-18 — `client_id`, `client_secret` | Receive the assigned client identity and, when applicable, a secret. | **Missing response handling; static counterparts exist.** The local options take externally supplied values; no registration response creates or updates them. [Tenant client settings], [endpoint client]. | The response requires a client ID, not a secret for every client. An external provisioner can supply the resulting settings; the existing confidential configuration annotation is not a registration credential store or lifecycle. |
| R-19 — `registration_access_token`, `registration_client_uri` | Authorize access to this client's OP-side registration record. | **Missing.** No dedicated options, returned-pair validation, credential association/storage, or use of the provided configuration URI. [Tenant client settings], [endpoint client], [provider configuration]. | The initial registration can return both or neither; a later read can omit unchanged values. When provided, the client must use the complete returned URI rather than construct it from client ID or the registration URL. An ordinary access token/client secret is not automatically a Registration Access Token. |
| R-20 — `client_id_issued_at`, `client_secret_expires_at` | Describe issuance time and client-secret expiration. | **Missing.** No import, expiry monitoring, or registration-driven replacement/reconfiguration of client credentials. [Tenant client settings], [Client authentication]. | Secret expiration is an absolute timestamp, with zero meaning non-expiring; it is required in the response when a secret is issued. Access-token `expires_in`, refresh-token renewal and local cookie lifetime are different mechanisms. |
| R-21 — Client Read request/response; sections 4.1–4.3 | Retrieve the current registration and any externally updated values. | **Missing.** No GET to the returned Client Configuration Endpoint using its Registration Access Token, and no adoption of read metadata/changed credentials. [Endpoint client], [provider configuration]. | Reading Helidon configuration, reloading Discovery or refreshing a user access token is not this operation. Read is intended to be idempotent; it is not a protocol that deliberately rotates credentials on each GET. A read can reveal values changed by another mechanism. |
| R-22 — Registration/read errors and validation; sections 3.3, 4.4, 7 | Handle rejected metadata, invalid credentials or unavailable registrations safely. | **Missing with the protocol client.** No registration-specific error path for invalid redirect URIs/client metadata, no Client Read authorization-error handling, and no fail-closed adoption of a validated registration response. [Endpoint client], [tenant validation]. | Existing token-endpoint error parsing and local configuration checks do not exercise registration response rules. This is an absent workflow, not a claim that current login incorrectly parses registration errors it never requests. |

All six registration-response field names are covered in R-18 through R-20, separately from the 30 client metadata
names. Registration success and Client Read success are specified with recommended 201 and 200 statuses respectively;
there is no implemented registration transport here whose response policy can be claimed conformant.

### Localization, server responsibilities, and specification boundaries

Spec references: [metadata languages/scripts](https://openid.net/specs/openid-connect-registration-1_0.html#LanguagesAndScripts),
[sector validation](https://openid.net/specs/openid-connect-registration-1_0.html#SectorIdentifierValidation),
[implementation considerations](https://openid.net/specs/openid-connect-registration-1_0.html#ImplementationConsiderations),
[stateless registration](https://openid.net/specs/openid-connect-registration-1_0.html#StatelessRegistration), and
[security](https://openid.net/specs/openid-connect-registration-1_0.html#Security).

| ID / Registration feature or boundary | What the feature provides | Current support and evidence | Gap or exclusion rationale |
| --- | --- | --- | --- |
| R-23 — Localized/extensible metadata and wire representation; sections 2.1, 3, 6–7 | Transmit language-tagged branding, additional metadata and correctly typed values. | **Missing registration model/serialization/adoption.** No handling of localized client metadata names such as `client_name#ja`, server-substituted values, or a registration-specific validation/default layer. [Tenant client settings], [provider configuration], [endpoint client]. | Generic JSON facilities or Core's localized user-claim storage do not provide localized client registration. A future client must preserve the protocol's types/strings and distinguish requested metadata from the OP's effective response. |
| R-24 — OP registration/configuration service; sections 2–5, 7, 9 | Assign client identities/credentials, validate metadata and sector documents, authorize reads, and apply server policy. | **Outside the RP component's role.** No registration/configuration server routes or provisioning service. [HTTP feature: setup], [README](README.md#supported-standards-boundary). | OP-side uniqueness, URI/key checks, sector-document validation, CORS and branding/impersonation controls belong to an OP implementation. This does not make an RP-side registration client out of role. Any future client also needs protected TLS transport/credential handling; existing WebClient TLS alone is not proof of a registration implementation. |
| R-25 — Stateless OP registration; section 8.2 | Allow an OP to encode registration information in an opaque client identifier instead of keeping a client record. | **No dynamic workflow; opaque configured IDs have a local counterpart.** The provider accepts an externally supplied client ID and uses it as an identifier rather than decoding an OP registration format. [Tenant client settings], [Client authentication], [code exchange tests]. | Stateless issuance is an OP design. It can omit the read endpoint/token, so those outputs must not be treated as mandatory for every successful registration. Accepting an opaque ID does not establish stateless dynamic registration support. |
| R-26 — Additional management methods / software statements; section 8 | Locate the boundary to other registration extensions. | **Outside this base-spec assessment, not implemented by the absent registration client.** The OIDC Client Configuration Endpoint defines GET only; additional management operations and software-statement metadata are addressed by the separately referenced OAuth specifications. [Endpoint client]. | Do not invent a mandatory OIDC PUT/DELETE workflow or count ordinary client-assertion signing as software-statement processing. Those separate specifications are not being assessed here. |

### Registration overview: what is actually missing

There is no built-in implementation of the dynamic registration/read protocol. The useful existing coverage is the
ability to run OIDC flows using a client already provisioned by an operator or external tool, with configurable
authentication, callback, key and response-protection settings. Those counterparts do not create or synchronize the
OP's client record.

A registration client could make sense for automated onboarding or dynamically provisioned tenants. It is technically
feasible in Helidon; no evidence establishes that it was permanently rejected as unsuitable. It would need a deliberate
owner/lifecycle for the registration and returned credentials, bootstrap authorization, metadata adoption, persistence
or handoff, read/reconfiguration behavior, and safe retries. That is different from merely adding another metadata GET.
As an architectural option, such work could live in deployment/provisioning tooling instead of the per-request
authenticator. This is an assessment, not a recorded project decision or authorization to implement it now.

Two distinctions matter especially when configuring an externally registered client:

- Keep **OP public keys**, **client public registration keys**, and **client private signing/decryption keys** separate.
- Do not equate local defaults/allowlists with registration defaults or returned effective choices. In particular,
  no-secret local authentication defaults to NONE, while omitted registration authentication defaults to Basic.

### Registration assessment method and limits

All 30 section-2 client-metadata names and all six section-3.2 response-field names were extracted from the supplied
errata-set-2 specification and mapped explicitly. The endpoint client, discovery model, tenant/configuration APIs,
callback routes and relevant existing counterpart tests were inspected; no registration/read protocol path was found.
References to registered algorithms in configuration documentation or test names describe expected externally
registered values, not evidence of an HTTP registration exchange.

The registration-create/read success statuses are SHOULD-level, the configuration-URI/token pair is optional at initial
registration, and read may omit unchanged values. The returned configuration URI must not be reconstructed. The
response's effective metadata can differ from the request, with the specified redirect-URI exception. These boundaries
were checked separately from local configuration defaults so that omitted features or absent endpoints do not acquire
invented requirements.

This is source-based documentation, not a new protocol implementation, negative-runtime probe or conformance-test run.
Core/Discovery feature rows remain unchanged. No standalone OAuth registration-management or JWT/JOSE specification
was assessed, and no earlier deferred issue was reopened.

Registration assessment is complete for this baseline. The separate Session Management assessment follows.

## 4. OpenID Connect Session Management 1.0

Assessed: 2026-09-24. Source: [Session Management 1.0](https://openid.net/specs/openid-connect-session-1_0.html),
matching the supplied `oidc-specs/openid-connect-session-1_0.html` (Final, 12 September 2022). The code baseline is unchanged.

This specification monitors an end-user's browser login state at the OP so an RP can react to changes, including OP
logout. It is not the general concept of storing a local login session. Its protocol uses an OP-supplied session-state
value, browser iframes and origin-restricted `postMessage` communication.

The README explicitly places browser session management outside the implemented profile. Source inspection agrees:
there is no session-monitor browser component, no `session_state` handling and no `check_session_iframe` metadata
consumer. This is a documented current scope boundary, not proof that a Helidon web application could never support it.

### RP session establishment, wire state, and browser monitoring

Spec references: [session creation/state](https://openid.net/specs/openid-connect-session-1_0.html#CreatingUpdatingSessions),
[status notification](https://openid.net/specs/openid-connect-session-1_0.html#ChangeNotification),
[RP iframe](https://openid.net/specs/openid-connect-session-1_0.html#RPiframe), and
[discovery metadata](https://openid.net/specs/openid-connect-session-1_0.html#OPMetadata).

| ID / Session Management feature | What the feature provides | Current support and evidence | Gap or exclusion rationale |
| --- | --- | --- | --- |
| S-01 — Establishing the RP's own login session; section 2 | Start local authenticated use after validating an ID Token. | **Implemented adjacent Core behavior.** Code-flow callback handling validates identity and stores protected local authentication state. [HTTP feature: processTokenEndpointExchange], [local authentication result], [cookie state handler]. | This is a prerequisite/context for monitoring, not evidence of the Session Management protocol. Local session creation does not report whether the OP browser session subsequently changes. |
| S-02 — `session_state` in success/error responses; section 2 | Carry opaque OP login state back to the RP. | **Missing protocol handling.** The callback model does not extract, retain or expose this parameter for monitoring, nor enforce its no-space string representation. [Callback processor], [authorization response result], [local session state]. | A supporting OP must return it on authentication success and should return it on errors; that does not mean every plain Core RP implements monitoring. Ordinary `state`, nonce and local browser-session generation are different values. |
| S-03 — `check_session_iframe`; section 3.3 | Locate the OP's HTTPS browser frame for session checks. | **Not consumed.** No discovery field, explicit equivalent setting or propagation to a browser monitor. [Discovery metadata model], [endpoint configuration], [HTTP feature]. | An OP supporting both Session Management and Discovery must advertise this field; out-of-band acquisition is also allowed. Neither acquisition path is implemented here. A token endpoint, UserInfo endpoint or end-session redirect URL is not the check-session iframe. |
| S-04 — RP/OP frame setup; sections 3.1–3.2 | Embed and address the hidden frames in a browser page. | **Missing; outside the documented current profile.** No supplied frame page/script or route wiring for a browser monitor. The HTTP feature installs code callbacks and local logout routes. [HTTP feature: setup], [README](README.md#supported-standards-boundary). | Requires an application/browser integration, not merely a server-side timer or another WebClient request. A Helidon-served web application can provide that integration; an API-only consumer cannot run this browser protocol by itself. |
| S-05 — RP polling and origin-restricted messages; section 3.1 | Send client ID plus opaque state and accept replies only from the expected OP origin. | **Missing with the browser monitor.** No `postMessage` sender/listener, OP frame ID/origin binding, or polling lifecycle. [HTTP feature], [authorization response result]. | The polling interval is application-dependent; the spec's example is not a mandatory fixed interval. This absence is not an origin-check bypass in an existing listener—there is no implemented message channel. |

### Change handling, reauthentication, and OP responsibilities

Spec references: [RP behavior](https://openid.net/specs/openid-connect-session-1_0.html#RPiframe),
[OP behavior](https://openid.net/specs/openid-connect-session-1_0.html#OPiframe), and
[validation/security](https://openid.net/specs/openid-connect-session-1_0.html#Validation).

| ID / Session Management feature | What the feature provides | Current support and evidence | Gap or exclusion rationale |
| --- | --- | --- | --- |
| S-06 — `changed`, `unchanged`, `error` replies; section 3.1 | Decide whether to re-check the OP session or stop an invalid exchange. | **Missing.** No message-result state machine. The protocol requires `prompt=none` reauthentication on `changed`, and forbids that reaction to `error` to avoid loops. [HTTP feature], [request factory], [callback processor]. | `changed` is not itself proof the original user logged out: it can reflect other OP browser-state changes. A future integration must distinguish these outcomes rather than treating every reply as a logout or every error as a retry. |
| S-07 — Silent reauthentication with previous ID Token hint; section 3.1 | Obtain a fresh identity result/session state after a change indication. | **Core building blocks only; monitoring workflow missing.** A configured `prompt=none` can be serialized for ordinary code-flow initiation, but there is no monitor-driven request, automatic old-ID-Token authentication hint, or hidden-frame return/update integration. [Authorization configuration], [request factory], [HTTP feature]. | Configuring a static prompt is not ongoing session checking; an already valid local cookie does not by itself initiate a new OP browser-session check. Logout's ID Token hint handling is a different path. The spec recommends the iframe/old-hint approach, while the `changed` re-check requirement is stronger. |
| S-08 — Same-user continuity and original-user logout; section 3.1 | Update state for the same user, or end the original RP session when silent reauthentication returns no ID Token/a different user. | **Missing monitoring semantics.** The normal callback validates a new login and creates its local state; it does not implement the monitor's prior-user comparison/session-state update/logout decision. [HTTP feature: processTokenEndpointExchange], [authorization response result], [local session state]. | Refresh-specific identity continuity checks do not implement this new-authentication workflow. Already being logged out at the RP counts as successful logout in the protocol; there is no monitor integration here to apply that rule. |
| S-09 — OP iframe, state calculation and change detection; section 3.2 | Compare the RP's opaque state with OP-origin browser login state and report the result. | **Outside this RP component's OP role.** No OP browser-state store, session-state issuer or OP frame implementation. [README](README.md#supported-standards-boundary), [HTTP feature: setup]. | The OP owns state generation/recalculation and expected-origin enforcement. The RP treats its value as opaque; the illustrative hash/salt encoding is not something to infer from a Helidon cookie. A Helidon-based OP would be separate work. |
| S-10 — Origin binding, privacy and multi-origin coordination; sections 3.1–3.2, 6 | Keep the browser check bound to the right client/origin and avoid unintended correlation. | **Missing browser integration; OP duties remain separate.** No cross-frame origin/state coordination exists. Existing HTTP callback or logout origin checks are not `postMessage` checks. [HTTP feature], [callback processor], [local logout handler]. | Sharing an RP cookie across subdomains does not make an origin-bound OP session-state value interchangeable. The spec's discussion of an OP JavaScript-readable state cookie is not a requirement to expose RP authentication tokens or disable their HttpOnly protection. |

### Browser constraints and existing adjacent mechanisms

Spec references: [third-party content restrictions](https://openid.net/specs/openid-connect-session-1_0.html#ThirdPartyContent)
and [relationship to the logout specifications](https://openid.net/specs/openid-connect-session-1_0.html#Introduction).

| ID / Session Management feature or boundary | What the feature provides | Current support and evidence | Gap or exclusion rationale |
| --- | --- | --- | --- |
| S-11 — Blocked third-party state and false-change loops; section 5.1 | Avoid repeated reauthentication when browser privacy restrictions prevent the OP frame reading required state. | **Missing defensive integration with the absent monitor.** No detection/backoff/user-notification path for this scenario. [HTTP feature], [request factory]. | The spec warns that blocked cookies/storage can produce persistent `changed` results and recommends defenses. This is deployment/browser dependent, not proof the protocol always fails or that an unimplemented loop is currently exploitable. Actual browser testing would be necessary before claiming support. |
| S-12 — Local browser-session generation | Keep stale local responses from restoring a session after RP logout. | **Implemented adjacent protection, not OP session state.** The RP creates/protects a random generation marker, checks it against local authentication state and rotates it during local logout. [Cookie state handler], [authentication orchestrator], [local logout handler], [refresh tests]. | This value is created by the RP, not returned as the OP's `session_state`. Its late-refresh/logout protection neither polls the OP frame nor detects another application's/OP's logout. |
| S-13 — Token refresh and local-session expiration | Keep local credentials usable within their configured lifetime. | **Implemented adjacent behavior.** Renewal is driven by access-token expiry during local authentication; local session deadlines remain enforced. [Refresh manager], [local authentication result], [authentication orchestrator]. | Successful token renewal or token validation is not the browser-session status exchange defined here. Local expiry/re-authentication is not a guarantee of prompt notification when an OP browser session ends. |
| S-14 — Local logout, OP logout requests and other logout protocols; section 1 | Separate monitoring an OP session from requesting/receiving logout through other mechanisms. | **Adjacent actions exist; this monitoring bridge does not.** Local logout clears RP cookies and can redirect to an OP end-session endpoint when configured. [Local logout handler], [feature route tests]. | These actions do not implement `check_session_iframe`/`postMessage` change handling. Session Management, RP-Initiated Logout, Front-Channel Logout and Back-Channel Logout are distinct/complementary protocols; the latter three remain separate assessments rather than being declared fully covered or absent here. |

### Session Management overview: why the boundary matters

There is no built-in implementation of this browser-monitoring protocol. The component does maintain a local RP login
and provide refresh/logout actions, but those are not evidence that it can notice an OP browser-session change and
apply this specification's reauthentication/logout decision. In particular, the OP's `session_state`, authorization
`state`/nonce and the RP's local generation marker are not interchangeable.

For an API-only service without an end-user browser, the iframe protocol is not the relevant session mechanism. For a
Helidon web application using browser login, it can be useful and is technically feasible. Supporting it would need a
browser component plus backend plumbing for discovered frame information, retained OP state, safe browser messaging,
silent reauthentication and the application's local-session transition. A background server poll alone cannot execute
an OP-origin frame against the end-user's browser state.

Browser privacy restrictions are a real constraint identified by the spec. They call for deployment-specific testing
and defensive behavior, not a categorical claim that Helidon cannot support the feature or that changing cookie flags
alone would make it work. No modern browser/version compatibility matrix or workaround is claimed by this source review.
The README's documented exclusion explains the current scope; it is not a permanent architectural prohibition.

### Session Management assessment method and limits

The final 2022 specification was checked against the local copy and the official publication. Both defined wire
extensions (`session_state` and `check_session_iframe`), all three message outcomes, RP/OP roles, reauthentication and
browser limitations are accounted for. Callback/state models, metadata parsing, route setup, authentication request
construction and local refresh/logout code were inspected. No browser script/frame asset or protocol handler was found.
Existing cookie/refresh/logout regression tests support the adjacent behavior, not the absent monitoring protocol.

The assessment preserves the normative distinctions: `changed` requires the re-check; `error` must not cause that
reauthentication loop; the hidden-frame/old-ID-Token-hint approach is recommended; the polling interval is not fixed by
the sample code. Browser storage restrictions are conditional deployment constraints, not an untested universal failure
claim. No browser tests, new runtime probes, source changes or certification checks were performed in this pass.

Session Management assessment is complete for this baseline. Its browser-monitoring assessment is separate from
RP-Initiated Logout below. The prior Core, Discovery and Registration feature assessments remain unchanged.

## 5. OpenID Connect RP-Initiated Logout 1.0

Assessed: 2026-09-25. Source: [RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html),
matching the supplied `oidc-specs/openid-connect-rpinitiated-1_0.html` (Final, 12 September 2022). The code baseline is
unchanged.

This specification lets an RP send the user's browser to the OP to request logout there, optionally followed by a
return to the RP. It defines request parameters, OP endpoint metadata, registered return URLs, and OP processing rules.
It does not equate clearing the RP's cookies with ending the OP's session, and it does not define the separate
Front-/Back-Channel mechanisms for delivering logout notifications to other RPs.

### Activation, endpoint acquisition, and request transport

Spec references: [RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout),
[OP metadata](https://openid.net/specs/openid-connect-rpinitiated-1_0.html#OPMetadata), and
[implementation requirements](https://openid.net/specs/openid-connect-rpinitiated-1_0.html#ImplementationConsiderations).

| ID / RP-Initiated Logout feature | What the feature provides | Current support and evidence | Gap or exclusion rationale |
| --- | --- | --- | --- |
| L-01 — Opt-in RP logout request; sections 1–2 | Ask the OP to end the user's OP session. | **Implemented, opt-in.** An enabled tenant's configured `logout` block supplies the local route; its optional enabled `end-session` block enables the OP redirect. The default local path is `/oidc/logout`; both blocks default to enabled when present. [Local logout configuration], [end-session configuration], [local logout handler]. | Local-only logout remains possible and is not an OP logout request. Neither creating an RP login session nor enabling the local route alone enables the OP protocol. |
| L-02 — `end_session_endpoint`; section 2.1 | Locate the OP's Logout Endpoint through Discovery or another mechanism. | **Implemented.** Consumes the discovered field or explicit `end-session-endpoint-uri`; explicit configuration wins. An enabled end-session path requires an endpoint or available discovery source, and resolved metadata must contain a valid endpoint. [Discovery metadata model], [tenant validation], [tenant metadata validation], [discovery loading tests]. | Publishing the field is the OP's responsibility when it supports both RP-Initiated Logout and Discovery. Out-of-band configuration is allowed by this spec; it is not necessary to implement Dynamic Registration to discover the endpoint. |
| L-03 — OP endpoint URI and transport policy; section 2.1 | Use the required HTTPS OP endpoint, with optional port, path and query components. | **Implemented in the default TLS-required profile.** URI validation requires HTTPS by default and rejects fragments; logout construction preserves the endpoint's existing query before appending generated parameters. [Endpoint URI validation], [endpoint configuration], [local logout handler]. | Explicit `tls-required=false` also permits HTTP, which is outside this spec's HTTPS requirement for the OP endpoint. This opt-out must not be described as a conforming production alternative. The post-logout RP return URI has different scheme rules, assessed separately. |
| L-04 — GET or POST to the OP; section 2 | Serialize a logout request as URL query parameters or a form body. | **Implemented GET choice.** The local handler replies with HTTP 303 and an OP `Location` URL built with Helidon's query serializer; the browser then uses GET. [Local logout handler], [feature route tests]. | No form-POST-to-OP mode. The spec requires the OP to support both methods but allows an RP to choose either. Helidon's own POST-only local trigger is a different endpoint, not a violation of the OP's dual-method requirement. |

### Complete logout request parameter inventory

These are all six request parameters defined by [section 2](https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout).
The local trigger reads its supported caller-supplied values from the URL query, despite being an HTTP POST route;
it is not a form-body passthrough to the OP. Parameter status below concerns generated request values. Any fixed
query already embedded in the configured/discovered OP endpoint is preserved, not interpreted as dedicated configuration.

| ID / Request parameter | What the feature provides | Current support and evidence | Gap or exclusion rationale |
| --- | --- | --- | --- |
| L-05 — `id_token_hint` | Identify the OP session using a previously issued ID Token; RECOMMENDED by the spec. | **Implemented from local login state.** Uses the original token in the protected, readable, unexpired local authentication result. `id-token-hint-required` defaults to `true`; missing a required hint returns 403 after local cleanup. No arbitrary caller-provided ID Token hint is accepted. [Local logout handler], [cookie state handler], [end-session configuration], [feature route tests]. | Requiring the hint is configurable RP policy, not a spec MUST. The default requires enabled code-flow login; disabling the requirement permits a hintless request and requires a configured client ID. Expired local state and encrypted hints have separate limitations below. |
| L-06 — `logout_hint` | Give the OP an optional, OP-defined user/session hint. | **No first-class/dynamic support; static URL transport only.** Not read from the local request or exposed as an end-session option. A fixed OP endpoint query can carry it. [Local logout handler], [end-session configuration]. | The spec deliberately leaves its meaning to the OP. A dynamic, provider-aware hint could be useful, but no implementation or documented permanent exclusion was found. A fixed endpoint query cannot derive the current user's hint. |
| L-07 — `client_id` | Identify the RP, especially without an ID Token hint or when the OP needs help interpreting an encrypted hint. | **Implemented conditional generation.** Sends the tenant's configured ID when the hint is absent or encrypted; an ordinary signed hint is sent without an additional generated client ID. [Local logout handler], [tenant validation], [feature route tests]. | The parameter is OPTIONAL, so always sending it is not required. Matching it to the hinted token is an OP MUST when both are present. Sending a client ID alone neither replaces OP user confirmation nor guarantees a post-logout redirect. |
| L-08 — `post_logout_redirect_uri` | Optionally request a browser return to an already registered RP URI. | **Implemented request selection.** Uses the configured default, or one caller query value exactly matching that default/additional local allowlist. Multiple, blank, malformed or unlisted requested values are rejected. Comparison uses the original URI string, including case and percent-encoding spelling. [Local logout handler], [end-session configuration], [feature route tests]. | This is the RP's own allowlist, not OP registration or evidence that the OP will accept the URI. Return-URI profiles and registration obligations are assessed below; the actual redirect is the OP's action. |
| L-09 — `state` | Optionally correlate the logout request with the post-logout return. | **Partial: pass-through only.** Copies the first local `state` query value if nonblank, and only when generating a request with a post-logout redirect. No automatic value creation, protected transaction storage, expiry/replay tracking, or return-state verifier exists. [Local logout handler], [HTTP feature: setup], [end-session configuration]. | The application must manage/check correlation if it relies on this parameter. Optional `state` is not a requirement to create another built-in transaction API, and merely forwarding it does not establish that an OP logout succeeded. OP echo behavior is an OP responsibility. |
| L-10 — `ui_locales` | Optionally express preferred languages/scripts for the OP logout UI. | **No first-class/dynamic support; static URL transport only.** No per-user request forwarding or end-session setting; an existing OP endpoint query can carry a fixed value. [Local logout handler], [end-session configuration]. | Feasible for localized applications; no evidence that it is intrinsically unsuitable for Helidon. Interpreting preferences and normally tolerating unsupported locales belong to the OP, not to a Helidon logout UI implementation. |

### Return-URI registration and supported profile

Spec references: [post-logout redirection](https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RedirectionAfterLogout),
[client metadata](https://openid.net/specs/openid-connect-rpinitiated-1_0.html#ClientMetadata), and
[request URI rules](https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout).

| ID / Registration or URI feature | What the feature provides | Current support and evidence | Gap or exclusion rationale |
| --- | --- | --- | --- |
| L-11 — `post_logout_redirect_uris`; section 3.1 | Register an array of permitted post-logout return URLs with the OP. | **Static counterpart only.** Local default/additional allowed return URIs are configured, but no registration request or OP registration update is sent. The README explicitly requires configuring those exact values at the OP too. [End-session configuration], [local logout handler], [README: local logout](README.md#local-logout-endpoint). | Out-of-band registration is explicitly permitted, so a Dynamic Registration client is not required for this flow. The operator must keep the OP registration and RP allowlist aligned; login `redirect_uris` and logout return URLs are distinct settings. |
| L-12 — RP return-URI scheme/profile; sections 2, 3.1 | Support HTTPS, conditionally HTTP for a confidential client with OP approval, and optionally alternative/native callback schemes. | **Implemented web-URI subset.** Configured return URIs require a scheme, use HTTPS by default, accept HTTP with `endpoints.tls-required=false`, and reject fragments and other schemes. No relative-path expansion is provided here. [Endpoint URI validation], [tenant validation], [configuration tests]. | HTTPS is the spec's SHOULD for return URIs, unlike the OP endpoint's MUST. Allowing HTTP locally does not verify confidential-client registration or OP permission; those conditions still apply. Native/custom schemes are excluded by the current URI guard, not by the spec. Assessment: a web-RP profile is coherent, but alternate schemes are technically possible if a deployment needs them. |

### Hint lifetime and encrypted-token interoperability

Spec reference: [hint processing and session rules](https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout).

| ID / Hint lifecycle feature | What the feature provides | Current support and evidence | Gap or exclusion rationale |
| --- | --- | --- | --- |
| L-13 — Hints from expired/recent RP sessions; section 2 | Let the OP recognize a current/recent session even when the hinted ID Token has expired. | **Limited to a readable live local session.** The cookie reader enforces the stored RP deadline; the initial deadline is capped by ID Token expiry. No separate retained-expired-hint source exists. Missing, expired or unreadable local state therefore cannot supply this handler's hint. [Cookie state handler], [local authentication result], [local logout handler]. | The spec says the OP SHOULD accept expired hints for current/recent sessions; it does not require every RP to archive them. This is an availability/UX boundary: the default hint-required policy can stop the OP request while the OP session still exists. Hintless mode is configurable, subject to OP confirmation/return-target rules. |
| L-14 — Encrypted ID Token hint; section 2 | Carry a previously issued encrypted ID Token back as an OP logout hint. | **Raw-token transport implemented; broad interoperability not established.** Sends the original encrypted token plus client ID, not the decrypted inner signed token. Local ID Token decryption uses the RP's configured RSA private keys. The encrypted-hint route test checks the constructed redirect, not OP acceptance. [Local logout handler], [ID Token decryptor], [ID Token configuration], [feature route tests]. | The spec's client-ID/decryption example concerns symmetric encryption. Supplying a client ID does not itself let an OP decrypt a token encrypted to the RP's asymmetric key. OP-side recognition/compatibility must be established; neither universal success nor universal rejection is demonstrated by the URL-construction test. This pass does not claim a separate encrypted-hint conversion MUST or introduce a runtime fix. |

### Local logout lifecycle, routing, and failures

Spec references: [local-versus-OP logout ordering](https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout),
[validation/error handling](https://openid.net/specs/openid-connect-rpinitiated-1_0.html#ValidationAndErrorHandling), and
[logout request security](https://openid.net/specs/openid-connect-rpinitiated-1_0.html#Security).

| ID / Local behavior or boundary | What the feature provides | Current support and evidence | Gap or exclusion rationale |
| --- | --- | --- | --- |
| L-15 — Local cleanup before the OP redirect; section 2 | End the RP's browser session independently of the OP's eventual decision. | **Implemented permitted ordering.** Sends deletion cookies for the full supported local session/chunk namespace and authentication-request cookie, and rotates the protected browser-generation cookie before constructing the OP request. Generation checking prevents an older in-flight refresh response from restoring this browser's authentication. [Local logout handler], [cookie state handler], [authentication orchestrator], [refresh tests], [Keycloak logout tests]. | The spec explicitly leaves early local logout to the RP. Local cleanup is not contingent on OP approval or successful discovery. This is not a global server-side session/token revocation claim, and it does not mean all cookies, including the generation marker, are removed. |
| L-16 — Local trigger and same-origin protection | Let the application expose a controlled user logout action. | **Implemented local policy.** Registers the configured exact path for POST only. Requires a same-origin `Origin`, falling back to `Referer` only when `Origin` is absent; rejects failure before cookie changes. [HTTP feature: setup], [local logout handler], [feature route tests]. | A plain GET logout link or headerless/cross-origin call does not trigger this handler. This protection belongs to Helidon's local endpoint; the spec does not prescribe that endpoint's HTTP API, and it does not replace OP user confirmation. |
| L-17 — Tenant selection and shared logout paths | Select the right OP/client and limit which local cookies are cleared. | **Implemented with ambiguity handling.** Selects the sole readable local-session tenant on the exact path, or the sole configured path tenant when no unique local session identifies one. If multiple path tenants remain ambiguous, clears their local state and returns 204 without choosing an OP. A uniquely identified session limits cleanup to its tenant. [Local logout handler], [feature route tests]. | A shared path is not automatic federation-wide logout. The application can use distinct local paths to make the target unambiguous. Tenant configuration is a Helidon concern, not an additional parameter or requirement defined by this OIDC spec. |
| L-18 — Local errors after cleanup | Reject an unusable outgoing request without abandoning local logout. | **Implemented explicit outcomes.** Missing required hint gives 403, invalid/unlisted requested return URI 400, unavailable tenant-initialization admission 503, and an unavailable resolved OP endpoint 502. These occur after the local cleanup headers are added; local-only/ambiguous cases return 204. [Local logout handler], [feature route tests]. | These are local HTTP outcomes, not OP logout protocol responses. An error can still leave the RP logged out; retrying after cookie deletion can lose the hint required by the default policy. No automatic retry/completion workflow or guarantee of ending the OP session is supplied. |
| L-19 — Post-logout landing route and result UX; section 3 | Receive the OP's browser return and present the application outcome. | **Application-owned return handling.** The feature does not install a handler for the configured return URL, verify returned logout state, or expose a dedicated OP-logout-completed event. The Keycloak integration test adds its own landing route and checks the OP's echoed state. [HTTP feature: setup], [local logout handler], [Keycloak logout tests]. | A usable return page and any correlation checks remain application work. Emitting the initial 303 is not proof that the browser reached the OP, the user approved logout, or the OP finished it. Absence of a generic callback API is not itself a spec violation. |

### OP responsibilities and limits of the logout guarantee

Spec references: [OP processing/confirmation](https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout),
[post-logout redirection](https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RedirectionAfterLogout), and
[validation/idempotency](https://openid.net/specs/openid-connect-rpinitiated-1_0.html#ValidationAndErrorHandling).

| ID / OP responsibility or protocol boundary | What the feature provides | Current support and evidence | Gap or exclusion rationale |
| --- | --- | --- | --- |
| L-20 — Hint validation, session matching and user confirmation; sections 2, 6 | Decide whether the request legitimately identifies the user's OP session and obtain approval. | **Outside the component's role: OP processing.** The OP must validate its own issuance of the hinted token and, when present together, the matching client ID. Confirmation is recommended generally and mandatory when the hint is missing or unrelated to the current OP session/user; user approval requires the OP to log out. Helidon sends the request to that external OP. [Local logout handler], [README](README.md#supported-standards-boundary). | OP handling of `aud`/`sid`, acceptance of recent expired hints, confirmation screens and OP-session termination are not missing RP implementations. A same-origin RP POST or a configured client ID cannot substitute for those OP decisions. |
| L-21 — Return validation, OP errors and repeat requests; sections 3–4 | Return only to a legitimate, exactly registered URI, echo state, and handle already-ended sessions safely. | **OP-side responsibility; local retry UX is separate.** Failed validation must stop operations that depend on the rejected information. The OP must not redirect after request validation errors, or to an unregistered/mismatched target; a hintless return needs another legitimacy check. An included state is echoed on the return. Already having no OP session is explicitly not a logout error. Helidon checks its own return allowlist, not OP session state. [Local logout handler], [end-session configuration]. | A repeated local request after cookie removal can give 403 under the default hint-required policy; that is not the OP treating an already-ended session as an error. Repeated OP requests are not guaranteed by the local HTTP API. Hintless mode does not waive OP checks. The OP may still offer its own logout/error UI without using rejected return information. |
| L-22 — Notifications to other RPs and overall logout scope; sections 1–3 | Coordinate logout of other participating RPs before the post-logout return. | **OP notification dispatch is outside this component's role.** The spec calls for mutually supported notification mechanisms, including notifying the initiating RP before redirecting it back. Helidon performs its own local cleanup and sends the OP request; that alone is not notification delivery/receipt. [Local logout handler], [HTTP feature: setup]. | Receiving notifications belongs to the separate Session Management, Front-Channel and Back-Channel assessments. Those capabilities must not be inferred from this local POST route. Clearing RP cookies or emitting the OP redirect does not by itself prove every RP session or previously issued access/refresh token is invalidated. |

### RP-Initiated Logout overview: supported flow and remaining boundaries

The ordinary server-side web-RP flow is implemented: discover/configure the OP endpoint, clear local browser state,
send the current ID Token hint, and optionally request a registered return URL with caller-supplied state. The built-in
GET-to-OP choice, early local cleanup and externally managed OP registration are all permitted by the specification.
Its two metadata extensions and all six request parameters are mapped above; optional parameters are not silently
treated as mandatory requirements.

The main application/deployment boundaries are:

- Register the exact return URLs at the OP as well as configuring the RP; provide the landing route and any state
  correlation. Local allowlisting and forwarding `state` do not perform those tasks.
- `logout_hint` and `ui_locales` have no dedicated dynamic handling. Existing endpoint query text permits fixed values,
  not user-specific derivation or validated parameter configuration.
- The default requires an ID Token from a still-readable local session. Losing/expiring that state can prevent the OP
  request even though the OP session remains active. A hintless request is available, with the OP's additional checks.
- The web-URI profile excludes native/custom return schemes. Disabling TLS is not a general specification exemption:
  the OP endpoint still has an HTTPS MUST, and HTTP return URLs have their own confidential-client/OP-permission conditions.
- Raw encrypted hints plus client ID are constructed, but the URL-level regression does not establish that arbitrary
  OPs can recognize those tokens encrypted for the RP. Validate the relevant OP/encryption combination before claiming coverage.
- Local logout, a sent OP logout request, a browser return and coordinated logout across RPs are distinct outcomes.
  This feature is not a promise of universal single logout or token revocation.

These are feature/policy/integration boundaries, not a blanket nonconformance or exploitability verdict. Optional
extension points could be added if useful; neither Helidon's server-side role nor this spec requires adding unused
public APIs. OP-only responsibilities would need an OP implementation, not another RP helper. The separate notification
protocols are assessed in their own sections; no deferred earlier finding is reopened by this inventory.

### RP-Initiated Logout assessment method and limits

Checked the final 2022 local specification against its official publication, with a complete six-request/one-discovery/
one-registration field inventory. Inspected local/end-session configuration, endpoint and tenant validation, Discovery
consumption, the full logout handler, route registration, protected cookie restoration/cleanup and local-session expiry.
Existing configuration, metadata-loading, route, refresh, [synthetic logout tests] and [Keycloak logout tests] provide
source-level evidence; none were rerun in this documentation pass.

In particular, the Keycloak return-flow test explicitly follows the OP endpoint, checks echoed state and serves a
test-owned landing route. That is stronger evidence than only checking `Location`, but is not built-in application state
validation or broad OP/browser certification. The separate encrypted-hint route test stops at the generated URL.
No new runtime probe, browser exercise, OP registration change or implementation change was performed.

RP-Initiated Logout assessment is complete for this baseline. Front-Channel Logout is assessed separately below;
all prior feature assessments are preserved.

## 6. OpenID Connect Front-Channel Logout 1.0

Assessed: 2026-09-25. Source: [Front-Channel Logout 1.0](https://openid.net/specs/openid-connect-frontchannel-1_0.html),
matching the supplied `oidc-specs/openid-connect-frontchannel-1_0.html` (Final, 12 September 2022). The implementation
baseline is unchanged.

This specification delivers logout notifications from an OP to RPs through the end-user's browser. The OP embeds
the RPs' registered logout URLs in iframes, causing GET requests that end RP sessions. It does not require the ongoing
OP iframe on RP pages used by Session Management, and is distinct from an RP redirecting the browser to ask the OP
to log out. It can be used independently or together with the other OIDC logout mechanisms.

No built-in Front-Channel Logout receiver was found. The current local POST logout route and optional end-session
redirect implement different actions. The README documents those actions but does not establish a permanent policy
excluding Front-Channel Logout from Helidon; missing protocol support is not proof that the platform cannot provide it.

### RP notification endpoint and complete metadata inventory

Spec references: [RP functionality and registration](https://openid.net/specs/openid-connect-frontchannel-1_0.html#RPLogout),
[OP functionality and Discovery](https://openid.net/specs/openid-connect-frontchannel-1_0.html#OPLogout), and
[relationship to other logout protocols](https://openid.net/specs/openid-connect-frontchannel-1_0.html#Introduction).

The following table includes both client-registration fields and both OP Discovery fields defined by this spec.
The Discovery flags and the client's session-parameter requirement each default to `false` in the specification;
there is no corresponding built-in Front-Channel configuration or negotiation here.

| ID / Front-Channel feature or metadata | What the feature provides | Current support and evidence | Gap or exclusion rationale |
| --- | --- | --- | --- |
| F-01 — Browser-delivered OP notification; sections 1–2 | End an RP session when the OP loads the RP's logout URL in an iframe. | **Missing protocol receiver.** The HTTP feature registers code-flow callbacks and a local POST logout route, not an iframe GET logout handler. The existing POST handler also checks the request's same-origin signal. [HTTP feature: setup], [local logout handler], [feature route tests]. | RP-Initiated Logout's outbound browser redirect is not this inbound protocol. A GET to the existing local logout route does not clear the session. Feasible for a Helidon browser application, but not enabled by configuring an OP end-session URL. |
| F-02 — `frontchannel_logout_uri`; section 2 | Register the RP URL that the OP will render to deliver logout. | **Missing dedicated endpoint/configuration and registration handling.** Neither local logout nor end-session configuration supplies this protocol setting; no registration exchange publishes it. [Local logout configuration], [end-session configuration], [HTTP feature: setup]. | Dynamic Registration is not a prerequisite: registration can be managed outside Helidon. However, manually registering the existing local POST URL does not create an iframe GET receiver. This URI is neither the OP's end-session URL nor a post-logout return URL. |
| F-03 — `frontchannel_logout_session_required`; section 2 | Optionally require the OP to include both issuer and session ID; omitted means `false`. | **Missing protocol policy/registration field.** No front-channel session-identification requirement or its enforcement exists. [Local logout configuration], [end-session configuration], [local logout handler]. | The spec recommends registering this related setting when using Dynamic Registration; it does not require every RP to select `true`. The existing `id-token-hint-required` controls an outgoing RP-Initiated Logout request and is not this option. |
| F-04 — `frontchannel_logout_supported`; section 3 | Advertise whether an OP supports browser-based logout notifications; omitted means `false`. | **Not consumed.** The Discovery parser/model has no field or policy using this advertised capability. [Discovery metadata model: fromWellKnownMetadataJson], [endpoint configuration]. | An OP advertising `true` does not activate a Helidon receiver. The missing receiver is established from routing/handler evidence, not merely inferred from ignoring metadata. OP publication of the field is a separate issuer responsibility. |
| F-05 — `frontchannel_logout_session_supported`; section 3 | Advertise OP support for issuer/session parameters and including the session-ID claim in ID Tokens; omitted means `false`. | **Not consumed.** No Discovery model field, local equivalent policy or metadata-driven session handling. [Discovery metadata model], [endpoint configuration], [local logout handler]. | Generic parsing of an ID Token that happens to contain a session ID is not implementation of this capability. Session-claim data retention and actual logout matching are assessed separately below. |

### Registered URI, notification parameters, and session correlation

Spec references: [URI/parameter rules and optional matching](https://openid.net/specs/openid-connect-frontchannel-1_0.html#RPLogout)
and [session-ID definition](https://openid.net/specs/openid-connect-frontchannel-1_0.html#OPLogout).

| ID / URI or notification parameter | What the feature provides | Current support and evidence | Gap or exclusion rationale |
| --- | --- | --- | --- |
| F-06 — Registered logout-URI contract; section 2 | Use an absolute, fragment-free URL with the domain, port and scheme of a registered login redirection URI; retain existing query values when adding parameters. | **Missing for this protocol.** No Front-Channel URL configuration/registration validation or rendering path exists. Local logout accepts a local path, and existing callback/post-logout URL checks serve other protocols. [Endpoint URI validation], [tenant validation], [local logout configuration]. | The origin relationship is between the RP logout URL and a registered RP login callback, not between the OP's page and the RP. HTTPS is recommended; HTTP is permitted for a confidential client when the OP allows it. Existing URI utilities do not themselves implement that registration contract or the OP's query-preserving dispatch. |
| F-07 — `iss` notification parameter; section 2 | Identify the OP issuing the browser-delivered logout notification. | **Missing incoming logout handling.** The local logout handler does not read this parameter or use it to match a Front-Channel session. Authorization-response issuer checking is a separate implemented path. [Local logout handler], [callback processor]. | The OP may omit both notification parameters unless required by registration; if it sends either `iss` or `sid`, it MUST send both. Core/authorization-response issuer validation cannot be counted as this notification's handling. |
| F-08 — `sid` notification parameter; section 2 | Identify which OP/RP session is to be logged out. | **Missing incoming logout handling.** No notification parser or issuer/session-pair selection exists; the local handler selects tenants from local cookies and the configured path instead. [Local logout handler], [local session state]. | Session IDs are opaque and only need to be unique within an issuer. A subject ID, local generation marker or tenant ID is not a substitute. The both-or-neither sending rule applies to this parameter together with `iss`; no extra front-channel token is defined here. |

| ID / ID Token and correlation feature | What the feature provides | Current support and evidence | Gap or exclusion rationale |
| --- | --- | --- | --- |
| F-09 — `sid` ID Token claim; section 3 | Retain the OP's opaque session identifier for later correlation; a session-aware OP includes it in its ID Tokens. | **Generic claim preservation only.** The original ID Token is kept in protected local state, and its claims become principal attributes. Subject mapping expressly prevents UserInfo from replacing its `sid`. There is no dedicated front-channel session policy or consumer. [Cookie state handler], [subject mapper], [local session state]. | This is useful underlying data, not end-to-end logout support. No UUID encoding is required by the spec. The RP's independently generated browser-session marker is not this OP-issued claim and is not sent as the notification's session ID. |
| F-10 — Current/recent session matching; section 2 | Optionally compare notification issuer/session values with an ID Token from a current or recent session and ignore a mismatch. | **Missing with the receiver.** No Front-Channel matching/ignore decision, retained recent-session association or notification-specific tenant resolution. Ordinary local cookie restoration enforces its own stored expiration. [Local logout handler], [cookie state handler], [local authentication result]. | The spec makes this RP comparison a MAY; do not turn it into an unconditional MUST or treat missing checks in a nonexistent handler as an authentication bypass. A future session-aware mode must connect its advertised policy to actual session data. The spec does not prescribe a particular server-side session database. |

### Local state, response caching, and browser constraints

Spec references: [RP cleanup, repeat notifications and response caching](https://openid.net/specs/openid-connect-frontchannel-1_0.html#RPLogout)
and [third-party content restrictions](https://openid.net/specs/openid-connect-frontchannel-1_0.html#ThirdPartyContent).

| ID / RP lifecycle or browser feature | What the feature provides | Current support and evidence | Gap or exclusion rationale |
| --- | --- | --- | --- |
| F-11 — Session cleanup and already-logged-out success; section 2 | Clear state associated with the notified session, including relevant cookies/browser storage; already being logged out counts as success. | **Adjacent local cookie cleanup only.** The POST handler clears OIDC session/chunk and request-state cookies and rotates the local generation marker. No iframe receiver invokes that logic, and no browser-storage cleanup page/script exists. [Local logout handler], [cookie state handler], [authentication orchestrator], [feature route tests]. | Existing cleanup is a reusable internal building block, not protocol support. Application-owned login state in browser storage would need appropriate application integration; the provider itself stores its local session in protected cookies. This rule is not an instruction to erase unrelated application storage. |
| F-12 — `Cache-Control: no-store` on the RP response; section 2 | Prevent a cached iframe response from replacing a later logout request. | **Missing Front-Channel response handling.** There is no notification response/page with this caching policy. Existing `no-store` validation reads upstream Token Endpoint responses; it does not emit a Front-Channel response header. [HTTP feature: setup], [local logout handler], [HTTP response checks], [endpoint client]. | The header is a SHOULD in this spec. This is part of implementing the absent receiver, not evidence of an exploitable caching defect in the existing local POST logout path. |
| F-13 — Third-party state access and defensive failure UX; section 4.1 | Detect when browser restrictions prevent iframe access to RP login state and, where possible, tell the user that RP logout could not be performed. | **Missing browser integration.** No iframe delivery/state-access check or notification-failure UI. Current OIDC cookies are created with `Secure`, `HttpOnly` and `SameSite=Lax`; there is no Front-Channel-specific cookie/browser profile. [Cookie state handler], [HTTP feature], [local logout handler]. | The spec warns of conditional browser cookie/storage restrictions and recommends defensive handling, without defining a universal detection algorithm. This needs deployment/browser testing, not a claim that it always works or can never work. Changing cookie attributes alone would not implement the missing receiver or remove all third-party restrictions. |

### OP and dual-role responsibilities

Spec references: [OP session tracking and iframe dispatch](https://openid.net/specs/openid-connect-frontchannel-1_0.html#OPLogout),
[downstream cascade](https://openid.net/specs/openid-connect-frontchannel-1_0.html#RPLogout), and
[session-ID security](https://openid.net/specs/openid-connect-frontchannel-1_0.html#Security).

| ID / OP or intermediary feature | What the feature provides | Current support and evidence | Gap or exclusion rationale |
| --- | --- | --- | --- |
| F-14 — OP tracking and parallel iframe notifications; section 3 | Remember participating logged-in RPs and build the page that loads their registered logout URLs in parallel. | **Outside the component's role.** It consumes an external OP; no OP login-session/RP roster, logout fan-out page or Discovery publication is implemented. [README](README.md#supported-standards-boundary), [HTTP feature: setup], [local logout handler]. | The OP delivers these notifications; an RP receiving them need not implement an identity server or call every other RP. The spec's example of a visited-sites cookie is an OP storage approach, not a mandated RP cookie format. |
| F-15 — RP that also acts as an OP: downstream cascade; section 2 | Propagate logout to downstream sessions using nested iframe content when the receiving RP is itself an identity provider. | **Outside this component's current RP-only identity role.** No downstream OIDC session issuer or nested logout page. [README](README.md#supported-standards-boundary), [HTTP feature]. | This conditional intermediary/broker scenario is not a missing requirement for an ordinary RP. A Helidon application could implement an identity broker separately; the framework is not inherently incapable of serving the necessary content. |
| F-16 — Session-ID creation, uniqueness and entropy; sections 3, 5 | Issue opaque session strings unique within an issuer and sufficiently unpredictable to resist guessing/collisions. | **Outside the RP for OP-issued identifiers.** This provider consumes ID Tokens and does not mint their session IDs. Its random browser-generation value protects a different local cookie lifecycle. [ID Token validator], [cookie state handler], [subject mapper]. | OP session-ID generation is not an RP API gap. The spec does not prescribe a UUID or fixed entropy bit count here. Reusing the local generation marker as an OP-issued identifier would conflate unrelated state. |

### Front-Channel Logout overview: missing feature, not an impossible one

There is no built-in implementation of this notification protocol at this baseline. The provider can end its own
cookie-backed session and initiate OP logout, but cannot automatically receive an OP iframe notification to end the
matching RP session. Registering the existing `/oidc/logout` route with an OP does not bridge that gap: the route's
POST/same-origin contract serves a different purpose. Likewise, preserving an ID Token's session claim does not create
a session-aware notification handler.

Assessment: for Helidon web applications this is a feasible, potentially useful feature. Supporting it would require an
incoming notification path tied to RP session data and cleanup, the appropriate registration/configuration semantics, response
cache handling and browser integration/tests. Existing internal cookie cleanup, generation protection and ID Token
claim handling are useful building blocks; there is no reason in this spec alone to duplicate them or mandate a new
global session database. How application-owned browser state is cleared would need an explicit integration boundary.

Browser restrictions are a real deployment constraint identified by the spec, not evidence that all deployments fail
or that supporting the protocol is intrinsically unsuitable for Helidon. The current `SameSite=Lax` cookie profile and
local POST origin check are not a tested iframe logout solution. Relaxing those protections or changing flags alone
is not an implementation plan. No current browser compatibility matrix or universal workaround is claimed here.
For an application without an end-user browser to deliver notifications, a server-side HTTP call cannot stand in for
the specified browser-context operation.

OP session tracking, notification fan-out, session-ID issuance and an identity broker's downstream cascade are different
roles, not mandatory additions to an ordinary RP. Front-Channel Logout may complement the already-assessed mechanisms;
Back-Channel Logout is assessed separately in section 7. This inventory records a missing extension, not a new
exploitability finding or a reason to reopen deferred earlier review items.

### Front-Channel Logout assessment method and limits

Checked the final 2022 local copy against the official publication. Both notification parameters, both client-registration
fields, both OP Discovery fields and the ID Token session-claim role are explicitly mapped. The `sid` query parameter
and `sid` claim are intentionally separate inventory roles. The IANA section registers names already described by the
protocol; it is not a new RP runtime operation.

Inspected the feature's routes, the full local logout handler, logout/end-session/endpoint configuration, tenant URI
validation, Discovery parsing/model, protected state serialization, subject mapping and relevant test sources. Searches
of the module's source/resources and its synthetic/Keycloak integration sources found no dedicated Front-Channel handler,
metadata configuration, iframe/storage script or protocol test path. The existing GET-negative/local-cleanup route tests
are evidence of the local endpoint's boundary, not Front-Channel compliance tests.

The [Keycloak logout tests] exercise RP-Initiated Logout with a [WebClient-based browser test helper], not a browser that
renders iframe pages or enforces third-party storage policy. They do not establish Front-Channel delivery, storage access
or UI behavior. No runtime tests, browser probes, production changes or OP registration mutations were performed in this
documentation pass. Required parameter pairing, optional RP matching, recommended response caching and conditional
browser constraints have not been conflated into unconditional RP MUSTs.

Front-Channel Logout assessment is complete for this baseline. Back-Channel Logout is assessed separately below;
all prior feature assessments are preserved.

## 7. OpenID Connect Back-Channel Logout 1.0

Assessed: 2026-09-25. Source: [Back-Channel Logout 1.0 incorporating errata set 1](https://openid.net/specs/openid-connect-backchannel-1_0.html),
matching the supplied `oidc-specs/openid-connect-backchannel-1_0.html` (Final incorporating errata, 15 December 2023).
The implementation baseline is unchanged. In this edition, a Logout Token's `exp` claim is REQUIRED.

This specification delivers an OP logout notification directly to an RP server using a signed Logout Token in an HTTP
POST. It does not depend on an iframe or the end-user's browser sending RP cookies. The RP must identify and terminate
the affected sessions using the received information and its own application-specific session mechanism. It can be
used independently of, or together with, the other OIDC logout specifications.

No built-in Back-Channel Logout receiver was found. The README lists the feature as queued; that is a documented current
gap, not a permanent prohibition or an architectural impossibility. A browser-oriented local POST logout endpoint and
general JWT validation are not sufficient evidence that this protocol is implemented.

### Incoming notification, complete metadata inventory, and endpoint contract

Spec references: [protocol context](https://openid.net/specs/openid-connect-backchannel-1_0.html#Introduction),
[OP Discovery metadata](https://openid.net/specs/openid-connect-backchannel-1_0.html#BCSupport),
[RP registration](https://openid.net/specs/openid-connect-backchannel-1_0.html#BCRegistration), and
[notification transport](https://openid.net/specs/openid-connect-backchannel-1_0.html#BCRequest).

Both OP Discovery fields and both client-registration fields defined by this specification are listed below.
The two advertised capability flags and the client's session-required setting each default to `false` in the spec;
none is currently modelled as a Back-Channel capability/policy by this provider.

| ID / Back-Channel feature or metadata | What the feature provides | Current support and evidence | Gap or exclusion rationale |
| --- | --- | --- | --- |
| B-01 — Direct OP-to-RP logout notification; sections 1, 2.5 | Receive a server-to-server logout request independently of the user's browser. | **Missing protocol receiver.** Route setup provides login callbacks and the local browser POST logout handler, which checks same-origin headers and reads RP cookies. No incoming Logout Token route/processor exists. [HTTP feature: setup], [local logout handler], [README: coverage matrix](README.md#provider-coverage-matrix). | Sharing the POST method does not make the local route a Back-Channel endpoint. Local cookie deletion/RP-Initiated Logout are different operations. The documented queued status does not establish that Helidon could not support the extension. |
| B-02 — `backchannel_logout_supported`; section 2.1 | Advertise whether an OP supports this notification protocol; omitted means `false`. | **Not consumed.** No Discovery model field or capability policy uses this value. [Discovery metadata model: fromWellKnownMetadataJson], [endpoint configuration]. | Advertising support at the OP does not activate an RP receiver. Publishing OP metadata is a separate issuer responsibility; a missing consumer is not evidence about the external OP's actual capabilities. |
| B-03 — `backchannel_logout_session_supported`; section 2.1 | Advertise OP support for a session ID in Logout Tokens and ID Tokens; omitted means `false`. | **Not consumed.** No metadata-driven Back-Channel session handling or local equivalent setting. [Discovery metadata model], [endpoint configuration], [local logout handler]. | Generic preservation of an ID Token session claim is separate from consuming this capability and correlating a notification. It must not be counted as full protocol support. |
| B-04 — `backchannel_logout_uri`; section 2.2 | Register the RP server URL to which the OP sends Logout Tokens. | **Missing dedicated configuration/endpoint and registration handling.** Local logout/end-session configuration has no Back-Channel option; no registration exchange publishes this URL. [Local logout configuration], [end-session configuration], [HTTP feature: setup]. | OP registration can be managed out of band; Dynamic Registration is not required to use the protocol. Registering the existing browser logout URL does not supply the missing token-processing/session-termination behavior. |
| B-05 — `backchannel_logout_session_required`; section 2.2 | Optionally require a session-ID claim in Logout Tokens; omitted means `false`. | **Missing registration setting and enforcement.** No Back-Channel session-ID requirement is configured or applied. [Local logout configuration], [end-session configuration], [local logout handler]. | The spec recommends registering the related setting when using Dynamic Registration, not requiring every RP to select `true`. Without that requirement, a valid token may identify the user by subject without a session ID. The outgoing ID Token hint setting is unrelated. |
| B-06 — Registered URL, query retention and reachability; sections 1, 2.2 | Use an absolute, fragment-free URI, retaining any form-encoded query component; make the endpoint reachable by the relevant OPs. | **Missing Back-Channel-specific endpoint integration.** Existing local logout accepts a local path and has no Back-Channel URL/registration validation. [Endpoint URI validation], [local logout configuration], [tenant validation]. | HTTPS is recommended; HTTP is permitted for a confidential client if the OP allows it. This spec does not impose Front-Channel Logout's login-callback-origin rule. Deployment needs OP-to-RP network reachability; publishing an appropriate endpoint need not expose every RP node or the whole private application. |

### Request encoding, cryptographic protection, and token type

Spec references: [request body](https://openid.net/specs/openid-connect-backchannel-1_0.html#BCRequest),
[Logout Token format](https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken),
[validation steps 1–3](https://openid.net/specs/openid-connect-backchannel-1_0.html#Validation), and
[cross-JWT confusion](https://openid.net/specs/openid-connect-backchannel-1_0.html#CrossJWT).

| ID / Request or token-profile feature | What the feature provides | Current support and evidence | Gap or exclusion rationale |
| --- | --- | --- | --- |
| B-07 — `logout_token` form parameter; section 2.5 | Carry the signed Logout Token in an `application/x-www-form-urlencoded` POST body; additional unrecognized body values MUST be ignored. | **Missing request parser/dispatch.** The local logout handler reads cookies and selected URL query parameters, not this form field. No Back-Channel body-processing path is registered. [Local logout handler], [HTTP feature: setup]. | A generic POST route, Bearer authentication filter, or outbound form-encoding client is not the required receiver. The Logout Token belongs in this form field, not in an authorization-code callback or browser ID Token hint. |
| B-08 — Signature and `alg`; sections 2.4, 2.6 steps 2–3 | Require a signature and apply ID Token signing keys/algorithm policy; `none` MUST NOT be used, and RS256 SHOULD be the default when metadata/registration does not otherwise govern selection. | **Reusable verification primitives only.** Existing ID Token validation uses the OP key manager, configured algorithms and shared OIDC signature verification, but there is no Logout Token validation entry point. [ID Token validator], [OP key manager], [ID Token configuration]. | Existing signature support is not incoming Back-Channel support. The signature provides the protocol's proof of origin; a local same-origin HTTP-header check does not replace it. Reuse of key/signature machinery would still require the distinct Logout Token claim profile. |
| B-09 — Optional encryption and issuer header; sections 2.4, 2.6 step 1 | Decrypt encrypted Logout Tokens with the ID Token encryption keys/algorithms negotiated at registration; the encrypted token SHOULD replicate its issuer in a header. | **Reusable decryption primitives only.** ID Token decryption with explicit RP keys and algorithm policy exists, but is not connected to a Back-Channel receiver or replicated-issuer processing. [ID Token decryptor], [ID Token configuration], [local logout handler]. | Signing remains mandatory even when encryption is used. If ID Token encryption was negotiated and the Logout Token is unencrypted, rejection is a SHOULD, not an unconditional MUST. The spec reuses ID Token key material rather than defining an unrelated logout-key provisioning protocol. |
| B-10 — `typ` and token-purpose separation; sections 2.4, 4.1, 5.3 | Recommend explicit `logout+jwt` typing and prevent use of a token in the wrong protocol context. | **Missing dedicated Logout Token profile.** No consumer recognizes this type or applies the Logout Token's event/nonce rules. Existing ID Token validation has its own subject/nonce requirements and cannot be used unchanged as the complete Logout Token validator. [ID Token validator], [HTTP feature: setup]. | Explicit typing is RECOMMENDED; this spec does not universally require rejecting every untyped Logout Token. It discusses stricter new deployment profiles separately. The registered `application/logout+jwt` media type does not change the form-encoded POST contract. No token-confusion exploit is inferred solely from an absent receiver. |

### Complete Logout Token claim inventory

Spec references: [claim definitions](https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken)
and [mandatory and optional validation steps](https://openid.net/specs/openid-connect-backchannel-1_0.html#Validation).
These are claims in this OIDC Logout Token profile, not a separate general JWT specification assessment. Existing
ID Token validation is identified only where it provides relevant underlying code, not as a claim of Back-Channel support.

| ID / Logout Token claim | What the feature provides | Current support and evidence | Gap or exclusion rationale |
| --- | --- | --- | --- |
| B-11 — `iss` | REQUIRED: identify and validate the OP issuer using ID Token issuer-validation rules. | **Missing for Logout Tokens.** Ordinary ID Token validation checks the configured/discovered issuer, but no Back-Channel receiver applies that check to a Logout Token. [ID Token validator], [Discovery metadata model], [local logout handler]. | A signed payload's issuer still must be bound to the trusted OP; it is not an arbitrary tenant selector. Additional comparison with an ID Token from a current/recent session is a separate optional validation step, not a relaxation of this base requirement. |
| B-12 — `sub` | OPTIONAL individually, but at least one of subject or session ID is REQUIRED; without a session ID, target all RP sessions for the issuer/subject pair. | **Missing Logout Token claim/action handling.** Subject data and mapping exist for authenticated users, but no notification-specific subject-only logout path. The existing full ID Token validator always requires a subject. [ID Token validator], [subject mapper], [local logout handler]. | A valid session-ID-only Logout Token cannot be rejected just for lacking a subject under the base profile. Reusing the complete ID Token validator unchanged would impose that unrelated requirement. Subject identifiers must not be treated as globally unique across issuers. |
| B-13 — `aud` | REQUIRED: identify the intended RP audience(s) and validate them under ID Token audience rules. | **Missing for Logout Tokens.** ID Token client-audience checking exists, but no Logout Token consumer uses the RP/client audience policy. [ID Token validator], [tenant client settings], [local logout handler]. | Successful API access-token/Bearer authentication is not evidence that a Logout Token is addressed to this RP client. The recipient and tenant/client context must remain bound to the validated notification. |
| B-14 — `iat` | REQUIRED: carry the issue time and validate it as for an ID Token. | **Missing for Logout Tokens; time-validation primitive exists.** The ID Token validator configures issue-time checking and clock skew, but there is no Back-Channel validation path. [ID Token validator: claimValidator], [ID Token configuration]. | The presence of a general timestamp validator does not implement this request profile or an incoming replay policy. Issue time, expiration and optional duplicate-token detection are distinct checks. |
| B-15 — `exp` | REQUIRED in errata set 1: carry an expiration time and validate it using ID Token expiration rules. | **Missing for Logout Tokens; expiration primitive exists.** Mandatory ID Token expiration checking is implemented, not connected to a Logout Token receiver. [ID Token validator: claimValidator], [ID Token configuration]. | This assessment must not describe expiration as optional in the supplied edition. OP guidance for short Logout Token lifetimes is separate from an unconditional RP-side two-minute maximum; token expiry is also distinct from the RP session's own lifetime. |
| B-16 — `jti` | REQUIRED: uniquely identify the Logout Token; optionally check whether the same identifier was received recently. | **Missing Logout Token identifier/replay handling.** There is no incoming Logout Token consumer or recent-identifier check. Generating unique IDs for outgoing client-authentication assertions is unrelated. [Local logout handler], [client authentication]. | Required claim presence and optional replay detection are different requirements: validation step 8 is explicitly optional. Neither outgoing ID generation nor generic request/refresh coordination is an incoming replay ledger. No universal mandatory replay-cache lifetime is specified here. |
| B-17 — `events` | REQUIRED: a JSON object containing `http://schemas.openid.net/event/backchannel-logout`, whose value MUST be an object and SHOULD be empty. | **Missing Logout Token event validation.** No event-claim/profile consumer exists. General JWT/JSON handling and ID Token validation do not test for this logout event. [ID Token validator], [local logout handler]. | The event identifier marks the token's purpose; it is not an endpoint to fetch. Checking only that some `events` claim exists would not cover this contract. The empty member value is recommended, not the only permitted object value. |
| B-18 — `sid` | OPTIONAL individually; with subject, or instead of subject, identify the OP/RP session. At least one of the two is REQUIRED, and registration may require the session ID. | **Missing incoming session-ID processing.** No Logout Token extraction, session selector or session-required policy. ID Token claim data is only an adjacent source for possible correlation. [Local logout handler], [subject mapper], [local session state]. | The ID is opaque and issuer-scoped, not necessarily a UUID. Without it, the subject-based request covers all sessions for that issuer/subject at the RP. A local tenant ID or browser-generation marker cannot replace the OP-issued value. |
| B-19 — `nonce` (prohibited) | MUST NOT be present; distinguish a Logout Token from an authentication assertion. | **Missing Logout Token prohibition check.** The ordinary login validator instead requires and matches the authentication transaction's nonce; refresh validation has different Core rules. Neither is this profile. [ID Token validator], [local logout handler]. | This is a prohibition on the claim's presence, not an optional nonce comparison. It is one reason not to reuse the full ID Token validator unchanged. The missing receiver does not establish a reachable token-substitution attack against an existing login path. |

### Extensibility and additional session-correlation checks

Spec references: [additional token claims](https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken)
and [additional validation](https://openid.net/specs/openid-connect-backchannel-1_0.html#Validation).

| ID / Additional validation feature | What the feature provides | Current support and evidence | Gap or exclusion rationale |
| --- | --- | --- | --- |
| B-20 — Other Logout Token claims; section 2.4 | Permit extension claims and ignore claims the implementation does not understand. | **Missing end-to-end Logout Token handling.** There is no protocol parser/validator to apply this rule. Existing generic token/claim handling is not an extension-acceptance contract for logout. [ID Token validator], [subject mapper], [local logout handler]. | Ignoring unknown claims is a MUST, not a reason to skip validation of known required claims, the required event structure or the prohibited nonce. Unknown POST form fields are covered separately in B-07. |
| B-21 — Additional current/recent-session comparisons; section 2.6 steps 9–11 | Optionally compare the issuer, subject and session-ID values with those in an ID Token from a current or recent session. | **Missing Back-Channel correlation path.** No notification-specific comparison or retained association is used. Existing login/refresh identity validation is a different workflow. [ID Token validator], [local logout handler], [authentication orchestrator]. | These extra comparisons are optional; mandatory trusted-issuer/audience validation and locating the sessions to terminate remain necessary. Their optional status does not allow an arbitrary issuer or make actual session termination optional. |
| B-22 — `sid` in stored ID Tokens; section 2.1 | Preserve the OP session identifier, together with issuer/subject, as possible correlation data. | **Generic data preservation only.** The protected local cookie retains the original ID Token, including its claims; subject mapping prevents UserInfo from replacing the ID Token's issuer/subject/session-ID claims. Normal authentication retrieves this data from browser cookies. [Cookie state handler], [subject mapper], [local session state]. | There is no Back-Channel session lookup service or notification association. The OP's server request does not carry the browser's protected state, and the RP's local generation cookie is not the OP session ID or a server-authoritative invalidation record. |

### Session termination and refresh-token lifecycle

Spec references: [absence of browser state](https://openid.net/specs/openid-connect-backchannel-1_0.html#Introduction)
and [required logout actions](https://openid.net/specs/openid-connect-backchannel-1_0.html#BCActions).

| ID / Session action | What the feature provides | Current support and evidence | Gap or exclusion rationale |
| --- | --- | --- | --- |
| B-23 — Locate and terminate the affected RP sessions; section 2.7 | After validation, identify the indicated issuer/subject/session(s) and clear their associated state using an application-specific mechanism. | **Missing server-side notification effect.** Local authentication restores cookie state, checks the browser-generation marker and handles refresh/expiry, without consulting a Back-Channel invalidation signal. The local logout route sends cookie changes to its caller. [Authentication orchestrator], [cookie state handler], [local logout handler]. | A response to the OP cannot delete cookies in the user's browser. Assessment: implementing this requires an authoritative server-side or application-provided invalidation/session mechanism that affects subsequent authentication, including subject-wide logout when no session ID is supplied. The spec does not mandate moving all token data into a particular database or prescribing one storage product. |
| B-24 — Refresh tokens with/without `offline_access`; section 2.7 | Session-bound refresh tokens without offline access SHOULD be revoked; refresh tokens issued with offline access normally SHOULD NOT be revoked. | **Missing Back-Channel lifecycle integration.** Refresh handling and token data exist, but no validated logout notification selects affected credentials or initiates revocation. [Refresh manager], [endpoint client], [local session state]. | Discarding a local token copy is not revocation at its issuer. This spec states the token-lifecycle policy without prescribing one particular RP revocation API call; OP-side handling also matters. It is not a requirement to revoke all tokens, nor a guarantee that every previously issued access token becomes unusable. |

### Responses, idempotency, and diagnostic fields

Spec references: [validation failure](https://openid.net/specs/openid-connect-backchannel-1_0.html#Validation),
[already-logged-out handling](https://openid.net/specs/openid-connect-backchannel-1_0.html#BCActions), and
[response contract](https://openid.net/specs/openid-connect-backchannel-1_0.html#BCResponse).

| ID / Response feature | What the feature provides | Current support and evidence | Gap or exclusion rationale |
| --- | --- | --- | --- |
| B-25 — Success, failure and already-ended sessions; sections 2.6–2.8 | RP MUST return 200 on successful logout and 400 for an invalid request/failed logout; an already-logged-out target is success for a valid notification. | **Missing protocol response/action contract.** The local browser route's 204/303/400/403/502/503 outcomes belong to another API, not this receiver. [Local logout handler], [HTTP feature: setup]. | The spec tells OPs to tolerate framework-generated 204 success, but the stated RP success requirement remains 200. An optional replay check that rejects a token during validation is distinct from treating an already-ended session as a failed valid logout action. |
| B-26 — `error`, `error_description`; section 2.8 | Optionally return JSON diagnostic details on failure; `error` is required when that body is present, description optional. | **Missing Back-Channel diagnostic response.** No receiver generates the specified `application/json` error body. Local browser logout sends plain diagnostic text for its own failures. [Local logout handler], [HTTP feature]. | `invalid_request` is an allowed error value for request syntax problems. A response body is optional; the HTTP failure status is not. The spec describes these values as debugging information, not a basis for different runtime behavior keyed by individual error strings. |
| B-27 — `Cache-Control: no-store`; section 2.8 | Recommend preventing caches from interfering with later logout exchanges. | **Missing Back-Channel response policy.** No notification response handler exists. The existing cache-header helper examines upstream Token Endpoint responses rather than emitting this response. [HTTP response checks], [endpoint client], [local logout handler]. | This is a SHOULD for the protocol being implemented, not a demonstrated cache vulnerability in a different existing endpoint. Neither ordinary POST handling nor token-response cache validation is Back-Channel support. |

### OP delivery, token issuance, and dual-role responsibilities

Spec references: [OP tracking](https://openid.net/specs/openid-connect-backchannel-1_0.html#Tracking),
[delivery/retransmission](https://openid.net/specs/openid-connect-backchannel-1_0.html#BCRequest),
[token issuance and short expiry](https://openid.net/specs/openid-connect-backchannel-1_0.html#Security), and
[downstream cascade](https://openid.net/specs/openid-connect-backchannel-1_0.html#BCActions).

| ID / OP or intermediary feature | What the feature provides | Current support and evidence | Gap or exclusion rationale |
| --- | --- | --- | --- |
| B-28 — OP RP roster, dispatch and retransmission; sections 2.3, 2.5 | Remember logged-in RPs, send notifications (parallel sending encouraged), and delay retries for suspected recoverable delivery failures. | **Outside the component's role.** This provider is an RP/client/resource-server component, not an OP with an RP roster and notification sender. [README](README.md#supported-standards-boundary), [HTTP feature], [endpoint client]. | The spec discourages other retransmissions and gives no universal fixed retry interval/count. This is sender behavior, not a requirement for an RP to start notification fan-out/retry workers. A visited-sites cookie is an illustrative OP tracking choice, not mandatory RP storage. |
| B-29 — Issue protected Logout Tokens with short lifetimes; sections 2.4, 4 | Create correctly addressed/signed, optionally encrypted logout assertions; prefer short expiry, ideally no more than two minutes ahead. | **Outside the component's role: OP token issuance.** No OP Logout Token issuer exists. Outgoing client-authentication assertions are different messages, despite also having signatures, timestamps and token IDs. [Client authentication], [README](README.md#supported-standards-boundary). | OP issuance must satisfy the profile's required claims and signing rules. The short-expiry text is guidance to OPs, not a universal RP rejection threshold or the required duration of session-invalidation state. No new Logout Token signing API is required merely to receive notifications. |
| B-30 — RP that also acts as an OP: downstream cascade; section 2.7 | Propagate logout to downstream RPs when the receiving RP is itself their identity provider. | **Outside this component's current identity role.** No downstream OP sessions or notification sender are implemented. [README](README.md#supported-standards-boundary), [HTTP feature], [local logout handler]. | This is the conditional broker/intermediary scenario, not a missing responsibility of an ordinary RP. A Helidon application can implement such a role separately; it is not forbidden by the framework. |

### Back-Channel Logout overview: feasible, with a session-state boundary

Back-Channel Logout is not built in at this baseline, and the README identifies it as queued. The missing functionality
includes registration/configuration semantics, an OP notification receiver, a distinct Logout Token validation profile,
session selection/invalidation, token-lifecycle integration and the response contract. Existing OP-key handling,
signature verification, decryption, JSON/claim data and local cookie cleanup are useful implementation components, not
proof of an end-to-end notification feature.

Assessment: this is feasible and useful for server-side Helidon RPs. The significant design requirement is making the
notification affect authentication without having the browser present. Local cookie clearing currently works by sending
changes to that browser; returning those headers to an OP server would leave the browser's cookies unchanged. A future
receiver needs an authoritative session/invalidation mechanism, possibly application-provided, which subsequent RP
authentication consults. It does not follow that every token must move to a new central database. State scope, lifetime,
concurrency and multi-node consistency would need an explicit design; Logout Token expiry alone is not the lifetime of
the sessions being terminated.

Validation primitives can be reused, but the whole ID Token validator cannot simply be reused unchanged: a Logout Token
allows session-ID-only identification, requires the logout event and token ID, and prohibits nonce. This edition also
requires expiration. Mandatory issuer/audience/signature/time validation is distinct from optional recent-token replay
checks and extra comparisons against earlier ID Tokens. Explicit typing is recommended, not universally mandatory.

Network reachability is a deployment requirement: the OP must reach the registered RP endpoint. Browser iframe/cookie
access restrictions are not this delivery mechanism's dependency, but backend delivery failures remain possible.
Support does not require implementing the OP's roster, token-issuance or dispatch roles. It also does not imply native
application session integration merely because a Helidon backend can receive HTTP requests; the application-specific
session-termination boundary still has to exist.

This records a missing extension and its actual integration needs, not a demonstrated exploit or blanket nonconformance
of an RP that does not claim the extension. No particular storage product, unused public API, or implementation change
is proposed by this inventory. Standalone JWT/JOSE, token revocation and general event-delivery specifications are not
separate coverage entries; their concepts appear only where this OIDC specification uses them.

### Back-Channel Logout assessment method and limits

Checked the local errata-set-1 edition against the official publication. Accounted for both OP metadata fields, both
client-registration fields, the ID Token session-claim role, the form parameter, all eight defined Logout Token claims,
the prohibited nonce and both named error-response fields. All eleven numbered validation steps are mapped: decryption
(B-09), signature/algorithm (B-08), issuer/audience/times (B-11/B-13–15), subject/session presence (B-12/B-18), event (B-17),
nonce prohibition (B-19), optional replay detection (B-16), and optional previous-session comparisons (B-21).

Inspected route registration, the local logout handler/configuration, Discovery parsing, ID Token validation/decryption,
cookie serialization/authentication and generation checks, subject mapping, refresh handling and relevant source/test
searches. No incoming Logout Token parser, metadata policy, event/replay processor or notification-driven invalidation
path was found. Existing [feature route tests] and [Keycloak logout tests] cover the local/RP-Initiated paths, not receipt
of these OP notifications. Existing JWT, decryption or client-assertion tests are not Logout Token conformance evidence.

No new runtime tests, OP notification probes, browser tests, registration changes, production edits or commit were
performed. This source/spec pass does not claim a newly demonstrated token-confusion attack, a universal two-minute RP
limit, a mandatory replay cache or a particular session-storage architecture. Previous findings/deferred items are not
reopened by documenting an extension boundary.

Back-Channel Logout assessment is complete for this baseline. CIBA is assessed separately below.
All prior feature assessments are preserved.

## 8. OpenID Connect Client-Initiated Backchannel Authentication Flow - Core 1.0 (CIBA)

Assessed: 2026-09-25. Source: [CIBA Core 1.0](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html),
matching the supplied `oidc-specs/openid-client-initiated-backchannel-authentication-core-1_0.html` (Final, 1 September 2021).
The implementation baseline is unchanged.

CIBA lets a client that already has a user identifier request authentication directly from the OP. The user approves
on an authentication device, separate in role from the consumption device where the service interaction occurs.
Tokens arrive asynchronously through registered Poll, Ping or Push delivery. It is neither the browser authorization-code
flow nor Back-Channel Logout, and its client does not implement the OP's authentication-device interaction.

The README explicitly places CIBA outside the implemented client profile. Source inspection found no CIBA request,
grant, transaction or notification handler. Existing HTTP, client-authentication and token-processing components may
be useful building blocks; their presence is not end-to-end CIBA support. This is a current scope boundary, not a claim
that server-side Helidon applications cannot support the flow.

### Client role and complete CIBA Discovery metadata inventory

Spec references: [flow overview](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#overview)
and [registration/Discovery metadata](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#registration).
The four OP metadata fields introduced by CIBA are listed here; reused Core metadata is assessed separately below.

| ID / CIBA role or OP metadata | What the feature provides | Current support and evidence | Gap or exclusion rationale |
| --- | --- | --- | --- |
| A-01 — CIBA client workflow; sections 1–3, 5–6 | Initiate user authentication without a browser redirect and obtain its asynchronous result through Poll, Ping or Push. | **Missing; outside the documented current client profile.** No CIBA grant/request builder, outstanding-authentication transaction manager or notification receiver. Existing routes serve code callbacks/local logout, and token requests use other grants. [README](README.md#supported-standards-boundary), [HTTP feature: setup], [endpoint client], [request factory]. | Potentially useful for call-center, point-of-sale or other decoupled authentication applications. Being a server-side RP is not an obstacle. General token endpoint calls or background refresh do not implement this flow, and the RP need not become an OP to add client support. |
| A-02 — `backchannel_token_delivery_modes_supported`; section 4 | REQUIRED OP metadata advertising one or more of Poll, Ping and Push. | **Not consumed.** No CIBA delivery-capability model or selection/validation policy. [Discovery metadata model: fromWellKnownMetadataJson], [endpoint configuration]. | An OP's advertised modes do not enable any mode in this provider. Required publication applies to OPs advertising CIBA; an ordinary non-CIBA RP is not thereby required to implement all three modes. |
| A-03 — `backchannel_authentication_endpoint`; sections 4, 7 | REQUIRED OP metadata locating the direct authentication-initiation endpoint; communication with it MUST use TLS. | **Not consumed; no explicit equivalent CIBA setting.** Existing endpoint configuration/parser does not expose this endpoint. [Discovery metadata model], [endpoint configuration], [endpoint client]. | This is not the ordinary Authorization Endpoint, Token Endpoint or a logout endpoint. Configuring an existing endpoint URL to point there would not supply the CIBA request body or asynchronous lifecycle. |
| A-04 — `backchannel_authentication_request_signing_alg_values_supported`; section 4 | Optionally advertise accepted signed CIBA request algorithms; omission means signed authentication requests are unsupported. | **Not consumed.** No CIBA request-signing metadata/profile. Existing Request Object metadata and processing serve code-flow authorization/PAR requests. [Discovery metadata model], [Request Object processor], [request factory]. | Generic signing support cannot establish that a signed CIBA request is correctly composed or negotiated. The separate CIBA signing capability must not be inferred from Core Request Object metadata. |
| A-05 — `backchannel_user_code_parameter_supported`; section 4 | Optionally advertise OP support for a user-supplied secret code; omitted means `false`. | **Not consumed.** No corresponding CIBA capability/configuration or user-code request handling. [Discovery metadata model], [authorization configuration], [request factory]. | User-code support is optional and requires the corresponding client registration setting. An absent CIBA extension is not a Helidon inability to accept application input or a requirement to add a credential-collection UI to the provider. |

### Complete CIBA-specific client registration metadata inventory

Spec references: [client registration](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#registration)
and [Client Notification Endpoint](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#backchannel_client_notification_endpoint).
These four fields are introduced by CIBA. Registration can be managed externally; the lack of a Dynamic Registration
client is not, by itself, what prevents CIBA support here.

| ID / CIBA client metadata | What the feature provides | Current support and evidence | Gap or exclusion rationale |
| --- | --- | --- | --- |
| A-06 — `backchannel_token_delivery_mode`; section 4 | REQUIRED: choose one of Poll, Ping or Push at registration time. | **Missing configuration/registration and lifecycle.** No CIBA mode option or dispatcher exists. [Provider configuration], [tenant client settings], [endpoint client], [HTTP feature]. | Choosing one registered mode is different from a browser response mode or selecting a different OAuth outbound grant. Supporting a CIBA client does not require implementing every delivery mode, but the chosen mode needs its complete workflow. |
| A-07 — `backchannel_client_notification_endpoint`; sections 4, 9 | REQUIRED for Ping/Push: register an HTTPS endpoint for success/failure notifications; communication MUST use TLS. | **Missing dedicated endpoint/configuration.** No notification receiver or registration field; the feature only registers code-flow callbacks and local logout. [HTTP feature: setup], [tenant client settings]. | Poll does not require this endpoint. The authorization-code redirect URI and local logout URI are not interchangeable notification handlers. An application can manage registration externally, but that alone does not supply the authenticated callback workflow. |
| A-08 — `backchannel_authentication_request_signing_alg`; section 4 | Optionally select the algorithm for signed authentication requests; clients intending to sign MUST register it, and omission means they will not send signed requests. | **Missing CIBA-specific setting/registration.** Existing Request Object settings do not represent this field or generate CIBA requests. [Request Object configuration], [request factory], [tenant client settings]. | Available signing keys/algorithms are reusable components, not evidence of CIBA negotiation. The signed authentication-request profile is assessed below rather than inferred from code-flow Request Objects. |
| A-09 — `backchannel_user_code_parameter`; sections 4, 7.1.2 | Optionally declare client support/requirement for user-code handling, applicable when the OP advertises support; omitted means `false`. | **Missing setting and input workflow.** No CIBA user-code policy, request input or registration exchange. [Tenant client settings], [authorization configuration], [request factory]. | The application would collect the code when required; the OP verifies it. This setting is not permission for the client to store the code, and it does not make the RP responsible for issuing the user's code or implementing the OP's credential management. |

### Shared metadata, pairwise identifiers, and request transport

Spec references: [shared metadata and pairwise registration](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#registration),
[Backchannel Authentication Endpoint](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#auth_backchannel_endpoint), and
[authenticated request](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#auth_request).

| ID / Registration or transport feature | What the feature provides | Current support and evidence | Gap or exclusion rationale |
| --- | --- | --- | --- |
| A-10 — CIBA grant and reused client-authentication metadata; section 4 | Poll/Ping clients MUST register `urn:openid:params:grant-type:ciba` in `grant_types`; OPs advertise it in `grant_types_supported`. Backchannel Authentication uses the token endpoint's advertised/registered client-authentication methods and signing algorithms. | **Shared metadata/primitives only.** Grant lists and token-endpoint authentication metadata are consumed for implemented flows, but the CIBA grant is not selected, registered or sent. [Discovery metadata model], [tenant metadata validation], [endpoint client], [client authentication]. | Storing an advertised grant string is not implementing it. The relevant shared fields are `token_endpoint_auth_methods_supported`, `token_endpoint_auth_signing_alg_values_supported` and client `token_endpoint_auth_method`; they do not replace the missing CIBA endpoint/mode workflow. Push delivers its result directly instead of using this token-retrieval grant. |
| A-11 — Poll/Ping pairwise subject registration and key proof; section 4 | Use the client's public `jwks_uri`/sector registration and demonstrate possession of its key for pairwise identifiers, through an asymmetric signed request, private-key JWT authentication or self-signed-certificate mTLS. | **Partial building blocks only.** Private-key JWT/mTLS mechanisms and opaque subject handling exist, but no CIBA pairwise registration/URI-ownership workflow. [Client authentication], [client assertion configuration], [WebClient factory], [subject mapper]. | The OP checks registration and calculates pairwise subjects; the RP must provide the required URI/key relationship. Its public `jwks_uri` is not the OP verification-key URL in local endpoint configuration. Local private-key provisioning alone does not publish client JWKS or fulfill the CIBA registration/proof contract. |
| A-12 — Push pairwise subject registration; section 4 | Use the notification endpoint host as sector identifier, or a registered sector identifier whose URI list includes that endpoint. | **Missing CIBA registration/notification integration.** Ordinary issuer/subject mapping accepts opaque subject data but does not establish this sector relationship. [Subject mapper], [HTTP feature: setup], [provider configuration]. | Push has a different URI basis from Poll/Ping. OP subject calculation is outside this RP's role; external registration can establish the relationship, but a working notification receiver is still needed. |
| A-13 — Authenticated initiation over TLS; sections 7, 7.1 | POST UTF-8 form parameters directly to the OP over TLS, authenticating with the registered method. JWT client assertions SHOULD target the OP issuer; OPs MUST also accept their token/backchannel endpoint URLs as audiences. | **Reusable transport/authentication only.** HTTP form submission and client-authentication mechanisms, including issuer-audience selection for PAR, exist; no CIBA initiation operation or its profile checks are wired. [Endpoint client], [client authentication], [WebClient factory]. | An unauthenticated `NONE` exchange does not meet the requirement. Public-key client authentication is recommended in section 7.2, not a universal ban on shared-secret methods. Signed authentication requests still need client authentication, and their audience rule differs from the client-assertion rule. |

### Base Authentication Request parameters

Spec references: [request parameters](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#auth_request),
[user-code rules](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#user_code), and
[hint security](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#security_considerations).
The fields below belong to the CIBA initiation POST, not the existing code-flow authorization URI. Additional parameters
can be defined by extensions/profiles; the OP must ignore unrecognized request parameters.

| ID / CIBA request parameter | What the feature provides | Current support and evidence | Gap or exclusion rationale |
| --- | --- | --- | --- |
| A-14 — `scope` | REQUIRED; MUST include `openid`, with other standard/application scopes allowed. | **Shared scope handling only.** Scope configuration/serialization exists for implemented grants, but no CIBA Authentication Request is built. [Authorization configuration], [request factory], [endpoint client]. | CIBA does not invent a new scope vocabulary. Generic `openid` support or requesting `offline_access` in another flow is not CIBA initiation, consent or token delivery. |
| A-15 — `client_notification_token` | REQUIRED for Ping/Push: client-provided callback Bearer credential, at most 1024 characters, Bearer syntax, at least 128 bits of entropy with 160 recommended. | **Missing issuance, retention and verification workflow.** No CIBA per-request credential is generated, sent or associated with a transaction/callback. [Request factory], [HTTP feature: setup], [endpoint client]. | This credential authenticates OP callbacks to the client; it is not an OP-issued access token or the client's long-term secret. Existing API Bearer authentication does not replace matching the callback credential to its authentication-request identifier. |
| A-16 — `acr_values` | Optionally request authentication-context classes in preference order; the resulting ID Token's `acr` is highly recommended when requested. | **Missing CIBA request/result policy.** No CIBA option or retained requested-context policy; generic claim mapping does not enforce requested assurance. [Authorization configuration], [request factory], [ID Token validator], [subject mapper]. | The OP ultimately chooses the authentication method and reports the achieved context. Supplying a requested value is not by itself a guarantee of MFA or a particular assurance level; no universal assurance policy is defined for Helidon by this parameter. |
| A-17 — `login_hint_token` | Optionally identify the user with a token whose format, issuer and security requirements are deployment/profile-specific; issuer signing is recommended. | **Missing CIBA hint input/transport.** No request builder or dedicated hint-token integration. [Request factory], [authorization configuration]. | The client need not assume every hint token is a JWT that it can decrypt or mint itself. An encrypted hint token from a discovery service is a privacy option discussed by the spec; it is distinct from the unsupported encrypted authentication-request JWT format. |
| A-18 — `id_token_hint` | Optionally identify the user with an ID Token previously issued to this client; an asymmetrically encrypted token MUST be decrypted to the inner signed token before use. | **Decryption/data primitives only.** ID Tokens can be stored/decrypted, but no CIBA hint option or request uses the required inner-token form. Existing RP-Initiated Logout forwards its own hint under a different specification. [ID Token decryptor], [local session state], [request factory], [local logout handler]. | Do not transfer this CIBA MUST into another protocol or reuse the logout hint path unchanged. The OP's acceptance of recent expired hints is separate from normal RP validation of a newly received ID Token; it does not require this provider to archive every expired token. |
| A-19 — `login_hint` | Optionally identify the user through an OP-understood value such as a subject, account identifier, email address or phone number. | **Missing CIBA input/transport.** No CIBA request option or initiation path uses a user identifier. [Request factory], [authorization configuration]. | Knowing an identifier is not proof of user authentication or consent. The identifier need not be a static global identifier; the privacy choices below are deployment options, not a requirement to collect email/phone data in every application. |
| A-20 — `binding_message` | Optionally provide a human-readable cue displayed at the consumption/authentication sides to help the user recognize the same transaction. | **Missing request/UI integration.** No binding-message option, retained display context or application handoff. [Request factory], [authorization configuration], [HTTP feature]. | The spec recommends a relatively short, plain-text, recognizable value with reasonable entropy; it does not mandate the sample's length or alphabet. This visual cue is distinct from a secret user code, callback credential or opaque authentication-request identifier. |
| A-21 — `user_code` | Optionally supply the OP-verifiable user secret when supported/required; it is not the user's OP account password, and the client MUST NOT store it. | **Missing CIBA collection, request and challenge workflow.** No user-code option or handling of a missing-code challenge. [Request factory], [authorization configuration], [endpoint client]. | The OP can allow particular clients/users without a code even when it supports the mechanism. A client may ask for the code after `missing_user_code` and should request it per flow rather than persist it. OP code enrollment/change/verification is not a new responsibility of the RP component. |
| A-22 — `requested_expiry` | Optionally ask for a positive-integer authentication-request lifetime; the OP MAY use it to influence the acknowledged lifetime. | **Missing CIBA request/deadline policy.** Existing HTTP timeouts and token/session lifetimes do not send this field or retain the returned CIBA deadline. [Authorization configuration], [endpoint client], [local authentication result]. | This is a request, not an instruction the OP must honor exactly. The acknowledged lifetime governs the authentication transaction; it is different from access-token expiration, local-session duration or a single HTTP timeout. Signed requests have special string/number encoding rules for this field. |
| A-23 — Exactly one user hint and extensibility; sections 7.1–7.2 | Require exactly one of the three hint alternatives; permit profile/extension parameters and require OPs to ignore unrecognized inputs. | **Missing CIBA composition/validation.** No CIBA parameter set enforces the hint choice or provides an extension-aware initiation path. [Request factory], [authorization configuration], [endpoint client]. | The individual hint fields are optional only as alternatives; omitting all or sending several does not satisfy the base request. The OP resolves and validates the hint under its communicated deployment policy; the client need not implement a universal hint-token issuer or user-directory lookup. |

### Signed authentication requests and their six required JWT claims

Spec reference: [signed authentication request](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#signed_auth_request).
This is the CIBA request-protection feature, not a separate JWT specification assessment or the JWT used for client authentication.

| ID / Signed CIBA request feature | What the feature provides | Current support and evidence | Gap or exclusion rationale |
| --- | --- | --- | --- |
| A-24 — `request` wrapper and signed-only profile; section 7.1.1 | Put all authentication parameters inside an asymmetrically signed JWT, sent in the form `request` field; keep client-authentication parameters outside, without duplicating authentication parameters there. | **Signing primitives only.** Existing Request Object processing signs code-flow parameters and can encrypt that different profile; no CIBA request composer/transport exists. [Request Object processor], [request factory], [client authentication]. | The nine base request parameters use JSON strings in the JWT except `requested_expiry`, for which the OP must accept string or number; extensions may define other JSON types. Registered JWT claims retain their own types. Encrypted authentication-request JWTs are expressly unsupported by CIBA Core; that does not ban encrypted ID Tokens or opaque hint tokens. |
| A-25 — `aud`, `iss`; section 7.1.1 | REQUIRED signed-request claims: audience contains the OP issuer identifier; issuer is this client's ID. | **Matching construction primitives only.** The code-flow Request Object builder can use client ID as issuer and OP issuer as audience, but is not connected to a CIBA flow. [Request Object processor], [client authentication]. | The authentication-request audience rule is a MUST, unlike the client-authentication assertion's issuer recommendation/alternative audiences. The two JWT purposes must not be conflated. |
| A-26 — `exp`, `iat`, `nbf`; section 7.1.1 | REQUIRED signed-request claims defining expiration, creation time and not-before time. | **Partial construction primitives, not this profile.** The current code-flow Request Object builder supplies issue/expiration times but does not automatically add CIBA's required not-before claim. [Request Object processor], [Request Object configuration]. | This is not a defect in a different Request Object profile. CIBA needs its own complete claim contract; the signed JWT validity window is also distinct from the later OP-issued authentication-transaction lifetime. |
| A-27 — `jti`; section 7.1.1 | REQUIRED unique identifier for the signed authentication request. | **Identifier-generation primitive only.** Fresh identifiers are generated for existing Request Objects/client assertions, but no signed CIBA request is created. [Request Object processor], [client authentication]. | This client-generated JWT ID is not the OP-generated `auth_req_id` or the callback Bearer credential. Having a UUID generator or signed JWT alone does not implement the asynchronous transaction. |

### Authentication Request acknowledgment and transaction lifetime

Spec references: [acknowledgment fields](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#successful_authentication_request_acknowdlegment)
and [client validation/state retention](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#auth_request_acknowdlegment_validation).
An HTTP 200 acknowledgment accepts a transaction for processing; it is not yet a successful user authentication or Token Response.

| ID / Acknowledgment or transaction feature | What the feature provides | Current support and evidence | Gap or exclusion rationale |
| --- | --- | --- | --- |
| A-28 — `auth_req_id`; sections 7.3–7.4 | REQUIRED opaque OP-issued transaction ID that the client MUST retain for token requests or callback correlation. OP generation requires at least 128 bits of entropy, recommends 160, and restricts characters to ASCII letters, digits, dot, hyphen and underscore. | **Missing acknowledgment model/state.** No CIBA identifier is parsed, stored or correlated; code-flow state and PAR request URIs are different values. [Endpoint client], [request factory], [callback processor]. | The client must not interpret or rewrite an apparently structured identifier. The OP owns its generation; a client cannot prove entropy from one received value. The 1024-character cap on the notification credential must not be invented as an auth_req_id limit. |
| A-29 — `expires_in` in the acknowledgment; section 7.3 | REQUIRED positive JSON integer giving the authentication-request lifetime in seconds since the request was received. | **Missing CIBA deadline parsing/tracking.** Existing token lifetime handling serves returned credentials, not a pending CIBA transaction acknowledgment. [Token response], [endpoint client], [local authentication result]. | The same field name in a Token Response describes a different object's lifetime. A requested expiry does not supersede the OP's acknowledged value, and successful acknowledgment is not permission to wait indefinitely. |
| A-30 — `interval`; sections 7.3, 10.1 | Optional positive JSON integer for Poll/Ping minimum polling interval; if absent, the client MUST use five seconds. | **Missing CIBA polling policy.** No acknowledgment interval or per-transaction polling lifecycle exists. [Endpoint client], [request factory]. | This is not the HTTP response timeout, refresh-token reuse interval or token-cache lifetime. Polling cadence is measured from request send time and must also obey the no-overlap rule below. The parameter is not part of Push delivery. |
| A-31 — Acknowledgment validation, cleanup and correlation; section 7.4 | Validate required fields after HTTP 200, retain the request ID, and keep expiry for cleaning up transactions with no notification; ignore unknown acknowledgment parameters. | **Missing asynchronous transaction management.** Existing protected state is for code-flow callbacks, not CIBA acknowledgment/notification matching and expiry. [Cookie state handler], [callback processor], [endpoint client], [HTTP feature]. | Keeping auth_req_id and validating required fields are MUSTs; retaining expiry for cleanup is stated as guidance. The protocol needs correct lifecycle behavior, not a mandated database, timer implementation or new public API. Generic token parsing or lazy initialization does not by itself provide it. |

### Token retrieval, Poll/Ping/Push modes, and authenticated callbacks

Spec references: [CIBA token request and polling](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#token_request),
[Ping callback](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#ping_callback),
[Push delivery](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#successful_token_push), and
[token errors](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#token_error_response).

| ID / Mode or callback feature | What the feature provides | Current support and evidence | Gap or exclusion rationale |
| --- | --- | --- | --- |
| A-32 — Token-request `grant_type`, `auth_req_id`; section 10.1 | Poll/Ping clients authenticate and POST the CIBA grant value plus the retained transaction ID; the OP must verify that ID was issued to this client. | **Missing CIBA grant operation.** Existing token requests use authorization-code, refresh, client-credentials or token-exchange grants, not `urn:openid:params:grant-type:ciba`. [Endpoint client], [client authentication]. | The standard form/authentication machinery can be reused, but a different URL does not turn another grant into CIBA. Push clients MUST NOT call the Token Endpoint with the CIBA grant; this does not prohibit ordinary refresh-token requests. |
| A-33 — Poll mode cadence, long polling and backoff; section 10.1 | Respect the minimum interval measured from send time; MUST NOT overlap requests for the same auth_req_id. Allow for long polling and respect Retry-After guidance on 503. | **Missing polling state machine.** No per-transaction polling, completion/expiry handling or CIBA retry scheduling. Existing HTTP configuration and concurrent token acquisition serve other workflows. [Endpoint client], [WebClient factory], [request factory]. | A client should allow at least 30 seconds for a polling response; that is guidance, not a requirement to wait 30 seconds between requests. After a slow response, it may poll immediately if the interval elapsed, while still avoiding overlap. Different transaction IDs need not be globally serialized. |
| A-34 — Ping mode; sections 10.1–10.2 | Receive a JSON POST containing auth_req_id after successful or failed authentication, authenticate/correlate it, then retrieve the actual result at the Token Endpoint. | **Missing receiver and follow-up workflow.** No Ping route, credential-to-request association or result fetch is installed. [HTTP feature: setup], [endpoint client], [callback processor]. | A Ping is not itself an authentication success or a token delivery. Ping clients MAY also poll; the OP treats those requests as Poll mode. An expiry Ping need not be sent because the client already knows the transaction lifetime. |
| A-35 — Push mode; section 10.3 | Receive the JSON authentication result directly, including auth_req_id and standard token-response fields, or an error payload. | **Missing authenticated token-delivery workflow.** No Push receiver or transaction-bound result consumer. Existing Token Response parsing handles credentials returned to outgoing token calls, not an authenticated incoming CIBA delivery. [HTTP feature: setup], [token response], [endpoint client]. | Push success uses the inherited `access_token`, `token_type`, `expires_in`, `refresh_token`, `id_token` and scope semantics, plus the CIBA ID. Generic parsing alone does not provide callback authentication, ID Token/hash binding, transaction completion or application handoff. |
| A-36 — Notification authentication, HTTP responses and extensions; sections 9, 10.2–10.3 | Verify the callback Bearer credential and its association with auth_req_id. Invalid credentials SHOULD yield 401; valid requests SHOULD yield 204. OPs SHOULD also accept 200 and ignore response content. Clients MUST NOT redirect and OPs MUST NOT follow redirects; ignore unknown callback parameters. | **Missing notification-endpoint contract.** No CIBA callback credential/correlation or response handling. Existing browser callback redirects and resource-server Bearer validation have different purposes. [HTTP feature], [callback processor], [authentication orchestrator]. | The credential was provided by this client, not issued by the OP as an API access token. These rules also protect Push error delivery. Handling callback 4xx/5xx failures is outside this spec; it does not prescribe Back-Channel Logout's retry policy or a universal retry count here. |

### Token results and the three Push binding claims

Spec references: [Poll/Ping success](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#token_response)
and [Push token validation](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#successful_token_push).

| ID / Token-result feature | What the feature provides | Current support and evidence | Gap or exclusion rationale |
| --- | --- | --- | --- |
| A-37 — Successful tokens and ID Token validation; sections 10.1.1, 10.3.1 | Receive the inherited Core Token Response and validate the ID Token in the correct RP/transaction context; successful Poll/Ping redemption makes that auth_req_id unusable again. | **Reusable parsing/validation only.** Credential parsing, signature/decryption and Core issuer/audience/time checks exist, but no CIBA result consumer. The initial code-flow validator takes its own saved authentication-request nonce. [Token response], [ID Token validator], [HTTP feature: processTokenEndpointExchange]. | CIBA is not implemented by sending its result to the browser code callback or fabricating that callback's transaction state. OP one-time redemption and client transaction completion are different responsibilities. The extra Push bindings below are not unconditional requirements for Poll/Ping responses. |
| A-38 — `urn:openid:params:jwt:claim:auth_req_id`; section 10.3.1 | In Push, require the ID Token's signed request-ID value to match the callback's auth_req_id, already associated with the outstanding transaction. | **Missing Push transaction binding.** No consumer compares this claim with a callback/retained request ID. Generic preservation of claims is not a validation policy. [ID Token validator], [subject mapper], [HTTP feature]. | The explicit client rule uses an exact identifier match, not a newly defined digest of the ID. This is separate from validating the notification credential; both bindings are needed. The wording clarification below explains the relevant text. |
| A-39 — `at_hash` in Push; section 10.3.1 | Require and validate the access-token hash in the signed ID Token against the delivered access token using Core hash rules. | **Missing mandatory Push hash check.** The ID Token validator does not take the access token or validate this hash; protecting the claim from UserInfo overwrite is only data handling. [ID Token validator], [subject mapper]. | Code Flow's optional access-token hash check is not the rule for CIBA Push. Independently validating an access token or parsing an at_hash claim does not establish this binding to the delivered ID Token. |
| A-40 — `urn:openid:params:jwt:claim:rt_hash`; section 10.3.1 | When Push includes a refresh token, require and validate its hash in the ID Token using the analogous Core token-hash method. | **Missing conditional Push binding.** No CIBA refresh-token hash consumer or validator. Existing refresh-token storage/renewal is another operation. [ID Token validator], [refresh manager], [local session state]. | The check is mandatory when a refresh token is delivered, not when none is present. It protects the initial delivered credential set; later refresh exchange/identity-continuity checks are not a substitute. |

Wording clarification: the introductory binding sentence in section 10.3.1 can be read ambiguously as hashing both the
access token and the request ID. This assessment follows the [explicit client comparison](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.3.1.p.8),
the examples, [security explanation](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#security_considerations)
and [claim-name explanation](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#ClaimsReg):
the request-ID claim contains auth_req_id itself; the access/refresh token claims contain hashes. No additional
request-ID digest format or implementation defect is inferred from that introductory wording.

### Sender-constrained tokens and subsequent refresh

Spec references: [Push sender constraints](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.5)
and [delivered credential sets](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#successful_token_push).

| ID / Related credential feature | What the feature provides | Current support and evidence | Gap or exclusion rationale |
| --- | --- | --- | --- |
| A-41 — Sender-constrained tokens in Push; section 5 | Adapt token binding to the client's key material presented at the Backchannel Authentication Endpoint because Push has no CIBA token-retrieval call. | **Transport primitives only; OP issuance is outside this component's role.** mTLS client mechanisms exist, but no CIBA initiation/key-context integration or token issuer does this binding. [Client authentication], [WebClient factory], [endpoint client]. | The OP retains the original client's key context and binds issued tokens accordingly. It is not the OP's later callback connection that defines the client's binding key. Existing mTLS support does not prove complete CIBA sender-constrained-token support. |
| A-42 — Optional refresh-token use after CIBA | Use a returned refresh token under inherited Core semantics after validating the initial result. | **Core refresh building blocks only.** Refresh requests, response parsing and identity continuity exist for local browser sessions, but no CIBA-produced credential lifecycle is attached to them. [Refresh manager], [token response], [ID Token validator: validateRefresh]. | A refresh token is optional, not guaranteed by CIBA. Push's prohibition on the CIBA token-retrieval grant is not a ban on later refresh-token grant requests. The initial Push refresh-token hash requirement remains separate. |

### Three distinct error contexts

Spec references: [Token Error Response](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#token_error_response),
[Push Error Payload](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#push_error_payload), and
[Authentication Error Response](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#auth_error_response).
Decoding a standard OAuth error object is useful shared functionality; it does not implement mode-specific waiting,
backoff, terminal states, user-code collection or callback authentication.

| ID / Error context and fields | What the feature provides | Current support and evidence | Gap or exclusion rationale |
| --- | --- | --- | --- |
| A-43 — Poll/Ping Token Error Response; section 11 | Interpret inherited token errors plus CIBA's `authorization_pending`, `slow_down`, `expired_token`, `access_denied`, `invalid_grant`, `invalid_request` and Push-mode `unauthorized_client` cases. | **Generic decoding only; CIBA transitions missing.** OAuth error parsing/field validation exists, but no CIBA polling/backoff/termination state machine uses these codes. [Token error parser], [OAuth error validation], [endpoint client]. | Pending is not final authentication failure. Slow-down MUST increase the interval by at least five seconds for that and subsequent requests. Invalid-request stops further calls with that ID; expired IDs need a new authentication request. Invalid-grant covers invalid/wrong-client IDs; Push may not use the CIBA grant. Clients should inspect 4xx JSON rather than rely on status alone. |
| A-44 — Push `auth_req_id`, `error`, `error_description`; section 12 | Receive authenticated JSON failure delivery with required request ID/code and optional constrained-ASCII description; codes are `access_denied`, `expired_token` and `transaction_failed`. | **Missing Push error consumer/correlation.** Reusable OAuth error-field validation exists, but no notification endpoint verifies the callback credential, retains the ID or completes the corresponding transaction. [OAuth error validation], [token error parser], [HTTP feature: setup]. | Error delivery is not a successful user authentication and does not supply an ID Token to validate as a success payload. OPs need not send expiry notifications, but clients SHOULD accept that error. Correlation/authentication still matter; passive parsing of an error string is insufficient. |
| A-45 — Initiation `error`, `error_description`, `error_uri`; section 13 | Decode required ASCII code, optional constrained-ASCII description and optional URI-reference diagnostics. HTTP 400 covers `invalid_request`, `invalid_scope`, `expired_login_hint_token`, `unknown_user_id`, `unauthorized_client`, `missing_user_code`, `invalid_user_code`, `invalid_binding_message`; 401 covers `invalid_client`; 403 covers `access_denied`. | **Reusable error codec only.** The module validates the inherited error field formats, but there is no CIBA initiation call or context-specific recovery/application UX. [Token error parser], [OAuth error validation], [endpoint client]. | An immediate denial precedes authentication-device interaction and is not the same event as a user declining a later request. Missing/invalid user codes and unacceptable hints/messages need appropriate application handling, not an automatic generic retry loop. The diagnostic URI is not a new authentication endpoint to contact. |

### OP responsibilities, application handoff, and privacy

Spec references: [OP request validation](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#auth_request_validation),
[authentication/consent](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#auth_server_obtains_consent),
[security context](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#security_considerations), and
[privacy options](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#privacy_considerations).

| ID / Role or integration boundary | What the feature provides | Current support and evidence | Gap or exclusion rationale |
| --- | --- | --- | --- |
| A-46 — OP request validation, user authentication and consent; sections 7.2–8 | Authenticate the client, validate signed requests/parameters/hints, resolve the user, select an authentication channel and obtain an authorization decision. | **Outside the component's role: OP processing.** This module consumes an OP; it does not host a CIBA Authentication Endpoint, user directory, device-authentication service or consent engine. [README](README.md#supported-standards-boundary), [HTTP feature: setup], [endpoint client]. | Adding a CIBA client does not require Helidon to implement a mobile authenticator or become an identity server. The OP owns device/user interaction and code verification; the RP still owns correct requests and result handling. |
| A-47 — OP endpoint ownership and hint trust policy; sections 7.2, 14 | Check notification-endpoint administrative ownership and apply deployment-specific hint authenticity, issuer/audience, age and key-retention policy. | **OP-side responsibilities, not missing RP validators.** No OP registration/hint-validation service exists. RP-side ID Token validation has a different purpose. [README](README.md#supported-standards-boundary), [ID Token validator], [HTTP feature]. | The spec recommends checking endpoint ownership and signed hint-token provenance. Its special discussion of expired ID Token hints and pairwise alternatives is not permission for the RP to skip validating newly received authentication results. No universal hint directory/verification algorithm is mandated inside this client. |
| A-48 — Consumption-device association and result handoff; sections 2–3, 7.4, 9–10 | Connect the validated asynchronous result to the initiating application interaction and provide the needed display/input/result UX. | **Missing CIBA application integration.** Existing callback code establishes a browser code-flow session, not an asynchronous consumption-device operation. No outstanding CIBA result API/association or mode-specific application handoff exists. [HTTP feature: processTokenEndpointExchange], [cookie state handler], [callback processor]. | Assessment: a Ping/Push response goes to the OP, so setting a cookie there would not log in the consumption-device browser. A call-center verification also need not replace the agent's identity with the customer's. The application boundary must be designed; CIBA does not mandate one UI, storage product or public API shape. |
| A-49 — Privacy-preserving hints and optional context extensions; sections 14–15 | Avoid mandatory global identifiers by using pairwise ID Token hints, single-use identifiers or deployment discovery/hint services; optionally add application context through a profile. | **Generic identity/claim primitives only; no CIBA privacy workflow.** Opaque subject/claim handling exists but no CIBA hint selection, discovery-service integration or consumption-device context exchange. [Subject mapper], [request factory], [authorization configuration]. | Phone/email identifiers are not required by the protocol. A privacy discovery service is not the ordinary OP `.well-known` metadata loader. Geolocation/context exchange is neither required nor wire-defined by CIBA Core; absence is not a missing mandatory feature. These are feasible application/profile choices, not a Helidon platform limitation. |

### CIBA overview: useful building blocks, no implemented delivery mode

No Poll, Ping or Push client workflow is built in. The README explicitly excludes CIBA from the current client profile,
and code inspection agrees: no CIBA request/grant builder, acknowledgment/transaction state, notification receiver or
mode-specific result/error processing is present. The profile is technically feasible for a Helidon server application
that needs decoupled user authentication; the component's current scope does not establish a permanent rejection.

Assessment: the main work would be a coherent asynchronous client protocol and an application handoff, not another
implementation of HTTP, JSON, client authentication or basic signing/decryption. Existing components can help, but their
full code-flow contracts cannot be blindly transplanted: CIBA's signed-request claims and parameter placement, transaction
IDs, callback credentials, polling rules and Push hash bindings are different. Poll can avoid an inbound notification
endpoint; Ping and Push require reachable HTTPS notification handling. Implementing every mode is not a prerequisite for
a clearly scoped client, but any selected mode needs its entire validation/lifecycle behavior.

The three modes are genuinely distinct. Ping may also poll; Push must not use the CIBA token-retrieval grant. Polling
must avoid overlapping calls for the same transaction and obey cadence/backoff while allowing long responses. A valid
callback needs the client-provided credential bound to the retained request ID; a generic API Bearer validator or a
browser redirect callback is not interchangeable. A Push result additionally binds the signed ID Token to the request ID
and delivered access/refresh tokens. Receiving an acknowledgment or Ping alone does not authenticate the user.

Feature absence and normative exclusions are separated: encrypted authentication-request JWTs are unsupported by CIBA
Core, whereas encrypted ID Tokens or opaque encrypted hint tokens are different objects. User-code use is optional under
registration/policy, but the client must not store a supplied code. OP device interaction, consent, hint resolution and
notification-endpoint ownership checks belong to the OP; the RP does not need to build an identity server. Privacy choices
and application handoff remain important integration decisions rather than proof the protocol is unsuitable for Helidon.

### CIBA assessment method and limits

Read the local final specification through the substantive protocol, security/privacy and IANA sections and checked the
official edition. Inventoried all four new OP/four new client metadata fields, nine base request parameters, the signed
request wrapper/six claims, three acknowledgment fields, both token-request fields, all modes and three Push binding claims.
All seven CIBA-highlighted token-error cases, three Push error fields/three codes, and three initiation error fields/ten
codes are accounted for, with inherited Core/OAuth fields distinguished from new CIBA fields.

Inspected metadata parsing, endpoint/grant construction, client authentication, Request Object generation, route setup,
ID Token validation/decryption, token/error parsing, scope/subject/state handling and related source/test searches.
Existing primitives are identified explicitly; no CIBA-specific handler or test flow was found. Generic token, JOSE,
callback or Keycloak code-flow tests do not establish CIBA interoperability. No new runtime/device/callback probes, test
reruns, OP registration changes, production edits or commit were performed.

The assessment preserves required-versus-optional distinctions, including the five-second default interval, slow-down
increments, 30-second long-poll guidance, optional expiry notifications, callback HTTP semantics and conditional Push
hash checks. The request-ID wording clarification uses the explicit client comparison, examples and security/claim-name
explanations, rather than inventing an additional hash or reporting a proven specification/implementation defect.

CIBA assessment is complete for this baseline. All eight supplied OIDC specifications are now assessed, with 227
source-backed feature/role/policy entries. This completes the supplied-specification inventory, not a certification or
an assessment of every additional OIDC extension. No previous feature finding was changed by this final pass.

<!-- Implementation evidence links used by the feature tables. -->

[Request factory]: src/main/java/io/helidon/security/providers/oidc/next/OidcAuthenticationRequestFactory.java
[Request factory: create]: src/main/java/io/helidon/security/providers/oidc/next/OidcAuthenticationRequestFactory.java
[authorization configuration]: src/main/java/io/helidon/security/providers/oidc/next/OidcAuthorizationCodeConfigBlueprint.java
[provider tests]: src/test/java/io/helidon/security/providers/oidc/next/OidcProviderTest.java
[tenant validation]: src/main/java/io/helidon/security/providers/oidc/next/OidcTenantConfigDecorator.java
[Tenant validation: validateAuthorizationCodePrompts]: src/main/java/io/helidon/security/providers/oidc/next/OidcTenantConfigDecorator.java
[request factory: authorizationUri]: src/main/java/io/helidon/security/providers/oidc/next/OidcAuthenticationRequestFactory.java
[code exchange tests: endpoint query preservation]: src/test/java/io/helidon/security/providers/oidc/next/OidcAuthorizationCodeTokenExchangeTest.java
[HTTP feature]: src/main/java/io/helidon/security/providers/oidc/next/OidcFeature.java
[HTTP feature: setup]: src/main/java/io/helidon/security/providers/oidc/next/OidcFeature.java
[callback processor]: src/main/java/io/helidon/security/providers/oidc/next/OidcAuthorizationResponseProcessor.java
[callback tests]: src/test/java/io/helidon/security/providers/oidc/next/OidcAuthorizationResponseProcessorTest.java
[endpoint client]: src/main/java/io/helidon/security/providers/oidc/next/OidcEndpointClient.java
[token response]: src/main/java/io/helidon/security/providers/oidc/next/OidcTokenResponse.java
[code exchange tests]: src/test/java/io/helidon/security/providers/oidc/next/OidcAuthorizationCodeTokenExchangeTest.java
[ID Token validator]: src/main/java/io/helidon/security/providers/oidc/next/OidcIdTokenValidator.java
[ID Token configuration]: src/main/java/io/helidon/security/providers/oidc/next/OidcIdTokenConfigBlueprint.java
[ID Token tests]: src/test/java/io/helidon/security/providers/oidc/next/OidcIdTokenValidatorTest.java
[ID Token validator: validateAudience]: src/main/java/io/helidon/security/providers/oidc/next/OidcIdTokenValidator.java
[ID Token validator: validateNonce]: src/main/java/io/helidon/security/providers/oidc/next/OidcIdTokenValidator.java
[Tenant validation: validateIdToken]: src/main/java/io/helidon/security/providers/oidc/next/OidcTenantConfigDecorator.java
[configuration tests]: src/test/java/io/helidon/security/providers/oidc/next/OidcProviderConfigTest.java
[ID Token decryptor]: src/main/java/io/helidon/security/providers/oidc/next/OidcIdTokenDecryptor.java
[encryption configuration tests]: src/test/java/io/helidon/security/providers/oidc/next/OidcJweAlgorithmConfigTest.java
[ID Token validator: claimValidator]: src/main/java/io/helidon/security/providers/oidc/next/OidcIdTokenValidator.java
[HTTP feature: processTokenEndpointExchange]: src/main/java/io/helidon/security/providers/oidc/next/OidcFeature.java
[UserInfo support]: src/main/java/io/helidon/security/providers/oidc/next/OidcUserInfoSupport.java
[endpoint client: userInfo]: src/main/java/io/helidon/security/providers/oidc/next/OidcEndpointClient.java
[feature route tests]: src/test/java/io/helidon/security/providers/oidc/next/OidcFeatureRouteTest.java
[UserInfo JWT processor]: src/main/java/io/helidon/security/providers/oidc/next/OidcUserInfoJwtProcessor.java
[UserInfo JWT validator]: src/main/java/io/helidon/security/providers/oidc/next/OidcUserInfoJwtValidator.java
[subject mapper]: src/main/java/io/helidon/security/providers/oidc/next/OidcSubjectMapper.java
[UserInfo configuration]: src/main/java/io/helidon/security/providers/oidc/next/OidcUserInfoConfigBlueprint.java
[UserInfo support: mappedUserInfo]: src/main/java/io/helidon/security/providers/oidc/next/OidcUserInfoSupport.java
[subject mapper: localIdentity]: src/main/java/io/helidon/security/providers/oidc/next/OidcSubjectMapper.java
[subject mapper tests]: src/test/java/io/helidon/security/providers/oidc/next/OidcSubjectMapperTest.java
[Request Object processor]: src/main/java/io/helidon/security/providers/oidc/next/OidcRequestObjectProcessor.java
[Request Object configuration]: src/main/java/io/helidon/security/providers/oidc/next/OidcRequestObjectConfigBlueprint.java
[Tenant validation: validateRequestObject]: src/main/java/io/helidon/security/providers/oidc/next/OidcTenantConfigDecorator.java
[Client authentication]: src/main/java/io/helidon/security/providers/oidc/next/OidcClientAuthenticationSupport.java
[authentication methods]: src/main/java/io/helidon/security/providers/oidc/next/OidcClientAuthenticationMethod.java
[Request factory: prompts]: src/main/java/io/helidon/security/providers/oidc/next/OidcAuthenticationRequestFactory.java
[refresh manager]: src/main/java/io/helidon/security/providers/oidc/next/OidcRefreshTokenManager.java
[refresh tests]: src/test/java/io/helidon/security/providers/oidc/next/OidcRefreshTokenManagerTest.java
[ID Token validator: validateRefresh]: src/main/java/io/helidon/security/providers/oidc/next/OidcIdTokenValidator.java
[local authentication result]: src/main/java/io/helidon/security/providers/oidc/next/OidcLocalAuthenticationResult.java
[cookie state handler]: src/main/java/io/helidon/security/providers/oidc/next/OidcCookieStateHandler.java
[OP key manager]: src/main/java/io/helidon/security/providers/oidc/next/OidcJwkSetManager.java
[OP key configuration]: src/main/java/io/helidon/security/providers/oidc/next/OidcJwkSetConfigBlueprint.java
[shared key-refresh tests]: src/test/java/io/helidon/security/providers/oidc/next/OidcJwtAccessTokenValidationTest.java
[JWE decryptor]: src/main/java/io/helidon/security/providers/oidc/next/OidcJweDecryptor.java
[endpoint URI validation]: src/main/java/io/helidon/security/providers/oidc/next/OidcEndpointUris.java
[endpoint configuration]: src/main/java/io/helidon/security/providers/oidc/next/OidcEndpointConfigBlueprint.java
[WebClient factory]: src/main/java/io/helidon/security/providers/oidc/next/OidcWebClientFactory.java
[Discovery metadata model]: src/main/java/io/helidon/security/providers/oidc/next/OidcProviderMetadata.java
[Discovery metadata model: fromStaticConfig]: src/main/java/io/helidon/security/providers/oidc/next/OidcProviderMetadata.java
[Discovery metadata model: wellKnownUri]: src/main/java/io/helidon/security/providers/oidc/next/OidcProviderMetadata.java
[Discovery metadata model: validateWellKnownMetadataIssuer]: src/main/java/io/helidon/security/providers/oidc/next/OidcProviderMetadata.java
[Discovery loader]: src/main/java/io/helidon/security/providers/oidc/next/OidcProviderMetadataLoader.java
[discovery loading tests]: src/test/java/io/helidon/security/providers/oidc/next/OidcWellKnownMetadataLoadingTest.java
[tenant resolver]: src/main/java/io/helidon/security/providers/oidc/next/OidcTenantResolver.java
[tenant metadata validation]: src/main/java/io/helidon/security/providers/oidc/next/OidcTenantContextFactory.java
[tenant metadata validation: validateIdTokenMetadata]: src/main/java/io/helidon/security/providers/oidc/next/OidcTenantContextFactory.java
[tenant metadata validation: validateAuthorizationCodeCapabilityMetadata]: src/main/java/io/helidon/security/providers/oidc/next/OidcTenantContextFactory.java
[tenant metadata validation: validateTokenEndpointAuthenticationMetadata]: src/main/java/io/helidon/security/providers/oidc/next/OidcTenantContextFactory.java
[tenant metadata validation: validateOptionalIdTokenEncryptionMetadata]: src/main/java/io/helidon/security/providers/oidc/next/OidcTenantContextFactory.java
[tenant metadata validation: validateUserInfoMetadata]: src/main/java/io/helidon/security/providers/oidc/next/OidcTenantContextFactory.java
[tenant metadata validation: validateRequestObjectMetadata]: src/main/java/io/helidon/security/providers/oidc/next/OidcTenantContextFactory.java
[OP public-key loader]: src/main/java/io/helidon/security/providers/oidc/next/OidcJwkSetLoader.java
[OP key-source tests]: src/test/java/io/helidon/security/providers/oidc/next/OidcJwkSetPolicyTest.java
[token exchange tests]: src/test/java/io/helidon/security/providers/oidc/next/OidcTokenExchangeGrantTest.java
[Discovery metadata model: fromWellKnownMetadataJson]: src/main/java/io/helidon/security/providers/oidc/next/OidcProviderMetadata.java
[tenant metadata validation: needsWellKnownMetadata]: src/main/java/io/helidon/security/providers/oidc/next/OidcTenantContextFactory.java
[Discovery metadata model: mergeWellKnownMetadata]: src/main/java/io/helidon/security/providers/oidc/next/OidcProviderMetadata.java
[tenant runtime registry]: src/main/java/io/helidon/security/providers/oidc/next/OidcTenantRuntimeRegistry.java
[outbound metadata resolver]: src/main/java/io/helidon/security/providers/oidc/next/OidcOutboundMetadataResolver.java
[HTTP response checks]: src/main/java/io/helidon/security/providers/oidc/next/OidcHttpResponseValidation.java
[shared JSON predicate]: ../../../http/http/src/main/java/io/helidon/http/HttpMediaTypes.java
[Tenant client settings]: src/main/java/io/helidon/security/providers/oidc/next/OidcTenantConfigOptionsBlueprint.java
[provider configuration]: src/main/java/io/helidon/security/providers/oidc/next/OidcProviderConfigBlueprint.java
[UserInfo JWT configuration]: src/main/java/io/helidon/security/providers/oidc/next/OidcUserInfoJwtConfigBlueprint.java
[client assertion configuration]: src/main/java/io/helidon/security/providers/oidc/next/OidcClientAssertionConfigBlueprint.java
[authorization response result]: src/main/java/io/helidon/security/providers/oidc/next/OidcAuthorizationResponseResult.java
[local session state]: src/main/java/io/helidon/security/providers/oidc/next/OidcLocalAuthenticationStateBlueprint.java
[local logout handler]: src/main/java/io/helidon/security/providers/oidc/next/OidcLogoutHandler.java
[authentication orchestrator]: src/main/java/io/helidon/security/providers/oidc/next/OidcAuthenticationOrchestrator.java
[local logout configuration]: src/main/java/io/helidon/security/providers/oidc/next/OidcLogoutConfigBlueprint.java
[end-session configuration]: src/main/java/io/helidon/security/providers/oidc/next/OidcEndSessionConfigBlueprint.java
[synthetic logout tests]: ../../../tests/integration/security/oidc-next/src/test/java/io/helidon/tests/integration/security/oidcnext/OidcLogoutFlowIT.java
[Keycloak logout tests]: ../../../tests/integration/security/oidc-next-keycloak/src/test/java/io/helidon/tests/integration/security/oidcnext/keycloak/KeycloakLogoutIT.java
[WebClient-based browser test helper]: ../../../tests/integration/security/oidc-next-keycloak/src/test/java/io/helidon/tests/integration/security/oidcnext/keycloak/KeycloakOidcIntegrationSupport.java
[token error parser]: src/main/java/io/helidon/security/providers/oidc/next/OidcTokenErrorResponse.java
[OAuth error validation]: src/main/java/io/helidon/security/providers/oidc/next/OidcOAuthErrorFields.java
