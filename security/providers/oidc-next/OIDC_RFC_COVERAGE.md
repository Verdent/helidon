# OIDC-related RFC coverage

Assessment started: 2026-09-25. Implementation baseline: `e015f55ebe74d68032f3af20adacff7683c5d689`.

This is the RFC companion to [the completed eight-spec OIDC inventory](OIDC_SPEC_COVERAGE.md). It follows the user's
request to assess only OIDC-related RFC requirements, one RFC at a time, with incremental saves. It is a source-backed
capability/security-boundary review, not blanket RFC compliance, certification or a list of proven vulnerabilities.

Approved sequence completed: 2026-09-29. **Eleven detailed RFC passes, 285 feature entries.** RFC9449 (DPoP) is intentionally
unsupported and its detailed pass was skipped at the user's direction. As of 2026-10-02 (`a28eb6b50d`), the nine
numbered RFC-phase findings have **no active fixes pending**: eight were remediated and one is an accepted, explicit
compatibility exception. This is a disposition of the numbered findings, not certification or support for every optional
feature. The original feature assessments below retain their 2026-09 baseline; descriptions of pre-fix behavior are
historical where a subsequent remediation note or this table supersedes them.

| Finding | Current disposition |
| --- | --- |
| 7636-F01 | Accepted explicit `plain` compatibility exception for confidential clients; default S256 and the public-client guard remain (`1940827324`, restored in `d0ab537df8`). An explicitly selected `plain` client is not RFC 7636-conformant. |
| 9207-F01 | Fixed: issuer-to-metadata binding and independent-OP collision checks (`f4d178e813`). |
| 9101-F01 | Fixed for the reproduced signed-JAR+PAR path: a matching DNS SAN is checked after the TLS handshake and before the HTTP request, with CN-only certificates rejected (`9a9873498f`). Separate PAR HTTPS enforcement is in `fdd089914d`. This is not a claim that all configured WebClients enforce DNS-SAN-only identities. |
| 9126-F01 | Fixed: compare the numeric PAR 201 status (`72bf55a21a`). |
| 8414-F01 / F02 | Fixed: compare the numeric metadata 200 status (`0170fa3bae`); enforce metadata TLS policy before fetching (`dacfb25e88`). |
| 8705-F01 / F02 | Fixed: mTLS-intent alias selection for token binding and OP UserInfo (`282a094dee`). |
| 8707-F01 | Fixed: validate configured resource URI components against RFC 3986 (`62fb4e161d`). |

Feature entries otherwise describe the assessment baseline. Optional gaps/quality notes are not additional vulnerabilities.
The original eight-spec OIDC inventory is unchanged. No further RFC is queued by this document.

## Scope and sequence

These RFCs are considered only where they refine OIDC authentication requests, responses, RP client security or the
credentials obtained by that login. Generic OAuth resource-server/grant features are not added just because the module
also implements them. Standalone JWT/JOSE formats and non-RFC profiles remain outside this phase. Completion of a scoped
assessment is not a claim that every assessed feature is implemented. Describing a mechanism referenced by the current
RFC is not a full support/compliance verdict for that mechanism's own specification.

| RFC | OIDC-focused scope | Progress |
| --- | --- | --- |
| 9700 — OAuth Security BCP | Authorization-code RP protections, associated credentials and deployment/OP boundaries. | Complete for this scope: 30 entries; assessed 2026-09-25. |
| 7636 — PKCE | Authorization-code verifier/challenge generation and redemption. | Complete for this scope: 20 entries and one accepted, explicitly selected nonconformant compatibility option; assessed 2026-09-25, disposition documented in `1940827324` on 2026-09-30. |
| 9207 — Issuer identification | Issuer binding in authorization responses and mix-up prevention. | Complete for this scope: 20 entries and one conditional security/design gap; assessed 2026-09-25. 9207-F01 fixed/verified and committed as `f4d178e813` on 2026-09-30. |
| 9101 — JAR | Secured OIDC authorization requests. | Complete for this scope: 30 entries and separate quality notes; assessed 2026-09-29. Scoped signed-JAR+PAR TLS finding 9101-F01 fixed/verified in `9a9873498f` on 2026-10-01. |
| 9126 — PAR | Back-channel submission of OIDC authorization requests. | Complete for this scope: 25 entries, one resolved interoperability gap and separate quality notes; assessed 2026-09-29. 9126-F01 fixed/verified and committed as `72bf55a21a` on 2026-09-30. |
| 8414 — AS Metadata | Metadata relevant to OIDC issuer/endpoints and security capabilities. | Complete for this scope: 30 entries and separate quality notes; assessed 2026-09-29. 8414-F01 fixed/verified and committed as `0170fa3bae`; 8414-F02 committed as `dacfb25e88`. |
| 7523 — JWT assertion profiles | JWT client authentication used by the OIDC RP, not a new assertion-grant inventory. | Complete for this scope: 25 entries, no new confirmed protocol/security finding, and separate quality/reuse notes; assessed 2026-09-29. |
| 8705 — Mutual TLS | OIDC RP client authentication and protection of its associated credentials. | Complete for this scope: 30 entries and qualified binding/lifecycle boundaries; assessed 2026-09-29. Both alias findings 8705-F01/F02 fixed/verified in `282a094dee` on 2026-09-30. |
| 9449 — DPoP | Proof-bound credentials in an OIDC login/token client, not a general resource-server audit. | Not supported; intentional scope exclusion confirmed 2026-09-29. Detailed RFC pass skipped; see section 9. |
| 9470 — Step-up challenges | Triggering appropriate OIDC reauthentication/assurance from a challenge. | Complete for this scope: 20 entries; end-to-end protocol not implemented, related building blocks present, no new security/protocol finding. Assessed 2026-09-29. |
| 8707 — Resource Indicators | Resource selection in OIDC authorization/token requests. | Complete for this scope: 25 entries, one resolved URI-validation gap and documented static-list limitations; assessed 2026-09-29. 8707-F01 fixed/verified and committed as `62fb4e161d` on 2026-09-30. |
| 9396 — Rich Authorization Requests | Authorization details when combined with an OIDC authentication request. | Complete for this scope: 30 entries; RAR not implemented, reusable pieces/external roles documented, no new security/protocol finding; assessed 2026-09-29. |

Base OAuth and cryptographic documents may be referenced to interpret these requirements; that is not a standalone
assessment of their entire surface. Introspection, revocation, token exchange, general JWT access-token profiles,
protected-resource metadata, OAuth registration and Device Flow are not separate review items in this narrowed phase.

Status descriptions distinguish implemented behavior, partial building blocks, explicit policy exceptions,
application/deployment responsibilities, OP-only requirements and excluded/non-applicable mechanisms. A SHOULD is not
reported as a MUST. A security finding requires a reachable failure and impact, not only a missing optional feature,
test, header or server-side capability that belongs to another party.

## 1. RFC 9700 — OIDC authorization-code client security

Source: [RFC 9700, Best Current Practice for OAuth 2.0 Security](https://www.rfc-editor.org/rfc/rfc9700.html),
BCP 240, January 2025, matching the supplied `oidc-specs/rfc9700.html`. This RFC updates security guidance used by OIDC
on top of OAuth. This pass covers its OIDC RP implications, not every generic OAuth deployment or resource-server role.
Assessed: 2026-09-25. Thirty entries cover the selected RP profile, its explicit policy exceptions and the requirements
that belong to the OP or deployment. “Complete for this scope” does not certify every optional configuration or every
OAuth role against the entire BCP.

### Flow choice, PKCE defaults and transaction construction

Spec references: [redirect-based flows](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1),
[code-flow protection](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1.1),
[front-channel token avoidance](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1.2), and
[attacker model](https://www.rfc-editor.org/rfc/rfc9700.html#section-3).

| ID / Requirement or boundary | What RFC 9700 requires or recommends | Current behavior and evidence | Qualification or remaining responsibility |
| --- | --- | --- | --- |
| 9700-01 — Code-flow profile | Prefer code/token-endpoint issuance; avoid front-channel access tokens unless the specified injection/leakage defenses exist. | **Implemented selected profile.** Login constructs `response_type=code`; it does not request implicit or hybrid front-channel tokens. [Request factory], [authorization configuration]. | The RFC does not prohibit every Hybrid response type: it also gives `code id_token` as an example. This module's code-only choice is narrower, and is not a claim to implement other response types. |
| 9700-02 — Public-client PKCE and defaults | Public clients MUST use PKCE; confidential-client use is RECOMMENDED, with an OIDC nonce alternative subject to additional precautions. | **Implemented default and public-client guard.** PKCE is enabled by default with S256. Active code-flow configuration using Token Endpoint authentication `NONE` cannot disable PKCE or select `PLAIN`. [Authorization configuration], [tenant validation]. | The local guard classifies `NONE` as public-client authentication. Confidential-client opt-outs exist and require separate evaluation of the nonce path; merely being confidential does not remove the code-injection protection requirement. |
| 9700-03 — Non-exposing challenge method | When using PKCE, clients SHOULD select a method that does not reveal the verifier in the authorization request; the RFC names S256. | **Default implemented; explicit policy exception available.** S256 hashes the verifier. Confidential-client configuration can explicitly choose `PLAIN`, which instead transmits it as the challenge. [Request factory], [authorization configuration], [tenant validation]. | Plain is not equivalent to S256 against authorization-request disclosure. It is a nondefault reduction in protection, not the preferred BCP profile. RFC 7636's full method-selection contract will be assessed in its own pass; this row is not a blanket interoperability/security endorsement of that option. |
| 9700-04 — Transaction-specific values and user-agent binding | PKCE challenge/nonce MUST be transaction-specific and securely bound to the client and initiating user agent. | **Implemented construction/protected state.** Each initiation generates separate 32-byte SecureRandom state, nonce and (when enabled) verifier values. Tenant, issuer, callback, nonce/verifier and expiry are retained in authenticated-encrypted cookie state, with Secure/HttpOnly/SameSite=Lax attributes. [Request factory], [cookie state handler]. | Cookie/state construction is not the whole protection: callback matching and nonce validation before token use are assessed below. Secure key provisioning and appropriate browser/origin deployment remain necessary. No claim of a global consumed-transaction database is implied. |
| 9700-05 — Establishing PKCE support | The AS MUST support/enforce PKCE and provide a way to detect it; metadata advertisement is recommended, while deployment-specific assurance is allowed. | **Metadata check implemented, with a static-deployment boundary.** When well-known metadata is loaded and PKCE enabled, the configured method must appear in `code_challenge_methods_supported`. The capability check is skipped when metadata was not loaded. [Tenant metadata validation], [Discovery metadata model]. | Static deployments must establish OP support out of band; the client cannot prove server-side verifier enforcement merely by constructing a challenge or reading an advertisement. PKCE enforcement and downgrade rejection at the Token Endpoint are OP responsibilities. |

### Callback binding, code redemption and mix-up prevention

Spec references: [CSRF](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.7.1),
[PKCE/code injection](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.5.3.1),
[OIDC nonce precautions](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.5.3.2), and
[mix-up defenses](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.4.2).

| ID / Requirement or boundary | What RFC 9700 requires or recommends | Current behavior and evidence | Qualification or remaining responsibility |
| --- | --- | --- | --- |
| 9700-06 — CSRF and application-state integrity | Prevent CSRF; protect application state against tampering/swapping. PKCE can be relied on only when support is established, with state/nonce otherwise required. | **Implemented layered callback checks.** Requires a single returned state and matching protected request cookie; validates tenant, exact state value, expiry and callback location before producing a redeemable code result. Ambiguous state/cookie input is rejected. [Callback processor], [cookie state handler], [callback tests]. | The callback does not trust state text alone or assume a challenge guarantees OP support. Cookie clearing limits ordinary browser reuse, but is not a claim of a global one-time state/nonce ledger. The default also uses PKCE and a checked ID Token nonce. |
| 9700-07 — Redeem using the original transaction | Bind code redemption to the initiating instance/transaction; client authentication alone does not stop code injection. | **Implemented request binding.** The code exchange uses the stored callback URI and PKCE verifier, rather than callback-supplied alternatives or a newly generated verifier. It does not automatically retry an exchange without PKCE. [HTTP feature], [endpoint client], [request factory]. | The OP must bind/enforce the code challenge and reject inappropriate verifier use. This client-side construction cannot prove the behavior of an external OP or replace its one-time code/client/redirect checks. |
| 9700-08 — Nonce validation before token use | A nonce-based defense MUST validate the Token Endpoint ID Token nonce and disregard all issued tokens until that succeeds. | **Implemented ordering.** Initial ID Token validation requires the saved nonce and checks signature/issuer/audience/time policy. Only after success does callback processing call UserInfo or construct/store a local authenticated session. Failure returns without those uses. [ID Token validator], [HTTP feature]. | This supplies the stated additional precaution for the confidential-client nonce alternative. It does not make disabled/plain PKCE equivalent to the default, eliminate request/response disclosure risks, or allow public clients to replace PKCE with nonce. |
| 9700-09 — Bind and validate the issuer before redemption | Multi-AS clients MUST prevent mix-up and retain the initiating issuer bound to the user agent; issuer-based defense compares the response issuer with that stored value before proceeding. | **Implemented.** Protected state retains issuer/tenant/callback. Response `iss`, when present, is checked by exact string comparison and rejected if duplicate/empty/mismatched; missing `iss` fails when advertised or required by overlapping multi-issuer callbacks. These checks precede the token exchange and also apply before handling an authorization error. [Request factory], [callback processor], [mix-up policy], [callback tests], [route tests]. | Checking only the issuer of the eventual Token Endpoint ID Token would be too late to prevent a code being sent to the wrong endpoint. The implemented check is on the authorization response, not a substitute ID Token after redemption. A single-AS setup need not enable every multi-AS defense. |
| 9700-10 — Distinct callback alternative | Distinct per-issuer callback URIs may be used, but the received location MUST match the expected issuer's URI; this alternative SHOULD be used only when other options are unavailable. | **Implemented alternative with conservative overlap detection.** Distinct paths or distinct absolute origins can avoid a mandatory `iss` when not advertised. Shared/possibly overlapping locations for different or unknown static issuers require it. Incoming origin/path and configured query values are checked against protected state. [Mix-up policy], [callback processor], [endpoint URI validation], [callback tests]. | Query-only differences do not count as disjoint in the local overlap policy. This alternative depends on correct OP registration and deployment; it is not as robust operationally as always receiving issuer identification. The check is not an implementation of the OP's separate registered-URI comparison rule. |

### Redirect destinations and front-channel leakage

Spec references: [redirect validation](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.1.3),
[Referer leakage](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.2),
[browser history](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.3), and
[open redirectors](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.11).

| ID / Requirement or boundary | What RFC 9700 requires or recommends | Current behavior and evidence | Qualification or remaining responsibility |
| --- | --- | --- | --- |
| 9700-11 — Registered redirect validation | The AS applies exact registered-URI matching, with the stated native-loopback exception; section 4.1.3 also discusses authenticated request origin/integrity as a basis for trusting the URI. | **OP responsibility; RP supplies a stable transaction value.** The RP resolves its configured callback, saves it in protected state and reuses that value for redemption. Its incoming callback-location check is separate. [Request factory], [callback processor], [endpoint URI validation], [HTTP feature]. | Helidon is not the OP registration/authorization service. Origin/path comparison in the RP must not be reported as a failure of the OP's exact registered-string rule. Operators must register the intended external callback and ensure the OP applies its applicable validation rules. |
| 9700-12 — RP must not be an open redirector | Clients MUST NOT expose arbitrary redirect targets; allowlisting or authenticated origin/integrity of the target are defenses. | **Implemented bounded destinations.** The post-login destination is reduced to a local path/query both when captured and before the 303 response; leading `//` is collapsed and the authority/fragment is not carried over. Protected state prevents callback-supplied target replacement. Logout redirect input separately requires an exact configured/allowlisted string. [URI handling], [request factory], [HTTP feature], [logout handler], [provider tests]. | This covers the module's handlers, not arbitrary application endpoints on the same host. A locally allowed destination that itself implements an application open redirect remains the application's responsibility. OP logout registration checks are still separate. |
| 9700-13 — Keep access tokens out of URI queries | Clients MUST NOT put access tokens into URI query parameters; prevent token forwarding to unintended recipients. | **Implemented for built-in OIDC client requests.** UserInfo sends the access token in the Authorization header, not the URI. Token requests use form POSTs, and token/UserInfo requests explicitly disable automatic redirect following. The login callback receives a code rather than an access token. [Endpoint client], [request factory]. | Applications receiving a TokenCredential must preserve these rules in their own outbound use. This row is not an audit of generic inbound resource-server query-token compatibility options, which are outside this OIDC RP slice. |
| 9700-14 — Referrer and result-page exposure | Authorization endpoints and result pages SHOULD avoid third-party resources/external links that disclose authorization data. Referrer-Policy is an additional listed mitigation. | **Exposure-reducing handler behavior; no dedicated referrer policy.** Successful callbacks immediately issue a local 303; errors return generic text rather than a page containing third-party assets, supplied error links or token values. The module does not set Referrer-Policy itself. [HTTP feature]. | The missing header alone is not an unconditional MUST violation or proof of exploitable leakage. Application result pages, response filters, logging, proxies and the OP's own pages need deployment review. Setting an appropriate policy is an available hardening choice; this pass has not simulated browser/referrer behavior. |
| 9700-15 — Code history, state reuse and alternate response delivery | Codes/state can appear in browser history or logs. PKCE/confidential-client defenses and one-time code use mitigate replay; form_post is one alternative delivery mitigation. State invalidation after use is recommended. | **Code-flow defenses implemented; query delivery retained.** The callback is GET/query based, successful handling clears the request cookie and returns to the saved local path. PKCE and nonce validation are as described above. There is no form_post callback or global consumed-state ledger. [HTTP feature], [callback processor], [cookie state handler]. | A 303 is not a promise to erase browser history or access logs, and deleting a browser cookie is not atomic server-side replay tracking. The OP MUST invalidate a used code and SHOULD revoke tokens already issued from it on replay. form_post is an optional countermeasure, not a universal RFC 9700 requirement for this code flow. |

### Transport, proxy trust, client authentication and metadata

Spec references: [client authentication](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.5),
[metadata/TLS guidance](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.6), and
[TLS-terminating reverse proxies](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.13).

| ID / Requirement or boundary | What RFC 9700 requires or recommends | Current behavior and evidence | Qualification or remaining responsibility |
| --- | --- | --- | --- |
| 9700-16 — Secure transport by default | Authorization responses MUST NOT use unencrypted connections, with the native-loopback exception. Protect credentials and tokens in transit; end-to-end client/resource TLS is recommended. | **Implemented default; explicit noncompliant test relaxation.** `endpoints.tls-required` defaults to true. Relevant configured/discovered endpoints and the resolved callback normally require HTTPS; disabling the option permits HTTP for eligible non-production traffic, but PAR and outgoing mTLS endpoints retain their independent HTTPS requirements. [Endpoint configuration], [endpoint URI validation], [request factory], [tenant metadata validation], [client authentication validation]. | An HTTPS URI check is not an audit of certificates, custom trust/SSLContext settings, TLS versions, or a deployment's internal links. This server-side RP does not provide a separate native-loopback profile. `tls-required=false` is not a production BCP-compliant mode merely because it is configurable. |
| 9700-17 — Trusted proxy/origin boundary | A TLS-terminating proxy MUST sanitize externally supplied security-relevant headers; its internal connection MUST resist eavesdropping, injection and replay and authenticate its peers. | **Deployment responsibility with framework integration.** Relative callbacks are resolved from the SecurityEnvironment request origin; callback verification uses `request.requestedUri()`. Webserver security populates that environment from the requested URI. A focused route test covers an explicitly configured forwarded external origin/prefix. [Request factory], [HTTP feature], [webserver security integration], [route tests]. | The OIDC module does not establish which proxy or forwarded headers to trust, sanitize the proxy's inputs, or secure its internal link. Configure trusted external-origin discovery, restrict direct backend access and protect the internal connection. An absolute configured callback can reduce origin inference but does not replace those proxy requirements. |
| 9700-18 — Authenticate clients and prefer asymmetric credentials | Client authentication should be used where feasible. Asymmetric methods such as mTLS or private_key_jwt are RECOMMENDED; the RFC does not universally forbid shared-secret methods. | **Asymmetric options implemented; not automatically selected.** Token requests and refreshes use the configured authentication method. `PRIVATE_KEY_JWT`, `TLS_CLIENT_AUTH` and `SELF_SIGNED_TLS_CLIENT_AUTH` are available alongside secret methods and `NONE`. Without an explicit selection, a supplied secret selects Basic; without a secret it selects NONE. mTLS configuration is checked for TLS/key capability and prefers advertised endpoint aliases. [Client authentication], [client authentication validation], [endpoint client]. | Registration, credentials and OP support must agree. Basic is an interoperability default, not the RFC's recommended asymmetric deployment choice. Public NONE clients instead need the public-client protections already described; key registration/provisioning is not automated by selecting an enum. Detailed assertion/mTLS protocol assessment belongs to their later RFC passes. |
| 9700-19 — Use authenticated, consistent metadata | AS metadata use is RECOMMENDED to reduce configuration mistakes and advertise capabilities; it does not remove client validation duties. | **Discovery building blocks implemented, with static configuration available.** The OIDC well-known loader requires a successful JSON response and disables redirects. Merge checks exact configured issuer consistency, followed by relevant endpoint, PKCE, response-type and authentication-capability checks. HTTPS is the default policy. [Metadata loader], [Discovery metadata model], [tenant metadata validation]. | Explicit/static configurations can avoid a fetch; operators then own capability consistency. Trust starts with the configured issuer/metadata location and transport, not arbitrary discovered values. This row credits metadata use for the BCP and does not imply full RFC 8414 discovery-path or signed-metadata support; those details await its own pass. |

### Credentials obtained by the OIDC login

Spec references: [token replay prevention](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.2),
[least privilege](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.3),
[token leakage/replay](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.9),
[sender/audience restrictions](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.10), and
[refresh-token protection](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.14).

| ID / Requirement or boundary | What RFC 9700 requires or recommends | Current behavior and evidence | Qualification or remaining responsibility |
| --- | --- | --- | --- |
| 9700-20 — Protect stored login credentials | Refresh tokens require confidentiality in storage and transit; token leakage creates replay risk. | **Implemented protected browser persistence.** Local session payloads include ID/access/refresh tokens and are AES-GCM encrypted/authenticated before cookie chunking. Keys are tenant/client/purpose separated, and session cookies are Secure/HttpOnly/SameSite=Lax. Refresh requests use the protected Token Endpoint path described above. [Cookie state handler], [cookie keys], [endpoint client]. | This is encrypted client-side storage, not a server-side opaque-session store. The resulting cookie is itself an authentication credential: encryption is not sender-constraining and does not make a stolen session cookie harmless. Protect the cookie password, configuration, process memory, application credentials and logs. No browser, key-management or deployment penetration test was performed here. |
| 9700-21 — Consume rotated refresh tokens correctly | Rotation relies on replacing the old token with the newly issued one and not continuing ordinary use of the invalidated token. | **Implemented successful-refresh replacement and local concurrency control.** A validated refresh stores a returned replacement refresh token, or retains the previous one when the OP omits a replacement. Same-source session requests share work/results within one tenant runtime and a bounded grace interval; coordination keys use token fingerprints. Existing tests cover rotation, virtual-thread callers, omitted replacement and invalid_grant. [Refresh manager], [refresh coordinator], [refresh tests]. | This is not distributed exactly-once redemption or OP token-family replay detection. Failed validation/storage after an OP response can still require reauthentication; not every successful server-side rotation guarantees a usable new local session. The bounded coordination window does not turn old cookies into globally revoked credentials. Tests were inspected, not rerun in this pass. |
| 9700-22 — Refresh issuance, client binding and replay policy | The AS MUST risk-assess refresh issuance, bind tokens to consented scope/resources, and enforce sender constraints or rotation for public clients. Confidential refresh tokens remain client-bound. Idle expiry is recommended; revocation on security events is optional. | **RP cooperation implemented; policy/enforcement belongs to OP.** Refreshes use the selected client authentication, preserve configured resource selection and do not request expanded scopes. An invalid_grant removes local authentication; a successful validated replacement is persisted. [Endpoint client], [client authentication], [refresh manager], [refresh tests]. | Helidon cannot prove OP rotation/reuse detection from an opaque token and does not infer it from PKCE. A public-client deployment must obtain an appropriate OP policy; accepting an omitted replacement is not evidence that an unbound/nonrotating public refresh token is safe. Local session expiry/logout is not OP token-family revocation or its idle-expiry policy. |
| 9700-23 — Request minimum privileges and intended resources | Keep privileges/audiences narrow; scope/resource and authorization_details are mechanisms clients/ASs MAY use. AS issuance and RS enforcement must implement the actual restrictions. | **Scope/resource controls implemented; richer authorization details absent.** Login defaults to `openid` alone, permits configured scopes and sends configured repeated `resource` values at authorization, code exchange and refresh. There is no authorization_details request builder in the built-in OIDC login. [Authorization configuration], [request factory], [endpoint client]. | Operators select only needed scopes/resources, and the OP/RS must enforce what is granted. Sending resource is not proof the access token is audience-restricted; validating an ID Token audience is not access-token audience enforcement. authorization_details is an optional richer mechanism, not a universal BCP requirement. Detailed RFC 8707/9396 coverage appears later in this document. |
| 9700-24 — Sender-constrained access tokens | ASs/RSs SHOULD use sender constraints and audience restrictions to limit stolen-token reuse; the RFC names mTLS and DPoP approaches. | **mTLS building blocks present; no DPoP OIDC token client.** Configured TLS credentials and mTLS authentication/alias selection can participate in a certificate-bound-token deployment. The token parser accepts only the Bearer type, and the built-in UserInfo client sends Bearer without a DPoP proof. [Client authentication], [client authentication validation], [endpoint client], [token response]. | mTLS client authentication alone does not prove that issued tokens are certificate-bound or that every consumer enforces binding. A certificate-bound token can still have the Bearer token_type, so that label alone neither proves nor rules out binding. DPoP-type responses are rejected, not silently used as bearer credentials. Separate module resource-server validators are not evidence of complete RP-side proof-bound-token support and are outside this slice. RFC 8705 is assessed below; RFC 9449 was intentionally not reviewed in detail. |

### Request integrity, excluded flows and OP-only controls

Spec references: [authenticated request integrity](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.1.3),
[code-injection limits](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.5.4),
[access-token injection](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.6),
[password grant](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.4),
[credential-bearing redirects](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.12),
[identity confusion](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.15),
[clickjacking](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.16), and
[in-browser messaging](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.17).

| ID / Requirement or boundary | What RFC 9700 requires or recommends | Current behavior and evidence | Qualification or remaining responsibility |
| --- | --- | --- | --- |
| 9700-25 — Request integrity/privacy options | PKCE/nonce do not remove the need to prevent authorization-request modification and response leakage. JAR/PAR plus client authentication are discussed as mechanisms to authenticate request origin/integrity. | **Additional mechanisms implemented when selected/configured.** Request Objects sign the authorization parameters and can additionally encrypt them. PAR sends parameters or a signed Request Object over a back channel and redirects with the returned request_uri. AUTO/REQUIRED policies exist; missing required configuration or conflicts with loaded metadata fail. A PAR failure does not trigger an unpushed retry. [Request object processor], [request object configuration], [request factory], [endpoint client], [tenant metadata validation]. | These mechanisms are not a universal RFC 9700 mandate, and AUTO does not mean every ordinary request is signed/encrypted/pushed. The OP must validate/enforce the agreed profile and register client keys. Signing alone gives integrity, not confidentiality. Additional response-leakage protections remain necessary. Their scoped RFC 9101/9126 assessments appear below. |
| 9700-26 — Front-channel access-token injection | The implicit-flow attack injects an access token into an otherwise matching transaction. Protected OIDC front-channel token responses need the appropriate ID Token/nonce/token-hash binding; code flow avoids that issuance path. | **Attack surface avoided by the selected flow.** The callback exchanges a bound code and obtains tokens only from the back channel; it does not authenticate a browser-supplied access_token. ID Token checks precede use; when UserInfo is enabled its subject must match the validated ID Token before claims are accepted. [Request factory], [callback processor], [HTTP feature], [UserInfo support]. | The UserInfo comparison is an adjacent OIDC defense, not a substitute implementation of implicit/hybrid at_hash validation. Those response modes are not implemented. Direct use of a stolen token at a resource server is a different risk and still needs the sender/audience restrictions above. |
| 9700-27 — No resource-owner password login | The resource-owner password credentials grant MUST NOT be used. | **Not implemented in the built-in OIDC login.** The RP redirects to the OP and exchanges an authorization code; it has no resource-owner password grant request or user-password collection step. [Request factory], [endpoint client]. | This is a desirable exclusion, not a missing OIDC feature to add. Client secrets and cookie-protection passwords are different credentials and are not the prohibited resource-owner password grant. No broader alternative-grant inventory is undertaken here. |
| 9700-28 — OP credential UI, redirects, clickjacking and CORS | An AS forwarding a credential-submitted request MUST NOT use 307 and SHOULD use 303 for an HTTP redirect. ASs MUST prevent clickjacking; CSP is recommended. CORS is forbidden on the AS authorization endpoint, but may be supported on specified browser-accessed back-channel endpoints. | **OP/server responsibility, not an RP feature gap.** OIDC-next neither serves the OP's credential/consent UI nor hosts its authorization, token or registration endpoints. Its local successful callback uses 303, but that does not attest to the OP's credential-handling behavior. [HTTP feature], [request factory]. | Configure/test the external OP and any hosted application UI as appropriate. Adding CSP/CORS or a new login form to the RP cannot by itself satisfy a requirement imposed on the OP's pages. Client-side callback/result-page exposure is assessed separately in 9700-14. |
| 9700-29 — postMessage authorization responses | When in-browser messaging is used, verify sender/receiver origins exactly, do not use wildcard targets, and preserve the normal authorization-response defenses. | **Not applicable to the implemented response transport.** This is a server-side redirect/query code callback; no postMessage response sender or receiver is provided. [HTTP feature], [request factory], [authorization configuration]. | Supporting browser messaging later would introduce these requirements. Its absence is not an origin-check failure in the current transport. Do not confuse this with ordinary HTTPS callback validation or claim that a general Java HTTP component implements a browser receiver. |
| 9700-30 — AS client/user identifier separation | Where client/user identifiers share a namespace, the AS SHOULD NOT let clients select identifiers that impersonate users; if unavoidable, it MUST let the RS distinguish the token contexts. | **AS/RS role boundary, not a configurable RP string restriction.** This module consumes an existing client registration for OIDC login; it does not allocate the OP's client/user identifiers or mint its access tokens. Its code-flow login identity is validated through the ID Token. [Client authentication], [HTTP feature], [ID Token validator]. | Rejecting arbitrary client-id strings locally cannot enforce the OP's identifier namespace. General client-credentials access-token interpretation at resource servers is outside this pass. Do not report an RP feature omission merely because this external AS/RS policy cannot be proven from local source. |

### Section-to-role cross-check

Sections 1–3 supply the terminology, recommendations and attacker model; section 4 elaborates the attacks and
countermeasures. Sections 5–6 add no separate implementation feature (no IANA action; security guidance points back to
sections 2–4). This map prevents an OP-only paragraph or a deliberately absent response transport from being silently
treated as implemented RP functionality.

| RFC area | Coverage in this pass | Deliberate boundary |
| --- | --- | --- |
| 2.1, 2.1.1, 2.1.2 — redirect flows | 9700-01–15, 25–26. | Code-flow RP only; AS validation remains external. |
| 2.2, 2.3 — token replay/privileges | 9700-20–24. | No general resource-server validation audit. |
| 2.4, 2.5 — password grant/client auth | 9700-18, 27. | No new grant inventory; asymmetric methods require registration/keys. |
| 2.6 — metadata, TLS, browser messaging, CORS | 9700-16–19, 28–30. | OP CORS/identity policies and proxy operation are separate roles. |
| 3 — attacker model | Applied to transaction, issuer, leakage and token-reuse assessments. | Source analysis is not a live A1–A5 exploit test or proof against client/OP compromise. |
| 4.1 — redirect-URI validation | 9700-07, 10–12, 25. | Distinguish OP registered-string matching from RP callback/return handling. |
| 4.2 — Referer leakage | 9700-14–15. | No module-owned external result-page content; application/OP pages and logging need their own review. |
| 4.3 — browser history | 9700-13, 15. | Query delivery remains; no promise to erase history or implement form_post. |
| 4.4 — mix-up | 9700-09–10. | Depends on OP issuer support or correct distinct URI registration. |
| 4.5 — code injection | 9700-02–08, 25. | Confidential nonce precautions do not remove leakage risks or public PKCE requirements. |
| 4.6 — access-token injection | 9700-01, 26. | No implicit/hybrid response consumer; stolen-token RS use is a separate problem. |
| 4.7 — CSRF | 9700-04–08, 15. | No global consumed-transaction ledger is claimed. |
| 4.8 — PKCE downgrade | 9700-02–05, 07. | Client sends the stored verifier without downgrade retry; OP must bind/enforce the challenge. |
| 4.9, 4.10 — token leakage/replay at RS | 9700-13, 20, 23–24 for credentials obtained by login. | General RS compromise, audience enforcement and proof verification are outside this RP slice. The nonstandard metadata examples in 4.10.3 are discussion, not required fields to implement. |
| 4.11 — open redirectors | 9700-11–12. | Other application endpoints and OP redirects are not certified by the module's local-target helper. |
| 4.12 — 307 redirect | 9700-28. | The credential-posting OP is responsible, not the RP's code callback. |
| 4.13 — reverse proxy | 9700-16–17. | Deployment must sanitize trusted headers and secure/authenticate the internal link. |
| 4.14 — refresh protection | 9700-20–22. | Local rotation cooperation does not implement OP issuance/reuse detection/revocation policy. |
| 4.15 — client impersonating user | 9700-30. | AS namespace/RS token-context requirement; no client-credentials RS audit. |
| 4.16 — clickjacking | 9700-28. | OP authentication/consent UI responsibility. |
| 4.17 — in-browser communication | 9700-29. | No postMessage authorization-response flow. |

### Practical outcome of this RFC pass

- **Covered RP defaults:** code-only login, S256 PKCE, protected transaction state, pre-redemption issuer defenses,
  nonce/ID Token validation before token use, local return destinations, HTTPS policy and encrypted session storage.
- **Available with configuration:** asymmetric client authentication, scope/resource selection, signed/encrypted
  Request Objects and PAR. Metadata and correctly registered OP capabilities are part of the deployment contract.
- **Do not confuse compatibility with the preferred profile:** confidential PKCE disable/plain options, Basic as the
  inferred secret-authentication method, and the test-only TLS override are not all equivalent to the strongest BCP
  deployment. In particular, plain/off PKCE needs its qualifications above; the detailed RFC 7636 pass follows below.
- **Absent mechanisms with a bounded consequence:** no DPoP OIDC client, authorization_details, form_post callback or
  postMessage authorization response. None is universally required by RFC 9700 for this selected code-flow RP. A profile
  or OP that specifically requires one would need additional implementation; it must not be advertised as supported.
- **Not appropriate to label as RP implementation gaps:** OP code/refresh replay enforcement, token issuance/audience
  policy, OP login-page protections, client identifier allocation and proxy administration. Helidon must cooperate with
  them, but cannot prove or replace them from this module.

This pass does not establish a new exploitable vulnerability. It records supported mechanisms, nondefault protection
reductions and real feature/role limits without turning each missing optional mechanism into a security finding. It is
not a statement that every configuration, external OP or deployment is secure.

Method: read the supplied RFC's substantive text and map requirements to the current implementation, with selected
existing test bodies as supporting evidence. Normative strength and RP/OP/RS/deployment roles were kept distinct. No
tests, browser experiments, external-OP conformance checks or penetration tests were run. No runtime code was changed.
The completed eight-spec OIDC inventory remains a separate artifact. Detailed PKCE coverage follows in section 2.

## 2. RFC 7636 — Proof Key for Code Exchange (PKCE)

Source: [RFC 7636, Proof Key for Code Exchange by OAuth Public Clients](https://www.rfc-editor.org/rfc/rfc7636.html),
Standards Track, September 2015, matching the supplied `oidc-specs/rfc7636.html`. Assessed: 2026-09-25.
Scope: PKCE in OIDC-next's authorization-code RP, including configuration, request construction, protected transaction
state and redemption. The OP's challenge/code association and verifier enforcement are separate responsibilities.
The native-app interception example explains the mechanism; it does not make Helidon a native-application framework.
Complete for this scope: twenty entries and one accepted, explicitly selected conformance exception. The normal S256
path is implemented; the supported configuration surface cannot receive an unqualified compliance verdict because
7636-F01 remains intentionally available as an opt-out.

### Verifier/challenge construction and request parameters

Spec references: [protocol flow](https://www.rfc-editor.org/rfc/rfc7636.html#section-1.1),
[base64url terminology](https://www.rfc-editor.org/rfc/rfc7636.html#section-3),
[verifier creation](https://www.rfc-editor.org/rfc/rfc7636.html#section-4.1),
[challenge creation](https://www.rfc-editor.org/rfc/rfc7636.html#section-4.2), and
[authorization request](https://www.rfc-editor.org/rfc/rfc7636.html#section-4.3).

| ID / Requirement or boundary | What RFC 7636 requires or describes | Current behavior and evidence | Qualification or remaining responsibility |
| --- | --- | --- | --- |
| 7636-01 — Client-side PKCE flow | Correlate authorization and code redemption with a per-request secret: send its transformed challenge first and the original verifier only at redemption. | **Implemented client flow.** PKCE is enabled with S256 by default. Request creation generates a verifier, derives its challenge and keeps the original in the saved transaction. [Authorization configuration], [request factory]. | PKCE supplements the OIDC code flow; it neither issues codes nor substitutes for OP verifier enforcement. The detailed storage/redemption path and exceptional configurations are assessed below. |
| 7636-02 — Fresh cryptographic verifier | Create a high-entropy cryptographically random verifier for each authorization request; a 32-octet random input is recommended. | **Implemented.** Each enabled-PKCE initiation calls SecureRandom for a new 32-byte value. State and nonce use separate random draws; the verifier is not the client secret, a tenant constant or a reused shared challenge. [Request factory]. | This is source evidence for the generator and per-request construction, not a statistical certification of the deployed random-number provider or a guarantee against process compromise. |
| 7636-03 — Verifier syntax and encoding | The verifier has 43–128 unreserved ASCII characters. Base64url has no padding, line breaks or added whitespace. | **Implemented generated profile.** The JDK URL-safe Base64 encoder, without padding, turns the 32 random bytes into 43 characters from the permitted alphabet. [Request factory]. | A valid subset of unreserved characters is sufficient: the generator need not emit `.` or `~`, nor offer every permitted verifier length. There is no caller-supplied arbitrary verifier in the normal login request builder. |
| 7636-04 — S256 transformation | Compute the URL-safe unpadded Base64 encoding of the SHA-256 digest of the verifier's ASCII bytes; the challenge must satisfy its defined syntax. | **Implemented.** The S256 branch applies SHA-256 to US_ASCII verifier bytes, then the same unpadded URL encoder. The 32-byte digest produces a 43-character challenge. [Request factory], [PKCE methods]. | This establishes the S256 calculation, not the permissibility of selecting every other advertised enum value. Method-selection requirements are separate from correct transformation arithmetic. |
| 7636-05 — Authorization request fields | code_challenge is required when using PKCE. code_challenge_method identifies the transformation and defaults to plain if omitted. | **Implemented explicit method.** Enabled PKCE adds both fields once to the constructed authorization parameters. The enum sends exactly `S256` or `plain`; it does not accidentally omit the method and thereby invoke the protocol's plain default. [Request factory], [PKCE methods]. | Request construction does not prove that the OP records/enforces either parameter. The S256/default path and the explicitly selectable plain path must not receive a single undifferentiated compliance verdict. |

### Method selection, compatibility and verifier secrecy

Spec references: [method-selection rule](https://www.rfc-editor.org/rfc/rfc7636.html#section-4.2),
[compatibility](https://www.rfc-editor.org/rfc/rfc7636.html#section-5),
[entropy/secrecy](https://www.rfc-editor.org/rfc/rfc7636.html#section-7.1), and
[eavesdropping/downgrade protection](https://www.rfc-editor.org/rfc/rfc7636.html#section-7.2).

| ID / Requirement or boundary | What RFC 7636 requires or describes | Current behavior and evidence | Qualification or remaining responsibility |
| --- | --- | --- | --- |
| 7636-06 — S256-capable clients must select S256 | A client capable of S256 MUST use it. Plain is permitted only for a client that cannot support S256 for a technical reason and knows out of band that the server supports plain. | **Correct default/public guard; accepted explicit exception for confidential clients.** The RP implements S256, but an authenticated client can deliberately select PLAIN. The factory then emits the verifier as the challenge. A provider test explicitly expects that result. [Authorization configuration], [tenant validation], [PKCE methods], [request factory], [provider tests], [configuration tests]. | A legacy server lacking S256 does not satisfy the client-incapability exception. That explicitly selected client configuration is not RFC 7636-conformant; retaining it is the documented 7636-F01 compatibility choice, not a default-flow defect or a proven standalone exploit. |
| 7636-07 — Do not retry with a weaker transformation | Clients MUST NOT fall back to plain after trying S256. | **No automatic downgrade path found.** The method is fixed by configuration. Authorization errors terminate the callback; failed token exchanges return failure. Neither path regenerates the request with plain or retries redemption without the saved verifier. [Request factory], [callback processor], [HTTP feature], [endpoint client]. | The static plain choice in 7636-06 is a distinct issue under section 4.2, not evidence that the implementation performs the retry forbidden by section 7.2. Operators must not interpret a server's S256 rejection as a reason to silently lower the method. |
| 7636-08 — Compatibility versus assured support | Section 5 recommends sending the extra parameters even without advance knowledge of server support; an older server can ignore the extension. That does not prove PKCE is enforced. | **Stricter loaded-metadata policy, with static configuration available.** When metadata was loaded and PKCE is enabled, the selected method must be advertised; a missing method list or unsupported selected method rejects initialization. This capability precheck is skipped without a metadata fetch. [Tenant metadata validation], [metadata tests]. | Advertisement is not defined by RFC 7636 itself. The check is a later metadata/security-policy integration, not a missing PKCE wire feature. It deliberately limits interoperability with older metadata deployments; static deployment must establish OP enforcement separately. An ignored challenge never supplies PKCE protection merely because the login succeeds. |
| 7636-09 — Explicitly running without PKCE | The extension is distinguishable from ordinary OAuth code flow; section 5 recommends sending its parameters. Current public-client requirements also depend on the later security BCP. | **Explicit non-PKCE confidential option.** Disabling PKCE suppresses both authorization fields and leaves no verifier for redemption. Public NONE-authenticated clients cannot select this option. [Authorization configuration], [tenant validation], [request factory], [endpoint client], [provider tests], [configuration tests]. | This is a compatibility policy exception, not PKCE support in the disabled flow and not the same MUST-level method-selection issue as choosing plain while using PKCE. The confidential nonce alternative and its conditions are covered in 9700-02/08; public clients cannot use it to avoid their PKCE requirement. No automatic opt-out occurs. |
| 7636-10 — Keep the verifier secret between requests | Protection depends on the verifier remaining unlearned and unguessable by the attacker until it is sent to the Token Endpoint over the protected channel. | **Protected transaction persistence implemented.** The original verifier is serialized inside the authenticated-encrypted request cookie, not left as readable cookie text or placed in the state query value. Cookie attributes are Secure, HttpOnly and SameSite=Lax; an existing test checks that raw values are absent and tampering is rejected. [Request factory], [cookie state handler], [provider tests]. | The default S256 request exposes only the hash-derived challenge. Plain deliberately exposes the verifier wherever its challenge is visible. Cookie encryption cannot undo that exposure, and key, endpoint, browser and process compromise remain outside this construction's guarantee. |

### Transaction binding, redemption and the OP boundary

Spec references: [challenge/code association](https://www.rfc-editor.org/rfc/rfc7636.html#section-4.4),
[verifier submission](https://www.rfc-editor.org/rfc/rfc7636.html#section-4.5),
[server verification](https://www.rfc-editor.org/rfc/rfc7636.html#section-4.6), and
[TLS considerations](https://www.rfc-editor.org/rfc/rfc7636.html#section-7.5).

| ID / Requirement or boundary | What RFC 7636 requires or describes | Current behavior and evidence | Qualification or remaining responsibility |
| --- | --- | --- | --- |
| 7636-11 — Redeem with the initiating transaction's verifier | Redemption uses the original secret corresponding to the authorization request, not a newly generated or response-supplied verifier. | **Implemented.** The request cookie restores its saved verifier. Callback checks bind tenant, state, issuer, expiry and callback location before the HTTP feature passes that verifier with the code to the Token Endpoint client. Callback-supplied verifier/method values are not inputs to this exchange. [Request factory], [cookie state handler], [callback processor], [HTTP feature]. | State/issuer/nonce checks are surrounding OIDC defenses, not extra PKCE wire fields. This is protected transaction binding, not a claim that Helidon maintains a global consumed-verifier database. One-time code handling belongs to the OP. |
| 7636-12 — Token request placement and exact value | code_verifier is required at the Token Endpoint for a PKCE transaction. The verification method is the one already bound to the issued code. | **Implemented.** Code exchange sends the original verifier in the form-encoded POST body alongside code, grant_type and the original redirect_uri. It does not hash it again, send only the challenge, or attempt to renegotiate the method at redemption. The request is not a verifier-bearing URI query. An existing test asserts the exact form fields and POST media type. [Endpoint client], [HTTP feature], [code exchange tests]. | No verifier is sent for the explicit non-PKCE flow. Client authentication is applied separately; the presence of Basic/JWT/mTLS does not change which saved PKCE value is sent. |
| 7636-13 — Protected verifier transport | The verifier's confidentiality is essential; section 7.5 directs deployments to the current TLS security guidance rather than retaining obsolete OAuth TLS-version advice. | **HTTPS default and non-forwarding requests.** Configured/discovered Token Endpoints are checked against the default TLS-required policy. The form POST disables automatic redirect following, preventing this client path from automatically forwarding the verifier to a redirect target. [Endpoint configuration], [endpoint URI validation], [tenant metadata validation], [endpoint client]. | `tls-required=false` is an explicit documented non-production relaxation, not secure PKCE transport. HTTPS URL checks do not certify custom TLS trust, versions, proxy links, logs or host compromise. PKCE does not replace secure transport. |
| 7636-14 — Retain PKCE when composing authorization requests | The logical authorization request must carry the challenge/method corresponding to the saved verifier. Later request-container extensions must not accidentally drop that binding. | **Composition implemented.** The factory builds PKCE parameters before wrapping or pushing them. Request Object construction preserves them as claims; PAR transmits the parameters or containing Request Object and returns a request_uri for browser redirection. Existing tests cover signed-request fields, PAR form fields and their combination. [Request factory], [request object processor], [endpoint client], [provider tests], [configuration tests], [code exchange tests]. | JAR/PAR are not required by RFC 7636; their scoped RFC reviews follow below. A signed object is readable unless also encrypted; request protection is not permission to ignore the method-selection rule. The same saved verifier still goes to the Token Endpoint. |
| 7636-15 — OP association, server capability and code confidentiality | The OP MUST bind challenge/method to the issued code and later use that bound method. S256 is mandatory for a PKCE server. Challenge material must not leak through the returned code; stateless plain-bearing codes require server-only encryption. | **OP responsibility; no missing RP code-issuer implementation.** Helidon sends the chosen challenge/method and treats the authorization code as an opaque value to redeem. It does not issue or unpack the OP's code. [Request factory], [callback processor], [endpoint client]. | The encrypted Helidon request cookie is not the OP's authorization-code format. Implementing code encryption, code storage or server-side verifier comparison here would not enforce these requirements on an external OP. Its behavior requires OP conformance testing. |

### Verification/error roles, registry and regression evidence

Spec references: [authorization errors](https://www.rfc-editor.org/rfc/rfc7636.html#section-4.4.1),
[Token Endpoint verifier checks](https://www.rfc-editor.org/rfc/rfc7636.html#section-4.6),
[parameter registration](https://www.rfc-editor.org/rfc/rfc7636.html#section-6.1),
[method registry](https://www.rfc-editor.org/rfc/rfc7636.html#section-6.2),
[no challenge salt](https://www.rfc-editor.org/rfc/rfc7636.html#section-7.3),
[encoding example](https://www.rfc-editor.org/rfc/rfc7636.html#appendix-A), and
[S256 example](https://www.rfc-editor.org/rfc/rfc7636.html#appendix-B).

| ID / Requirement or boundary | What RFC 7636 requires or describes | Current behavior and evidence | Qualification or remaining responsibility |
| --- | --- | --- | --- |
| 7636-16 — OP enforcement and protocol errors | The authorization endpoint returns invalid_request for a missing required challenge or unsupported requested method. The Token Endpoint transforms the verifier using the bound method, compares it, continues ordinary processing on a match and returns invalid_grant on mismatch. | **OP responsibility; client request construction is present.** The RP supplies the challenge and original verifier and receives the usual code/token responses. It does not implement the external Token Endpoint's comparison or mint tokens. [Request factory], [endpoint client]. | Success from an OP that ignored PKCE is not proof of enforcement. A matching verifier is necessary for a PKCE transaction, not sufficient to bypass ordinary code/client/redirect checks. Missing OP comparison logic in this RP is not an implementation defect. |
| 7636-17 — Handle ordinary responses/errors without weakening PKCE | PKCE uses the existing authorization/token response formats and error fields; no special verifier-confirmation response is defined. | **Implemented ordinary failure handling.** Validated authorization errors stop before code exchange. Token error bodies are parsed, including invalid_grant; the callback returns failure before ID Token validation/session creation when exchange fails. No PKCE-specific success echo is required or trusted. [Callback processor], [endpoint client], [HTTP feature], [code exchange tests], [route tests]. | The browser receives a generic error rather than reflected OP descriptions or links. There is no automatic PKCE downgrade/recovery policy. Parsing an invalid_grant fixture demonstrates client handling, not that a real OP correctly verifies all malformed or missing verifiers. |
| 7636-18 — Registered names and extensibility | Parameter names and usage locations are registered; challenge-method names are case-sensitive. The RFC defines plain/S256 and a process for registering extensions. | **Defined wire names implemented; method set intentionally closed.** The three parameters use the defined underscore names, and enum wire values are `plain` and `S256`. There is no arbitrary method-name/hash plugin API. [PKCE methods], [request factory], [endpoint client], [configuration tests]. | An IANA extension-registration process is not a requirement for every client to support unknown future methods. Correctly naming plain does not make its selection permissible for this S256-capable RP. ABNF rule labels containing hyphens are not alternative HTTP parameter spellings. |
| 7636-19 — Unmodified, unsalted transformation | The S256 formula has no additional salt; the verifier's entropy supplies resistance to guessing. | **Implemented as defined.** The calculation hashes only the verifier's ASCII bytes. It does not mix in tenant IDs, client secrets, cookie keys or password-hardening parameters. [Request factory]. | Cookie-key derivation and its salt serve a different purpose and do not change the PKCE formula. The RFC's discussion of challenge salting is not general password-storage advice and does not justify changing cookie-password protection. |
| 7636-20 — Published examples and regression confidence | Appendices A/B give concrete base64url/S256 examples; they do not prescribe a test suite. | **Correct primitive construction; focused test improvement available.** Existing tests cover S256 request construction, protected state, exact redemption fields, public-client guards, metadata failures and JAR/PAR composition. The S256 request expectations reuse the production challenge helper; no literal Appendix A/B known-answer vector was found in the module's source/test tree. [Request factory], [provider tests], [configuration tests], [code exchange tests], [metadata tests]. | Add an independent Appendix B expected-value assertion and generated-verifier length/alphabet checks when improving tests; retain the explicit plain-acceptance regression for the documented compatibility exception. This is test hardening, not a second protocol defect. Tests were inspected, not executed in the initial inventory pass; no live OP conformance was established. |

### Accepted compatibility exception 7636-F01 — selectable plain despite S256 capability

**Disposition — 2026-09-30: accepted explicit compatibility exception; documentation committed as `1940827324`, no
runtime change requested.** OIDC-next keeps
the deliberately selected `PLAIN` option for authenticated confidential clients, with no second opt-in or automatic
downgrade. The default remains `S256`, and public clients cannot select `PLAIN`. The README and option/enum Javadocs now
state explicitly that this S256-capable RP using `PLAIN` does **not** comply with the RFC method-selection rule and loses
protection when the Authorization Request is observed. Supporting that user-chosen profile is not by itself an accidental
default-path security defect. This closes the item as a code-fix request, **not** as an assertion that `PLAIN` became
RFC-conformant.

Classification: **nondefault protocol-conformance exception and loss of one PKCE defense**, not a demonstrated default-flow
exploit. The exact rule is [RFC 7636 section 4.2](https://www.rfc-editor.org/rfc/rfc7636.html#section-4.2):
“If the client is capable of using \"S256\", it MUST use \"S256\"”. Section 7.2 further limits plain in new implementations.

Source-backed reachability:

1. On an otherwise valid code-flow tenant, supply a client secret (or another supported authenticated-client method) and select
   `authorization-code.pkce-method: PLAIN`. PKCE remains enabled by default.
2. `OidcTenantConfigDecorator.validatePkce` returns before the PLAIN rejection when the effective authentication method
   is not NONE. No technical lack of SHA-256 capability is involved.
3. `OidcAuthenticationRequestFactory.codeChallenge` returns the verifier unchanged for PLAIN, and the normal request
   builder sends it as code_challenge with method `plain`.
4. `OidcProviderTest.authorizationCodeFlowCanUsePlainPkceMethod` asserts this reachable behavior using a confidential
   tenant. At initial assessment the option/enum Javadoc recommended it for legacy confidential integrations without
   identifying the RFC deviation; that documentation is now corrected. [Tenant validation],
   [request factory], [provider tests], [authorization configuration], [PKCE methods].

The legacy-server justification does not meet the RFC's client-incapability condition. The S256 implementation is already
present in this same RP. The arithmetic for plain is correct; the explicit choice remains nonconformant for the client
that makes it and is now described as such, rather than as an RFC-compatible answer to a server limitation. RFC 9700's
separate SHOULD-level wording does not by itself establish compliance with this more specific PKCE method rule.

Impact is bounded: default S256 and public-client configurations do not take this path. In an ordinary direct plain
authorization request, observing the challenge also reveals the verifier, removing PKCE's protection against that request
observation. Client authentication, nonce validation and any selected request-protection mechanisms are separate defenses;
the source evidence alone does not establish account takeover in this confidential-client deployment. This is also not an
automatic S256-to-plain retry.

Decision: retain the existing explicit choice for authenticated clients without weakening the secure default, adding a
second switch, or silently disabling PKCE. A future strict-all-configurations policy could remove or reject `PLAIN`, but
that is not the chosen compatibility contract. No behavior changed in this disposition.

### Errata and interpretation boundaries

The supplied 2015 text has a section-5 wording error: the missing authorization-request parameter is code_challenge,
not code_verifier. The RFC Editor lists [Erratum 5687 as verified](https://www.rfc-editor.org/errata/eid5687).
Sections 4.3, 4.5 and 6.1 already make the two parameters' locations unambiguous; do not implement the typo by exposing
code_verifier in the authorization request.

The [official errata listing](https://www.rfc-editor.org/errata/rfc7636) also shows 6471 (section-7.1 naming) and 6179
(salting discussion) as Reported, and 8457/8458 (ABNF label spelling) as Rejected. They are not adopted here as verified
protocol changes. The section-4.1 verifier construction and section-4.2 S256 formula remain the basis for this review.
Errata records were available through indexed RFC Editor results; direct errata-page requests were rate-limited, so a
fresh live confirmation of those page statuses was unavailable. None changes the basis of 7636-F01.

### Section-to-role cross-check

| RFC area | Coverage in this pass | Qualification |
| --- | --- | --- |
| 1, 1.1 — attack and protocol model | 7636-01, 02, 10–16. | Server-side OIDC RP use, not native-app scheme registration or an OP implementation. |
| 2, 3 — notation/encoding | 7636-03–05, 18. | ASCII, base64url and parameter spellings distinguished from ABNF rule labels. |
| 4.1 — verifier construction | 7636-02–03, 10, 20. | Fresh 32-byte random source; generated 43-character value satisfies the syntax. |
| 4.2 — challenge and selection | 7636-04, 06, 19; 7636-F01. | S256 arithmetic is correct; explicitly selected plain remains an accepted nonconformant opt-out. |
| 4.3 — authorization parameters | 7636-05, 14. | Challenge/method, not the raw S256 verifier, belong in the logical authorization request. |
| 4.4, 4.4.1 — code association/errors | 7636-15–17. | Code issuer records the method/challenge and emits the prescribed errors. |
| 4.5 — verifier redemption | 7636-11–13. | Exact saved verifier in the token form; no client-side method renegotiation. |
| 4.6 — verifier check | 7636-15–17. | OP comparison/enforcement; no claim that the local error fixtures certify it. |
| 5 — compatibility | 7636-08–09, 17; Erratum 5687 note. | Older silent-ignore behavior is not proof of PKCE protection; later policies can be stricter. |
| 6, 6.1, 6.2 — registries | 7636-05, 12, 18. | Implement defined names, not an IANA registration service or arbitrary extension plugin system. |
| 7.1 — entropy/secrecy | 7636-02–03, 10. | Source-backed cryptographic construction, not environmental entropy certification. |
| 7.2 — request disclosure/downgrade | 7636-06–07, 10, 13, 15; 7636-F01. | Static plain issue separated from absent automatic downgrade retry and OP code-encryption duties. |
| 7.3 — salting | 7636-19. | No PKCE salt; do not reuse this discussion as general password-storage guidance. |
| 7.4, 7.5 — wider OAuth/TLS security | 7636-10–13 and the preceding RFC9700 inventory. | PKCE does not replace issuer/state/nonce, transport, OP or deployment controls; no standalone TLS audit. |
| Appendices A, B | 7636-03–04, 20. | Examples read; independent known-answer regression suggested, not claimed to have been run. |

### Practical outcome of this RFC pass

- **Covered:** fresh high-entropy verifier, permitted syntax, exact S256 transformation, explicit request fields,
  protected transaction storage, original-verifier redemption, failure handling and retention through JAR/PAR.
- **Accepted explicit exception:** confidential clients can choose plain despite S256 capability (7636-F01). This profile
  is outside RFC 7636 compliance and weakens request-disclosure protection; the default S256 path is unaffected.
- **Not missing RP features:** OP challenge/code binding, verifier comparison, code encryption and issuance/error policy.
  No required native-app integration, arbitrary method plugin, salt or PKCE-specific success response needs to be added.
- **Optional regression improvement:** an independent Appendix B S256 known-answer test and generated-value syntax checks.
  This does not constitute another security/spec finding. No PKCE-specific new Common utility is warranted by this pass:
  construction already uses Helidon common Parameters/UriQueryWriteable and the standard JDK cryptographic primitives.
  [Request factory].

Method: examined the supplied RFC's substantive sections and appendices, current source and focused existing test bodies;
consulted official RFC Editor material for edition/errata context with the access limitation above. No code was changed,
tests rerun or live OP/browser attack simulated. This is not a certification of external server behavior or every
deployment. The original eight-spec inventory and the thirty RFC9700 feature rows are preserved. Detailed issuer-response
coverage follows in section 3.

## 3. RFC 9207 — Authorization Server Issuer Identification

Source: [RFC 9207, OAuth 2.0 Authorization Server Issuer Identification](https://www.rfc-editor.org/rfc/rfc9207.html),
Standards Track, March 2022, matching the supplied `oidc-specs/rfc9207.html`. Assessed: 2026-09-25.
Scope: the `iss` authorization-response extension as consumed by the OIDC code-flow RP, its metadata and mixed-provider
policies, and the boundaries of its mix-up protection. OIDC issuer claims obtained only after code redemption are not
treated as equivalent protection. Assessment is complete for this scope: twenty entries and one source-level conditional
security/design finding. This is not an unqualified RFC9207 compliance verdict.

### Response identity, decoding and validation order

Spec references: [purpose/threat model](https://www.rfc-editor.org/rfc/rfc9207.html#section-1),
[response parameter and examples](https://www.rfc-editor.org/rfc/rfc9207.html#section-2),
[providing the issuer](https://www.rfc-editor.org/rfc/rfc9207.html#section-2.3), and
[client validation](https://www.rfc-editor.org/rfc/rfc9207.html#section-2.4).

| ID / Requirement or boundary | What RFC 9207 requires or describes | Current behavior and evidence | Qualification or remaining responsibility |
| --- | --- | --- | --- |
| 9207-01 — Response-side issuer identification | A supporting OP includes its issuer in authorization responses, including errors, so the client can identify the intended server before disclosing grant credentials. | **Implemented RP consumer for the selected flow.** The GET/query code callback recognizes `iss`; it is not treated as an unknown field or replaced by a Token Endpoint ID Token claim. [HTTP feature], [callback processor]. | OP emission is external. No request parameter in this RFC tells an otherwise unsupported OP to implement the extension. Other response transports and OIDC modes are assessed separately below; receiving an ordinary code response is not a claim to implement them. |
| 9207-02 — Use the issuer expected for this transaction | Compare against the initiating AS's metadata issuer, or a deployment-specific expected issuer where metadata is not used; the returned value must not choose its own trust anchor. | **Implemented saved issuer/tenant binding.** Initiation takes the resolved issuer from tenant metadata and stores it with tenant/state/callback in the protected request cookie. The callback requires the saved issuer to still equal the current tenant's issuer before considering the returned `iss`. Static issuer configuration is supported; metadata merge rejects an exact configured-issuer mismatch. [Request factory], [cookie state handler], [callback processor], [Discovery metadata model]. | The response does not select a new discovery URL or reroute redemption solely by its `iss`. Trust still starts with configured metadata/endpoints. Cross-tenant issuer identity uniqueness is a distinct section-4 requirement and is not proved by this per-transaction equality check. |
| 9207-03 — Decode the form-encoded value | Extract a supplied issuer value and decode its application/x-www-form-urlencoded representation before comparison. | **Implemented through existing Common URI handling.** The callback consumes decoded UriQuery values. Common's query parser decodes names and values, including percent-encoded UTF-8 and ordinary form `+` handling; the OIDC comparison does not apply a second URL decode. The callback test includes the encoded `https%3A%2F%2F...` form. [Callback processor], [Common query parser], [Common URI encoding], [callback tests]. | Form decoding and issuer-URL normalization are different operations. Once the outer query encoding is removed, any percent escapes belonging to the issuer identifier itself remain part of its exact string. This does not claim exhaustive testing of malformed form encodings. |
| 9207-04 — Exact comparison before proceeding | Use simple string comparison. On an issuer mismatch, reject the response and do not continue the grant. | **Implemented.** The issuer branch uses String.equals against the saved expected issuer, with no case folding, trailing-slash removal or URI-equivalence comparison. A mismatch returns an invalid result before a redeemable code is produced; the HTTP feature exchanges only validated results. [Callback processor], [HTTP feature], [callback tests]. | URI-equivalent strings are not necessarily equal issuer identifiers. A later ID Token issuer check alone would occur after possible code disclosure and would not replace this check. Actual OP identity/endpoints still depend on correct trusted configuration. |
| 9207-05 — Apply issuer checks to error responses | The OP includes iss on errors as well; a client must not attribute a mismatched error to the intended OP. | **Implemented common validation order.** Issuer validation runs before the callback's code/error branch. A mismatched issuer with error=access_denied is rejected as an invalid authorization response, rather than being handled as an error from the intended OP; an existing focused test asserts this path. [Callback processor], [HTTP feature], [callback tests]. | The presence policy for an omitted issuer still depends on metadata/local policy, as detailed below. This is RP validation, not proof that the remote OP adds iss to every error it emits. |

### Metadata, presence requirements and compatibility policy

Spec references: [advertising support](https://www.rfc-editor.org/rfc/rfc9207.html#section-2.3),
[mixed-support client policy](https://www.rfc-editor.org/rfc/rfc9207.html#section-2.4), and
[metadata field/default](https://www.rfc-editor.org/rfc/rfc9207.html#section-3).

| ID / Requirement or boundary | What RFC 9207 requires or describes | Current behavior and evidence | Qualification or remaining responsibility |
| --- | --- | --- | --- |
| 9207-06 — Support metadata and its default | authorization_response_iss_parameter_supported is Boolean and defaults to false when omitted; a metadata-publishing supporting OP advertises true. | **Implemented metadata consumer.** The metadata model reads the field as a JSON Boolean and uses false only when absent. Metadata merging retains an advertised true value. The JSON accessor rejects a present non-Boolean rather than coercing a string to true. [Discovery metadata model], [JSON Boolean access], [JSON value types], [metadata tests]. | This is consumption, not publication of AS metadata. An invalid metadata document can fail initialization; the RFC does not require the RP to repair it. OP advertisement does not prove that every actual response will follow the claim. |
| 9207-07 — Remember support and reject required omissions | In mixed-support deployments, retain each server's support state and reject missing iss where the server supports it according to client configuration. | **Implemented in tenant runtime metadata.** The retained tenant context carries the support flag. Callback validation rejects a missing issuer when that flag is true, regardless of whether the result would otherwise be a code or an error. Tests cover advertised support and missing-issuer rejection. [Tenant runtime registry], [Discovery metadata model], [callback processor], [callback tests], [metadata tests]. | The flag is not inferred from the current response's contents. Metadata loading and static deployment are different paths; this row does not claim that the RP fetches every OP's metadata merely because its issuer is configured. |
| 9207-08 — Unadvertised but matching issuer | Discarding an unsolicited iss is a SHOULD, with an explicit local-policy exception for legitimate OPs that send it without advertising support. | **Permitted lenient policy implemented.** Any supplied nonempty single issuer value is compared to the saved issuer even when the support flag is false; an exact match is accepted rather than rejected solely for absent advertisement. The encoded-issuer callback test uses a static tenant. [Callback processor], [callback tests]. | This is within the RFC's explicit policy allowance, not a MUST violation. There is no separate strict-unsolicited-issuer switch on this path. An unadvertised mismatch is still rejected; leniency does not mean ignoring a returned issuer value. |
| 9207-09 — Optional omissions and stricter multi-AS policy | Outside known support, a client MAY accept missing iss or require it as local policy; multi-AS deployments still need an effective mix-up defense. | **Conditional policy implemented.** In addition to advertised support, overlapping callbacks for different or statically unknown issuers require iss. Loaded metadata must advertise support before such a tenant becomes ready. With no such requirement, a missing issuer can be accepted; disjoint callback locations can supply the separately documented RFC9700 alternative. [Mix-up policy], [tenant metadata validation], [callback processor], [callback tests], [metadata tests]. | The missing-issuer decision is not a blanket opt-out for multiple OPs. Requiring advertisement in the overlapping-callback case is deliberately stricter than the general unsolicited-issuer exception. This can reject an OP that sends iss but fails to advertise it. |
| 9207-10 — Static deployment and configuration granularity | Without metadata, use a deployment-specific expected issuer. The RFC permits local presence policy but does not require a particular configuration API. | **Static identity supported; presence controls are derived rather than fully configurable.** A fully populated static tenant can skip metadata loading. Static metadata starts with the support flag false, while the cross-tenant overlap policy can still require iss. The current path has no independent static support declaration or always-require-iss option. [Discovery metadata model], [tenant metadata validation], [mix-up policy], [authorization configuration]. | Users cannot independently mark a single static OP as supporting the extension through these configuration objects. This is a policy-control limitation, not by itself a mandatory spec defect: the RFC allows omissions when support is not configured. A configured well-known URI may supply the identity without a pinned issuer; its trust/identity boundary is examined below. |

### Input boundaries and distinct authorization-server identities

Spec references: [issuer value](https://www.rfc-editor.org/rfc/rfc9207.html#section-2),
[client validation/policy](https://www.rfc-editor.org/rfc/rfc9207.html#section-2.4), and
[unique issuer identities and security limits](https://www.rfc-editor.org/rfc/rfc9207.html#section-4).

| ID / Requirement or boundary | What RFC 9207 requires or describes | Current behavior and evidence | Qualification or remaining responsibility |
| --- | --- | --- | --- |
| 9207-11 — Unambiguous supplied issuer value | Extract and compare the issuer value; multiple conflicting values cannot establish the expected issuer identity. | **Explicit value-list guards implemented.** More than one decoded iss value, including identical duplicates, is rejected. An explicit empty value (`iss=`) is rejected; a nonempty wrong/whitespace value fails exact comparison. Focused duplicate/empty tests exist. [Callback processor], [Common query parser], [callback tests]. | Common represents a bare query name (`iss` without `=`) as having no values. This callback therefore treats it as missing; it cannot satisfy mandatory issuer presence. This row does not overclaim an exhaustive malformed-input parser audit or promote bare-name handling into a demonstrated mix-up bypass. |
| 9207-12 — Issuer format and explicit transport relaxation | The OP's iss value is an HTTPS URL without query or fragment components. | **Expected-issuer scheme/query/fragment checks implemented.** Configured and discovered issuers go through the issuer URI checks. Received values must equal that expected string. The default policy requires HTTPS; the explicit non-production TLS override also permits HTTP issuer values. [Endpoint URI validation], [tenant validation], [tenant metadata validation], [callback processor], [endpoint configuration]. | The HTTP override is not an RFC9207-compliant issuer profile. These checks do not establish who controls the issuer or that its endpoints belong to the same AS. String/URI shape validation cannot resolve an issuer-identity collision. |
| 9207-13 — Alternative distinct callbacks | Missing-issuer acceptance is local policy; other mix-up countermeasures are possible, with their details outside this RFC. | **RFC9700 distinct-callback integration implemented.** Different callback paths or different absolute origins can avoid the additional multi-AS mandatory-iss policy when support is not advertised. Incoming callback location must still match protected state. Relative/overlapping paths and query-only distinctions are handled conservatively. [Mix-up policy], [callback processor], [endpoint URI validation], [callback tests]. | Advertised iss support remains mandatory even with distinct callbacks. This is the selected alternate defense, not implementation of Hybrid or JARM. Correct OP callback registration and trusted request-origin configuration remain necessary. |
| 9207-14 — Different ASs must not share an accepted issuer | Section 4 imposes a client MUST: distinct authorization servers cannot use the same issuer identifier, including manually configured AS details. | **Independent-OP collision checks implemented.** Configuration rejects tenants that could share an issuer while specifying conflicting or ambiguous Authorization/Token Endpoint sources. The check does not depend on which lazy tenant initializes first. [Provider configuration validation], [tenant runtime registry], [tenant metadata validation], [mix-up policy]. | Multiple registrations/tenants for one genuine OP remain valid. See the 9207-F01 remediation note below; the original unpinned-metadata attack path is no longer accepted. |
| 9207-15 — Bind the issuer to trusted endpoint identity | The issuer identifies the AS and its metadata/endpoints; equality is useful only when the expected identifier belongs to that same independently identified AS. | **Fetched metadata bound to issuer-derived discovery origin.** A configured issuer must still match returned metadata exactly; metadata-only discovery now also rejects returned issuers inconsistent with the fetched well-known URI. [Tenant validation], [metadata loader], [Discovery metadata model], [tenant metadata validation], [endpoint client]. | Arbitrary noncanonical well-known aliases cannot establish this standard binding; a separately designed explicit trust mechanism would be needed to add them. The 9207-F01 remediation note distinguishes these from wholly static/no-fetch configurations. |

### Response transports, alternative protections and protocol roles

Spec references: [client response processing and alternatives](https://www.rfc-editor.org/rfc/rfc9207.html#section-2.4),
[security boundaries](https://www.rfc-editor.org/rfc/rfc9207.html#section-4), and
[registered metadata/parameter names](https://www.rfc-editor.org/rfc/rfc9207.html#section-5).

| ID / Requirement or boundary | What RFC 9207 requires or describes | Current behavior and evidence | Qualification or remaining responsibility |
| --- | --- | --- | --- |
| 9207-16 — Supported response transport | The extension adds issuer identification to authorization responses; it does not mandate that each client implement every OAuth/OIDC response mode. | **GET/query code response supported.** The factory requests response_type=code and the feature registers a GET callback consuming query parameters. There is no form_post callback or browser fragment receiver in this path. [Request factory], [HTTP feature], [authorization configuration]. | These other transports remain unsupported, not silently equivalent to query processing. An OP/client profile requiring them needs additional implementation. Their absence is not a universal RFC9207 violation for this selected code-flow profile. |
| 9207-17 — Issuer consistency with front-channel ID Tokens | In OIDC flows returning an ID Token from the authorization endpoint, response iss and that token's issuer must agree; conflicting multiple issuer indications must be rejected. | **Conditional feature not implemented because the corresponding flow is absent.** No implicit/hybrid front-channel ID Token is requested or consumed. The implemented ID Token validation happens after the code exchange. [Request factory], [callback processor], [HTTP feature], [ID Token validator]. | Do not credit later ID Token validation as the front-channel comparison required by those alternative flows. Adding Hybrid support would require validating all applicable issuer indications before redemption; this inventory makes no Hybrid conformance claim. |
| 9207-18 — JARM as an alternative | A correctly validated issuer inside a JARM authorization-response JWT can supply the mix-up defense without a duplicate outer iss; multiple issuer indications must not conflict. | **JARM response processing unsupported.** The callback expects ordinary state/code/error/iss fields, not a signed response envelope. Existing Request Object support signs authorization requests and uses the client ID as the request JWT issuer; it is not JARM. [Callback processor], [request object processor], [request factory]. | JAR and JARM protect opposite directions. Request signing does not implement this response-JWT alternative, and there is no fallback that treats an unvalidated response JWT as authoritative. JARM itself is a separate non-RFC profile and is not independently reviewed here. |
| 9207-19 — Cryptographic scope of iss | The ordinary issuer parameter is not signed. The RFC's mix-up defense does not require a signed authorization response, but still relies on the expected issuer/endpoints being correctly identified. Single-AS clients need to revisit protection when adding an independent AS. | **Ordinary unsigned response profile, with surrounding checks.** State/cookie/nonce/PKCE, issuer comparisons and the added issuer/metadata binding coexist; multi-AS policy is calculated from configured enabled code-flow tenants. No new OP is enrolled from an incoming iss value. [Request factory], [callback processor], [mix-up policy], [tenant runtime registry]. | Absence of JARM/signatures alone is not a bug. Exact string comparison by itself could not have repaired the pre-fix false expected identity; see the resolved 9207-F01 path. This assessment does not claim protection against arbitrary browser/process/response tampering. |
| 9207-20 — Wire names, OP emission and registration roles | The RFC defines the response iss and Boolean support metadata and updates their registry entries; supporting OPs emit/advertise them consistently. | **Client field consumption implemented; OP publication is outside this module.** The callback consumes `iss` and metadata parsing consumes the exact `authorization_response_iss_parameter_supported` name. The RP does not publish AS metadata or generate the remote OP's authorization responses. [Callback processor], [Discovery metadata model]. | The registry's authorization-request usage also reflects other specifications; it is not a new RFC9207 request negotiation flag to add to every login URL. Request Object iss has a different role. No issuer-publication service or IANA registration machinery needs to be added to this RP. |

### Resolved 9207-F01 — independent OPs could share an accepted issuer

**Remediation status — 2026-09-30: fixed, verified and committed as `f4d178e813`.** The shared metadata loader
checks the actual requested well-known URI against the URL constructed from the returned exact issuer using either OIDC
Discovery or RFC 8414. A configured issuer with a nonmatching selected URI is rejected before GET; metadata-only tenants
reject mismatched issuer claims before becoming ready. These deterministic failures are outside retryable network-I/O
handling. The provider configuration also rejects enabled Authorization Code tenants that might accept the same issuer
while specifying different/ambiguous Authorization or Token Endpoint sources. Distinct registrations, scopes, callbacks,
cookies and approved mTLS aliases at the same genuine OP remain usable; initialization order cannot grant an exception.

Before the fix, the local callback regression with valid returned `iss` made **one** POST of the honest code to the wrong
Token Endpoint and returned 303; metadata-only discovery accepted an unrelated issuer, and colliding static endpoints
built. These three regressions now pass. Controls cover canonical OIDC and OAuth metadata paths, explicit issuer pins,
an actual trusted HTTPS mock OP under default TLS, the dev-only HTTP opt-out, static/no-fetch behavior, shared-OP client
registrations, different callbacks, both lazy initialization orders and concurrent virtual threads. All 1,586 module
tests, 42 synthetic integration tests, Checkstyle, maximum-effort SpotBugs/FindSecBugs and dependency analysis passed.
All 18 real-Keycloak integration tests also passed against the installed snapshot.

Noncanonical well-known aliases are deliberately refused when used for discovery, even if an issuer is pinned: the
standard issuer-origin check cannot verify them. A separate explicit trust design would be needed to add alias support
later; a generic duplicate-issuer/metadata-alias bypass was not introduced. Unused well-known overrides and fully
static configurations do not cause a metadata request. The original analysis below is the pre-fix baseline, not a claim
that the leak remains present. Full implementation detail: the current `rfc9207-f01-implementation.md` review note.

Historical pre-fix analysis follows; statements in this block about missing checks are not the current implementation.

Classification at the baseline: **conditional security/design and MUST-level conformance gap**. [RFC9207 section 4](https://www.rfc-editor.org/rfc/rfc9207.html#section-4)
requires clients to keep issuer identifiers unique across independent authorization servers. The current per-tenant
equality/presence checks do not enforce that invariant. Source tracing establishes the missing check and credential
forwarding path; an end-to-end exploit against an OP was not run.

The clearest path uses a supported metadata-only configuration, not a forged state cookie:

| AS relationship | Trusted client configuration | Returned metadata identity/endpoints |
| --- | --- | --- |
| Honest OP H | Its correct issuer H and an RP client registration. | Issuer H, honest authorization/token endpoints. |
| Separate OP M that is malicious or compromised | M's well-known URI; no pinned issuer. A separate tenant uses the same RP callback. | M falsely claims issuer H, advertises iss support and suitable code/S256/authentication capabilities, and retains its own Token Endpoint. |

The source path is:

1. `validateAuthorizationCode` permits issuer to be absent when well-known-uri is present. Metadata loading uses that URI;
   `validateWellKnownMetadataIssuer` compares only a configured issuer, so the absent pin does not constrain M's claim H.
2. Metadata capability checks can all succeed: M can advertise a valid HTTPS issuer H, the required response/PKCE/auth
   capabilities and `authorization_response_iss_parameter_supported=true`. The tenant runtime publishes M's context by
   tenant ID without comparing its AS identity with H's configured or discovered identity.
3. Starting login through M stores H as the protected transaction's expected issuer. In the ordinary unsigned/unpushed
   authorization-request profile, M can forward the browser request to H, using H's RP client ID and the shared registered
   callback while preserving state, nonce and the S256 challenge. This requires an applicable client/redirect registration
   at H; it is not an attack against an arbitrary unrelated callback.
4. H returns a legitimate code response with iss=H. The RP resolves M's tenant from the original protected state. Saved
   issuer H, current M metadata issuer H and returned issuer H all match. Required iss presence is satisfied as well.
5. The feature then calls M's endpoint client with the honest code, saved callback and PKCE verifier. That client posts to
   M's Token Endpoint. ID Token/nonce validation takes place only after this POST and cannot undo the disclosure.

Evidence: [Tenant validation], [metadata loader], [Discovery metadata model], [tenant metadata validation],
[provider configuration validation], [tenant runtime registry], [request factory], [callback processor], [HTTP feature],
[endpoint client]. The existing missing-issuer/wrong-endpoint route regression uses different expected issuers and no
returned iss; it does not cover this equal-issuer collision. [Route tests].

Impact and limits: this requires a configured independent malicious/compromised OP and the unpinned/conflicting identity
setup above. There is no claimed unauthenticated API for enrolling arbitrary OPs. It is not a default single-honest-OP
attack and does not require PLAIN PKCE: the RP itself discloses the S256 verifier along with the code. A public-client
registration at H is a concrete case in which those disclosed values can enable redemption; confidential-client redemption
additionally depends on H's client-authentication requirements. No universal account-takeover claim is made.

Requirements for a follow-up fix: bind discovered issuers to independently trusted AS identity and reject conflicting
claims across independent OP configurations before granting readiness or sending credentials. Do not make safety depend
on which lazy tenant initializes first. Preserve legitimate multiple tenants/client registrations for the same OP and
explicitly trusted metadata aliases; a blanket duplicate-issuer-string ban would be the wrong fix. Add a regression with
a colliding issuer and valid returned iss that asserts zero requests to the wrong Token Endpoint, plus the legitimate
shared-OP cases. These requirements were implemented in `f4d178e813`; the paragraph records the baseline proposal.

### Existing regression evidence and focused follow-ups

Inspected tests cover encoded issuer acceptance, mismatches, duplicate/empty values, advertised-required omissions,
overlapping/distinct callback policies, same-OP tenants, issuer changes and error-response ordering. Metadata tests cover
advertisement and exact pinned-issuer matching, including case differences. The route test for a missing issuer asserts
zero calls to the wrong Token Endpoint. [Callback tests], [metadata tests], [runtime metadata tests], [route tests].

The issuer-collision regression was subsequently added, retaining genuine shared-OP cases and both lazy-initialization
orders. Further small decoding/equality tests can cover issuer host-case/slash
differences in the callback, literal plus/percent escapes and malformed/duplicate input representation. Those optional test additions are
not independent product defects. Existing tests were inspected, not rerun; no OP/browser exploitation probe was performed.

### Section-to-role cross-check

| RFC area | Coverage in this pass | Qualification |
| --- | --- | --- |
| 1, 1.1 — purpose and terminology | 9207-01, 19; 9207-F01 conditions. | Multiple independent ASs, not simply multiple registrations with one genuine OP. |
| 2 — response iss and issuer format | 9207-01, 05, 11–12. | OP emits the field; RP consumes it and applies expected-issuer/presence policy. |
| 2.1, 2.2 — success/error examples | 9207-03–05. | Encoded issuer parsed in the query flow; issuer checks precede either outcome. |
| 2.3 — provide issuer/advertise support | 9207-02, 06, 10, 15. | Metadata and static identity paths; remote OP publishing is external. |
| 2.4 — client validation/policy | 9207-02–11, 13, 16–18. | Exact comparison and configured support, with conditional alternative-flow rules kept separate. |
| 3 — metadata/default | 9207-06–10. | Boolean/default false, remembered in tenant metadata; static presence controls are limited. |
| 4 — uniqueness and endpoint identity | 9207-14–15; 9207-F01. | Resolved independent-OP binding; legitimate shared-OP tenants are retained. |
| 4 — cryptographic scope/alternatives | 9207-13, 17–19. | Ordinary iss need not be signed; Hybrid/JARM are not implemented alternatives. |
| 5.1, 5.2 — registries | 9207-06, 20. | Correct consumer names, not an issuer-publication service or extra request negotiation parameter. |

### Practical outcome of this RFC pass

- **Covered:** response-issuer extraction, shared form decoding, exact comparison before grant use/error attribution,
  support metadata/defaults, required-omission rejection and the surrounding distinct-callback policy.
- **Policy choices/limits:** unadvertised matching issuers are accepted under the RFC's explicit local-policy allowance;
  static-only configuration has no independent always-require-iss/support toggle. Neither fact is automatically a defect.
- **Unsupported alternatives:** form_post/fragment reception, implicit/hybrid front-channel ID Tokens and JARM response
  JWTs. Their conditional issuer checks must be added with those flows, not credited to later Token Endpoint validation.
- **Resolved finding:** 9207-F01's independent identity-binding/uniqueness gap was fixed in `f4d178e813`. The historical
  analysis above records its attack assumptions and pre-fix code/verifier exposure path, not a current acceptance rule.

The Common query parser/encoding component is already reused; introducing a duplicate decoder or replacing String.equals
with URI-equivalence comparison would not improve this protocol implementation. No separate performance finding was
established by this source review. [Common query parser], [Common URI encoding], [callback processor].

Method: read all substantive local RFC9207 sections and map them to current source, with selected existing tests inspected.
The official RFC Editor publication was checked; no erratum was adopted. This is not an exhaustive errata-status audit,
live OP conformance test or executed exploit. Runtime code, Common and the legacy provider are unchanged. The original
eight-spec inventory and the fifty preceding RFC feature rows, including 7636-F01, are preserved. Detailed JAR coverage
follows in section 4.

## 4. RFC 9101 — JWT-Secured Authorization Request (JAR)

Source: [RFC 9101, The OAuth 2.0 Authorization Framework: JWT-Secured Authorization Request](https://www.rfc-editor.org/rfc/rfc9101.html),
Standards Track, August 2021, matching the supplied `oidc-specs/rfc9101.html`. Assessed: 2026-09-29.
Scope: JAR production and delivery by the OIDC code-flow RP, configured algorithms/keys, request integrity/privacy and
OP/deployment responsibilities. This is not a standalone JWT/JOSE audit. By-value requests, external Request Object URIs
and AS-issued references are distinguished; PAR's complete protocol assessment remains a later pass.
Assessment is complete for this scope: thirty entries, one conditional TLS-profile finding and separate quality notes.
This is not a blanket compliance verdict for every Request Object URI, TLS provider or OP deployment.

### Request Object construction and claims

Spec references: [purpose](https://www.rfc-editor.org/rfc/rfc9101.html#section-1),
[Request Object/URI terminology](https://www.rfc-editor.org/rfc/rfc9101.html#section-2), and
[Request Object requirements](https://www.rfc-editor.org/rfc/rfc9101.html#section-4).

| ID / Requirement or boundary | What RFC 9101 requires or describes | Current behavior and evidence | Qualification or remaining responsibility |
| --- | --- | --- | --- |
| 9101-01 — Produce a secured authorization request | Represent authorization parameters in a JWT Claims Set and sign it, optionally encrypting the signed result. | **Signed and signed/encrypted producer implemented.** The request factory obtains a locally generated Request Object when the mode/key/metadata policy selects it. The processor signs first and optionally passes that signed JWT to encryption. [Request factory], [request object processor], [request object configuration]. | This establishes the producer path, not blanket JAR compliance or default use on every login. Request Object settings do not make the RP an AS-side validator. Selection/downgrade policy and nested protection are assessed separately below. |
| 9101-02 — Protect all operative request parameters | All parameters used to process the authorization request, including extensions, belong in the Request Object except the two container parameters. | **Implemented for the built-in request set.** The factory builds response_type, client_id, redirect_uri, scope, state, nonce and selected prompt/resource/PKCE values before signing. The processor copies these into claims. An existing request test checks the protected fields, including repeated resources and PKCE. [Request factory], [request object processor], [provider tests]. | This is not an arbitrary OIDC-parameter builder: optional controls absent from the login factory are not added merely by selecting JAR. The claim is that the parameters the factory actually uses are protected, not that every possible extension is supported. |
| 9101-03 — JSON types and UTF-8 | Parameter names/string values use JSON strings encoded in UTF-8; numerical values use JSON numbers. | **Implemented emitted types/encoding, with a bounded parameter model.** Current request scalar values are strings; repeated values become lists, and JWT time claims are serialized as numeric epoch seconds. SignedJwt serializes the JSON and encodes it using UTF-8. [Request factory], [request object processor], [JWT serialization], [JWT signing]. | The internal Parameters input is string/list based, not a general typed extension-value API. No currently emitted numeric OIDC request control was found; adding one such as max_age would need explicit numeric handling rather than blindly copying a string. That absent optional control is not by itself a JAR serialization defect. |
| 9101-04 — Do not nest the container parameters | request and request_uri MUST NOT occur inside a Request Object. | **Implemented.** The signing loop excludes both names, and the normal factory's authorization-parameter set contains neither. The signed-object regression checks that they are absent from the payload. [Request object processor], [request factory], [provider tests]. | This exclusion concerns JWT claims. It does not prohibit the outer transport from carrying request or request_uri to deliver/reference the object. Those two outer alternatives have their own rules. |
| 9101-05 — Request issuer and audience | Signed Request Objects SHOULD carry issuer/audience claims; the audience should identify the AS issuer. | **Implemented client-issued profile.** The object issuer is the configured client ID; its audience contains the resolved AS issuer, not the Token Endpoint URL. Client ID also remains an authorization-request claim. Existing tests assert issuer and audience. [Request object processor], [request factory], [provider tests]. | A one-element audience array uses the referenced JWT audience semantics. This request issuer is the client, not an ID Token or RFC9207 response issuer. The AS must bind/validate these values and trust the client's signing key. Using a resolved issuer does not repair the separate identity-source issue recorded in 9207-F01. |

### By-value delivery, references and hosting responsibilities

Spec references: [outer authorization request](https://www.rfc-editor.org/rfc/rfc9101.html#section-5),
[by value](https://www.rfc-editor.org/rfc/rfc9101.html#section-5.1),
[by reference](https://www.rfc-editor.org/rfc/rfc9101.html#section-5.2),
[reference creation/lifetime](https://www.rfc-editor.org/rfc/rfc9101.html#section-5.2.1), and
[AS retrieval](https://www.rfc-editor.org/rfc/rfc9101.html#section-5.2.3).

| ID / Requirement or boundary | What RFC 9101 requires or describes | Current behavior and evidence | Qualification or remaining responsibility |
| --- | --- | --- | --- |
| 9101-06 — By-value request and outer client ID | Send the Request Object in request and include the matching client_id. request and request_uri are mutually exclusive. | **Implemented by-value construction.** With Request Objects selected and PAR not selected, the factory emits the compact JWT as request and copies the same client ID used in its payload. Common UriQueryWriteable performs form-query encoding. No request_uri is added by this branch. [Request factory], [request object processor], [provider tests]. | This is browser authorization-request construction, not a Request Object hosting endpoint. The OP must check the outer/inner client-ID binding rather than trusting an outer ID alone. |
| 9101-07 — Outer duplicates and inner precedence | A client MAY duplicate parameters outside the object, but the AS MUST use protected inner parameters and enforce the client-ID match. | **Compatible duplicates implemented.** The by-value OIDC wrapper includes response_type, client_id and scope from the same parameter set used to create the object. It does not copy a competing redirect_uri, nonce, state or resource outside the object. Existing tests check both views. [Request factory], [provider tests]. | The OIDC compatibility fields are not a JAR violation. Authoritative inner-parameter processing and mismatch rejection are OP duties; the RP cannot certify them by sending matching values. No claim is made that a supporting OP may substitute unsigned outer parameters. |
| 9101-08 — Externally hosted Request Object URI | A client may send an HTTPS reference to an accessible Request Object instead of its value. | **Standalone external-reference mode unsupported.** The configuration has no arbitrary Request Object URI/publishing option, and the HTTP feature does not host generated objects for an OP to fetch. Objects are generated locally for by-value or PAR delivery. [Request object configuration], [request factory], [HTTP feature]. | This is an optional delivery mode, not a requirement to add a hosting service to every RP. A deployment needing third-party-hosted/prebuilt objects would need an explicit integration; ordinary PAR support is not evidence that such a publisher exists. |
| 9101-09 — AS-issued reference delivery | An AS may provide a reference after a back-channel submission; when that AS also consumes the reference its internal content is an implementation detail. Section 5.2 describes AS-issued references as URNs. | **PAR-based route integration present, not a general JAR reference implementation.** The client can send its Request Object to PAR, then redirect with only client_id and the returned request_uri. It does not fetch that handle. The response parser checks a nonblank string and positive expires_in, not a complete URI/URN shape policy. [Request factory], [endpoint client], [PAR response], [code exchange tests]. | General RFC9101 reference constraints are not comprehensively enforced by this adapter. The full PAR receipt/URI contract belongs to the next RFC9126 pass; no blanket by-reference conformance is claimed here. This lack of local URI-shape enforcement is not itself evidence of RP SSRF: the RP forwards the encoded handle to its AS, rather than fetching it. |
| 9101-10 — Reference entropy, size, expiry and fetching | Publicly retrievable references need appropriate entropy and timeout/access control; the Request URI should not exceed 512 ASCII characters. The AS retrieves the object securely. | **Hosting functions delegated/not implemented locally.** No RP-owned object store, capability-URL generator, GET publisher, cleanup scheduler or fetch cache exists on this path. PAR creates one handle per initiation and passes it on without a local reuse cache. [Request factory], [endpoint client], [PAR response], [HTTP feature]. | For AS-issued handles the OP owns storage/entropy/expiry/enforcement. No local 512-character limit or guarantee of remote cleanup is provided. These are not reasons to add an unused hosting subsystem to a by-value RP; they become implementation work if standalone hosted-reference support is introduced. |

### Signing, encryption and algorithm agreement

Spec references: [protected Request Object and algorithm metadata](https://www.rfc-editor.org/rfc/rfc9101.html#section-4),
[required signed form](https://www.rfc-editor.org/rfc/rfc9101.html#section-5),
[algorithm choice](https://www.rfc-editor.org/rfc/rfc9101.html#section-10.1), and
[source authentication](https://www.rfc-editor.org/rfc/rfc9101.html#section-10.2).

| ID / Requirement or boundary | What RFC 9101 requires or describes | Current behavior and evidence | Qualification or remaining responsibility |
| --- | --- | --- | --- |
| 9101-11 — Signed-object algorithm profile | A by-value Authorization Request Object must be JWS-signed or signed and encrypted, using appropriate mutually supported algorithms. | **Asymmetric signing subset implemented.** The adapter permits RS256/RS384/RS512 and ES256/ES384/ES512. Its local key must be an RSA or EC private JWK. Explicit none/blank/padded/unsupported algorithm settings are rejected; the generated object is always signed. [Request object processor], [tenant validation], [client authentication]. | PS algorithms, EdDSA and HMAC Request Object signing are not exposed by this adapter. The RFC does not mandate that this RP implement every JOSE algorithm. Shared-secret client authentication elsewhere is not evidence of HMAC JAR support. Algorithms/registration must agree with the intended OP. |
| 9101-12 — Client signing-key selection/provisioning | The OP must validate signatures with a key associated with the client; signing and verification depend on correctly selected algorithms and keys. | **Local private-key selection and guards implemented.** The key resource must be local classpath/file/content, not URI-backed. Multiple keys require a configured key ID. Selection checks private-key availability, declared-algorithm consistency, signing use/key operations, RSA minimum size and EC algorithm/field-size compatibility. The key algorithm is selected from explicit configuration, declared alg or a compatible default. [Request object processor], [request object configuration], [JOSE key policy]. | The OP's public copy/registration is external; this class is not a client-key publication or registration service. Private signing material is not obtained from the OP's public JWKS. The processor retains the chosen local key; no live private-key-file reload guarantee is implied. |
| 9101-13 — Sign, then encrypt | Applying both protections requires a signed inner JWT and an encrypted outer JWT. Public-key encryption alone is not source authentication. | **Implemented nested JWT.** The processor signs, then passes SignedJwt to EncryptedJwt. That builder encrypts the compact signed token and marks its nested content with cty=JWT. Tests decrypt generated requests and verify the inner signature in both direct and PAR paths. [Request object processor], [JWT encryption], [code exchange tests]. | Encryption is optional and never replaces signing on this path. Nested-JWT content type is not the same as explicit JAR typ; typing is assessed separately. These source/tests establish adapter behavior, not independent cryptographic certification of every primitive/provider. |
| 9101-14 — Recipient key and encryption subset | Encryption must use an appropriate recipient key/algorithm; both parties need compatible protection parameters. | **RSA encryption subset and key eligibility implemented.** Supported key-management methods are RSA-OAEP and RSA-OAEP-256. Content encryption supports A128GCM/A192GCM/A256GCM and A128CBC-HS256/A192CBC-HS384/A256CBC-HS512. If enc is omitted after selecting encryption, the OIDC configuration default is A128CBC-HS256. OP JWKS selection honors a pinned kid or chooses an eligible key, checking RSA size, declared alg, use and key operations; ambiguous no-kid multi-key choices are excluded. [Request object processor], [request object configuration], [JOSE key policy], [Request Object key tests]. | ECDH/direct/symmetric key-management profiles are not available here. The enc default comes from this OIDC configuration contract, not a universal RFC9101 mandate. Correct OP metadata/JWKS trust is still necessary; a local filter cannot prove the recipient's real-world identity or private-key protection. |
| 9101-15 — Match capabilities and registration | The client-selected algorithms need support at both endpoints; client registration and AS algorithm metadata can communicate that agreement. | **Advertised-capability checks implemented, with static/out-of-band boundaries.** If algorithm lists are present, the selected signing/encryption/enc values must be listed. Encryption requires an OP JWKS source. Loaded metadata also gates by-value request support where PAR is not used. Missing optional encryption lists do not automatically reject an otherwise configured choice. [Tenant metadata validation], [Discovery metadata model], [metadata tests]. | These are compatibility checks, not dynamic algorithm negotiation or automatic client registration. Where optional metadata is absent or no fetch occurs, the operator must align request_object_signing_alg/request_object_encryption_alg/request_object_encryption_enc with the OP registration. The RP does not publish those registration values on the user's behalf. |

### Selection, downgrade resistance and receiver responsibilities

Spec references: [receiver validation](https://www.rfc-editor.org/rfc/rfc9101.html#section-6),
[authorization responses/errors](https://www.rfc-editor.org/rfc/rfc9101.html#section-7),
[source authentication/reference replay](https://www.rfc-editor.org/rfc/rfc9101.html#section-10.2), and
[downgrade prevention](https://www.rfc-editor.org/rfc/rfc9101.html#section-10.5).

| ID / Requirement or boundary | What RFC 9101 requires or describes | Current behavior and evidence | Qualification or remaining responsibility |
| --- | --- | --- | --- |
| 9101-16 — Local selection and no failure-triggered weakening | A JAR profile must not silently lose its request protection; signed requests may be used even when the AS does not globally require them. | **Mode selection and failure behavior implemented.** AUTO selects Request Objects when a signing key is configured or loaded metadata requires them. REQUIRED needs a signing key; DISABLED conflicts with configured protection options and with a loaded require_signed_request_object=true. Missing keys/capabilities or signing/encryption failures fail the operation rather than retrying unsigned/unencrypted. [Request object processor], [tenant validation], [tenant metadata validation], [request factory], [metadata tests], [code exchange tests]. | AUTO without a key/known server requirement is ordinary non-JAR login. A fully static tenant may not load metadata, so an unknown OP requirement cannot be inferred. This local control is not the OP's enforcement against a browser replacing the request. |
| 9101-17 — Enforce the protected profile at the OP | require_signed_request_object defaults false. When true in server or applicable client metadata, the OP rejects nonconforming/none requests; otherwise ordinary requests can bypass JAR protections. | **Server flag consumed; client-registration enforcement external.** The metadata model parses the server Boolean/default and runtime validation honors known requirements. Local REQUIRED makes the RP send a signed object, but there is no Dynamic Client Registration operation setting the corresponding client metadata. [Discovery metadata model], [tenant metadata validation], [request object configuration]. | Operators must register/enforce the required profile at the OP, globally or for this client. The local mode is not evidence that the OP rejects an attacker-created unsigned request. This is a real deployment requirement, not an instruction to add an unused registration client or weaken ordinary OAuth handling globally. |
| 9101-18 — AS decryption, signature and parameter binding | The AS decrypts JWE, validates the inner signature with the associated client key/algorithm, respects kid, uses only inner parameters and checks the outer client ID. AS-issued URI services also authenticate/bind the client. | **Producer/authentication cooperation; receiver validation is OP-only.** The RP sends signed or nested objects and applies its configured endpoint authentication on PAR. It does not serve the AS authorization/URI broker endpoint or validate incoming JAR requests for it. [Request object processor], [request factory], [endpoint client], [client authentication]. | An encrypted request alone does not authenticate its sender, and matching fields emitted by the RP do not prove OP enforcement. Public/no-secret endpoint settings must be compatible with the OP's applicable source-authentication/profile rules; no universal assurance follows from a client_id field. |
| 9101-19 — Standard response path and JAR error values | The authorization response remains the OAuth response, with invalid_request_uri, invalid_request_object, request_not_supported and request_uri_not_supported added as error values. | **Generic error handling can consume these values.** Error validation accepts the permitted OAuth character syntax rather than a closed enum; a validated authorization error stops before redemption, while initiation/PAR failures do not trigger weaker retries. [OAuth error fields], [callback processor], [HTTP feature], [request factory], [endpoint client]. | No dedicated JAR-error recovery or user-facing diagnostic catalogue is implemented. Generic messages avoid reflecting OP descriptions/links. The OP must emit the appropriate error; the RP need not mint server validation errors or receive a distinct JAR success response. Focused tests for all four names would improve coverage, not establish a separate missing protocol feature. |
| 9101-20 — Freshness and replay limits | Reference lifetimes should be short and preferably single-use, with sufficient entropy; normal JWT/OAuth security remains relevant. | **Per-initiation claims and local transaction binding implemented.** The producer adds iat, exp from a configurable positive lifetime (default one minute), a fresh UUID jti and the request's fresh state/nonce/PKCE values. There is no cache of reusable Request Object JWTs. [Request object processor], [request object configuration], [tenant validation], [request factory]. | JWT expiry is not the same as Request URI expiry; the OP must enforce received claims and reference replay policy. A generated jti is not an AS replay database. The configured object lifetime has no general maximum; this source review does not certify an arbitrary operator-selected lifetime or global one-time transaction consumption. |

### Cross-JWT separation, transport and disclosure boundaries

Spec references: [TLS requirements](https://www.rfc-editor.org/rfc/rfc9101.html#section-8),
[explicit endpoints](https://www.rfc-editor.org/rfc/rfc9101.html#section-10.3),
[reference attacks](https://www.rfc-editor.org/rfc/rfc9101.html#section-10.4),
[cross-JWT confusion](https://www.rfc-editor.org/rfc/rfc9101.html#section-10.8), and
[request disclosure](https://www.rfc-editor.org/rfc/rfc9101.html#section-11.2.1).

| ID / Requirement or boundary | What RFC 9101 requires or describes | Current behavior and evidence | Qualification or remaining responsibility |
| --- | --- | --- | --- |
| 9101-21 — Distinguish Request Objects from other JWTs | Section 10.8 offers mitigations including avoiding client-ID sub, explicit oauth-authz-req+jwt typing and distinct keys for different purposes. | **One stated mitigation implemented; additional hardening available.** The producer does not generate sub=client_id (no sub is emitted by the current factory) and does not fabricate a derived user principal. Its Request Object signing resource is independently configurable from client assertions. It does not set the specific oauth-authz-req+jwt typ or enforce distinct key material across those configurations. [Request object processor], [request factory], [JWT serialization], [JWT headers], [request object configuration]. | Explicit typing is not an unconditional MUST here, and absent typ alone is not a proven cross-JWT exploit. A new profile can reasonably add it; OP type validation and purpose-separated keys must agree with that profile. cty=JWT on nested encryption is not the same control. |
| 9101-22 — TLS and certificate identities | Relevant HTTP clients use protected TLS and DNS-ID certificate verification; section 8 forbids using CN-ID and SRV-ID/URI-ID for authentication. | **Scoped signed-JAR+PAR check implemented.** The relevant PAR endpoint must use HTTPS. For tenants that can send a signed Request Object through PAR, their OIDC WebClient verifies a matching DNS subjectAltName after the TLS handshake, before sending HTTP data; the normal trust/hostname checks still run. Real Keycloak tests cover matching DNS SAN, wrong DNS SAN and trusted CN-only certificates. [Endpoint URI validation], [OIDC HTTP client factory], [Common TLS sockets], [Keycloak TLS identity tests]. | The strict listener is selected for signed-JAR+PAR-capable tenants, not every WebClient or every OIDC request. It rejects IP-named peers for that profile. This is the 9101-F01 remediation below; it does not assert all TLS providers/deployments are certified. |
| 9101-23 — Explicit intended endpoints/message position | Section 10.3 recommends making intended interaction endpoints and message position tamper-evident, without making all such additions mandatory. | **Partially represented.** redirect_uri is protected; configured resource values are protected and aud identifies the AS issuer. The producer does not add separate authorization_endpoint, token_endpoint, protected_resources or message-position claims. [Request factory], [request object processor]. | resource and aud are not literal implementations of every field discussed in section 10.3. Adding unfamiliar claims without an agreed OP/profile meaning would not create enforcement. This is a recommendation/profile capability limit, not a demonstrated code-exposure bug or a cure for the previously recorded issuer trust-boundary issue. |
| 9101-24 — Reference rewrite, recursion and resource exhaustion | Reference resolvers should constrain destinations/media types, apply timeouts and avoid recursive or huge/slow fetches; source/authentication binding remains important. | **No RP reference fetcher to expose.** The built-in RP does not dereference the returned request_uri or implement the OP's object-fetching endpoint. Its provider-owned HTTP traffic disables redirect following for PAR, but that is a separate client request. [Request factory], [endpoint client], [HTTP feature]. | OP/third-party hosting/fetching defenses are external. The RP's normal WebClient timeout or its JWK cache is not evidence that an external OP's request_uri fetch is bounded. There is no reason to add an unused request resolver just to tick off server-side requirements. |
| 9101-25 — Confidentiality is not provided by a signature | Sensitive request parameters SHOULD be protected with encryption; browser/referrer/history disclosure must be considered. | **Optional encrypted-object path implemented; visibility remains bounded by delivery choice.** JWE conceals the inner signed payload. In direct OIDC by-value delivery, client_id, response_type and scope are still duplicated outside the encrypted object. PAR's browser redirect instead carries client_id and the returned handle. [Request object processor], [request factory], [provider tests], [code exchange tests]. | A signed-only object is readable, and encrypting the inner object does not conceal its outer duplicates. Applications must avoid putting sensitive data in exposed fields or select an appropriate profile/delivery mechanism. No blanket browser-history, referrer, logging or privacy-compliance claim follows from enabling JWE. |

### Privacy, delegation and registered fields

Spec references: [registered JWT claims](https://www.rfc-editor.org/rfc/rfc9101.html#section-9.1),
[server metadata](https://www.rfc-editor.org/rfc/rfc9101.html#section-9.2),
[client metadata](https://www.rfc-editor.org/rfc/rfc9101.html#section-9.3),
[media type](https://www.rfc-editor.org/rfc/rfc9101.html#section-9.4),
[collection limitation](https://www.rfc-editor.org/rfc/rfc9101.html#section-11.1), and
[reference tracking](https://www.rfc-editor.org/rfc/rfc9101.html#section-11.2.2).

| ID / Requirement or boundary | What RFC 9101 requires or describes | Current behavior and evidence | Qualification or remaining responsibility |
| --- | --- | --- | --- |
| 9101-26 — Minimize requested personal data | Clients SHOULD request only data needed for the intended purpose; the privacy guidance is not satisfied merely by signing the request. | **Configurable request minimization, not an automated policy engine.** Login defaults to openid alone and exposes scope/resource choices. JAR wraps those choices; it does not broaden them or inject user-profile claims. [Authorization configuration], [request factory], [request object processor]. | Applications/OPs must choose appropriate permissions and consent behavior. The RP cannot determine a business purpose's necessary data from a scope name, and this assessment is not legal/privacy certification. No jurisdiction-specific policy engine is required inside this provider. |
| 9101-27 — Trusted third-party certification/delegation | The RFC describes an optional trusted-party service that vets requests, returns references and participates in a trust/consent process. | **Dedicated third-party workflow unsupported.** The producer signs locally as the configured client. There is no pre-signed-object import, third-party certification/translation client or separate third-party reference service configuration in this login flow. [Request object configuration], [request object processor], [request factory]. | Pointing an OP endpoint option at some other service does not implement its distinct trust/credential/policy contract. This optional architecture would require an explicit application integration. The OP's consent display and trusted-party signature/identity checks are not RP UI features to add here. |
| 9101-28 — Avoid persistent per-user reference identifiers | Long-lived per-user Request Object URIs enable correlation; single-use/short-lived references are an alternative, with entropy/lifetime requirements for sensitive unencrypted content. | **No RP-managed persistent per-user URI.** Each login builds fresh transaction values/object claims and, when PAR is used, performs a new submission. The RP forwards the returned handle rather than maintaining a per-user reference cache. [Request factory], [request object processor], [endpoint client], [PAR response]. | This does not prove the OP returns unique/unpredictable handles, enforces one use or chooses a short enough lifetime. The response parser's positive expires_in check is not a maximum-lifetime or entropy check. Browser/log retention and remote handle policy remain deployment responsibilities. |
| 9101-29 — Preserve registered JWT claim semantics | iss/sub/aud/exp/nbf/iat/jti are registered for authorization requests to prevent their reinterpretation by extensions. Registration does not make all seven mandatory in every object. | **Emitted subset uses the intended roles.** The producer emits client issuer, AS audience, numeric issued/expiry times and a fresh token ID. It leaves sub and nbf absent. Those names are not repurposed for unrelated application data. [Request object processor], [JWT serialization]. | Omitted sub/nbf are not missing mandatory JAR claims merely because they appear in the registry. Additional deployment profiles may impose more; no such profile is silently claimed by this component. |
| 9101-30 — Media type and metadata registration are distinct layers | The Request Object media type is application/oauth-authz-req+jwt (legacy application/jwt use is noted); require_signed_request_object is registered for both server and client metadata. | **Appropriate transport layers distinguished; no standalone publisher.** Direct login sends a compact JWT parameter, not a JWT HTTP request body. PAR keeps its form-encoded POST body containing request. Nested encryption uses cty=JWT; the dedicated JAR typ is not currently set. Server requirement metadata is consumed; client registration remains external. [Request factory], [endpoint client], [JWT encryption], [Discovery metadata model]. | Do not change a form POST's Content-Type to the Request Object's media type, or treat nested cty as explicit typ. Serving an external Request Object resource with its media type belongs to the unsupported hosting mode. Full Dynamic Client Registration and an IANA registry service are not implied by parsing this metadata. |

### Resolved scoped conformance gap 9101-F01 — CN fallback for signed JAR with PAR

**Remediation status — 2026-10-01: fixed for the reproduced signed-JAR+PAR path and committed as `9a9873498f`.**
When a tenant can send a signed Request Object through PAR, its provider-owned WebClient retains the configured TLS
settings but adds a post-handshake/pre-HTTP DNS-SAN check and disables cross-client connection-cache sharing. A trusted
CN-only certificate now fails before the PAR body (including signed request and client credentials) is sent; a matching
DNS SAN succeeds, and a wrong SAN fails. The existing connection listener still receives its callbacks on successful
connections. The shared WebClient handshake callback was added to make this ordering possible; the legacy OIDC provider
and Common TLS policy were not changed. Real signed-JAR+PAR Keycloak tests exercise all three certificate cases.
Separately, `fdd089914d` requires HTTPS for the PAR endpoint even when the tenant's general TLS opt-out is selected.
This resolution is specific to the path tested; it does not install a global DNS-SAN-only policy for unrelated clients.

The rest of this finding section records the original pre-fix evidence and planned remedy, not current TLS behavior.

[RFC9101 section 8](https://www.rfc-editor.org/rfc/rfc9101.html#section-8) requires DNS-ID verification and excludes CN-ID
for the relevant HTTP clients. The Request Object URI/PAR client path uses the configured WebClient TLS stack rather than
an OIDC/JAR-specific certificate-identity policy. In the assessed standard JDK-backed path, that stack is less restrictive
than this requirement.

Baseline source evidence, inspected on 2026-09-29:

- `OidcWebClientFactory` retains the configured TLS settings. Common's default endpoint identification algorithm is HTTPS;
  `TlsConfigDecorator` places it in SSLParameters, and the TCP connection creates a TLS socket and performs its handshake.
  [OIDC HTTP client factory], [Common TLS configuration], [Common TLS parameters], [TCP client connection], [Common TLS sockets].
- The default TLS manager uses normal JSSE context/trust management; the inspected wrapper has no DNS-SAN-only policy.
  [Common TLS manager], [Common TLS trust wrapper].
- Read-only inspection of the installed **Temurin 25.0.4+7** classes showed HTTPS dispatching through
  `sun.security.ssl.X509TrustManagerImpl` to `sun.security.util.HostnameChecker`. Its DNS match routine checks DNS SANs
  first, but when there is no DNS SAN it reads the subject Common Name and can return success after matching it.
  The evidence is reproducible using `java -version` and `javap -c -p` on those two classes; no TLS handshake experiment
  or live endpoint probe was performed.

Historical 2026-09-30 Keycloak reproduction: a then-uncommitted direct-HTTPS integration test gave OIDC-next explicit
trust in three test Keycloak certificates: DNS:localhost SAN, CN=localhost with **no SAN**, and CN=localhost with a
nonmatching DNS:other.example SAN. All three cases ran over HTTPS (no skips). The matching-SAN control performed a
real Keycloak PAR request and received an AS-issued `request_uri` (HTTP 303 to the browser); the wrong-SAN case was
rejected with HTTP 503, proving hostname verification was enabled. Only the desired CN-only rejection assertion
failed (expected 503, received 303). Existing
Keycloak HTTP PAR integration, test compilation and integration-module style checks passed. This demonstrated
the baseline transport behavior with actual TLS and no trust-all, but this particular test pushed ordinary authorization
parameters rather than a signed JAR; its result alone did not settle the normative scope of RFC 9101 section 8 for
JAR+PAR. At that checkpoint, no production TLS fix had been made, and the new negative test was intentionally red.

The 2026-10-01 follow-up retargeted that isolated Keycloak fixture to **signed JAR+PAR**. A dedicated test client
requires an RS256-signed Request Object and has the matching public JWK registered; OIDC-next uses its private signing
JWK with both Request Object and PAR modes REQUIRED. All three real-Keycloak HTTPS cases ran: matching DNS SAN returned
the expected AS-issued `request_uri` (303), wrong DNS SAN was rejected (503), and trusted CN-only/no-SAN still returned
303 instead of the required failure. The original HTTP Keycloak PAR test and the integration module's style checks
passed. At this pre-fix checkpoint only the deliberate CN-only regression was red; the remediation above now rejects
this server certificate before signed-JAR request bytes are sent.

The affected case is a DNS-named HTTPS endpoint with an otherwise trusted/valid certificate that lacks a DNS SAN but has
a matching CN. A certificate with a conflicting DNS SAN is rejected before this fallback; this finding does not assert
otherwise. It also does not bypass chain trust or demonstrate a man-in-the-middle attack. The gap is the protocol's
stricter certificate-identity acceptance rule, conditional on the deployed TLS provider/certificate profile.

The subsequently implemented remedy enforces a DNS-SAN identity policy for the signed-JAR+PAR client without disabling
ordinary certificate or hostname validation. Correct DNS-SAN certificates alone would not have changed what a pre-fix
client accepted. The shared WebClient callback change was separately authorized; **Common TLS and the legacy provider
remain untouched**, as requested.

### Separate code-quality and reuse observations

These are not additional security or RFC-conformance findings and do not authorize implementation changes.

- **Blueprint implementation constant — Rule 8.2.** `DEFAULT_CONTENT_ENCRYPTION_ALGORITHM` is declared in
  OidcRequestObjectConfigBlueprint and inherited by the public generated configuration interface. The current project
  [Rule 8.2](https://github.com/helidon-io/helidon/blob/main/DEV-GUIDELINES.md#rule-8-2) keeps such implementation details out
  of Blueprints. The existing package-private OidcRequestObjectConfigSupport can hold the shared constant; no new public
  API or utility class is needed. This placement change need not alter the correct enc default. [Request object configuration],
  [Request Object configuration support].
- **Member ordering — Rule 2.1.** In OidcRequestObjectProcessor, package-private static key-selection methods appear after
  instance processing/private methods. This differs from the permanent [Rule 2.1 member order](https://github.com/helidon-io/helidon/blob/main/DEV-GUIDELINES.md#rule-2-1).
  It is a mechanical style issue, not a behavior/security change. [Request object processor].
- **Repeated initialization key resolution — optimization opportunity.** With advertised signing-algorithm metadata, validation
  calls signingAlgorithm(config), which resolves/parses the private JWK. Creating the runtime processor resolves it again.
  Reusing the selected key/processor within that initialization could avoid duplicate work without a public API or global
  secret cache. This occurs during tenant initialization (which may be lazy), not every signed request; no benchmark was run.
  [Tenant metadata validation], [request object processor], [tenant context].

Existing reusable pieces already cover the main machinery: Common Parameters/UriQueryWriteable/ResourceConfig,
Helidon SignedJwt/EncryptedJwt/JWK support, and the module's key policy and JWK manager. Preserve that reuse when addressing
the focused findings. [Request factory], [request object processor].

### Section-to-role cross-check

| RFC area | Coverage in this pass | Qualification |
| --- | --- | --- |
| 1–3 — purpose/terminology | 9101-01, 06, 08–10, 27. | RP producer, external publisher, trusted third party and AS-issued reference are different roles. |
| 4 — Request Object | 9101-01–05, 11–15, 29–30. | Current parameter set, typed JWT claims, signing/encryption and agreed algorithms; not every extension/profile. |
| 5, 5.1 — authorization request/by value | 9101-06–07, 11, 16. | Matching client ID, exclusive container and permitted OIDC outer duplicates. |
| 5.2–5.2.3 — by reference | 9101-08–10, 24, 27–28. | No external URI publisher/fetcher; PAR adapter is not blanket standalone-reference support. |
| 6.1–6.3 — receiver validation | 9101-13, 18. | OP decrypts/verifies/binds client and assembles protected parameters; RP supplies compatible objects. |
| 7 — responses/errors | 9101-19. | Existing OAuth response path accepts the additional error names; no distinct success response. |
| 8 — TLS | 9101-22; 9101-F01. | Resolved for signed-JAR+PAR-capable tenants with pre-request DNS-SAN validation; unrelated clients retain their own TLS profiles. |
| 9.1 — registered claims | 9101-05, 20–21, 29. | Preserve meanings; not all registered claims are mandatory. |
| 9.2–9.4.1 — metadata/media type | 9101-15, 17, 30. | Server metadata consumed, client registration external, MIME/typ/cty/form transport kept distinct. |
| 10.1 — algorithms | 9101-11–15. | Concrete supported subset/key guards; no unsupported-algorithm fallback or broad cryptographic certification. |
| 10.2 — source authentication | 9101-12–13, 18, 20, 27–28. | Signature/client/reference validation at the OP or trusted broker; encryption alone is insufficient. |
| 10.3 — explicit endpoints | 9101-23. | Partial recommendation coverage, not invented mandatory nonstandard request fields. |
| 10.4–10.4.2 — reference attacks | 9101-08–10, 24. | Destination/media-type/timeout/recursive-fetch controls belong to the actual resolver. |
| 10.5 — downgrade | 9101-16–17. | Local outgoing requirements do not enforce OP rejection of unsigned replacement requests. |
| 10.6 — current TLS guidance | 9101-22; 9101-F01. | No obsolete TLS-version guarantee or provider-independent certificate-policy certification. |
| 10.7 — mismatched parameters | 9101-02, 04, 06–07, 18. | RP constructs consistent values; OP must enforce protected-inner precedence. |
| 10.8 — cross-JWT confusion | 9101-21. | No client-ID sub; explicit typ and enforced key separation are additional hardening options. |
| 11, 11.1 — collection/delegation | 9101-26–27. | Application purpose/consent/trusted-party service, not automatic business/privacy certification. |
| 11.2.1–11.2.2 — disclosure/tracking | 9101-10, 25, 28. | JWE inner privacy and fresh inputs do not prove outer-field secrecy or remote handle policy. |

### Practical outcome and validation limits

- **Implemented producer:** signed by-value OIDC requests, optional sign-then-encrypt, matching outer fields, key/algorithm
  guards, metadata-aware mode selection, no failure-triggered weakening and composition with PAR.
- **Unsupported/partial features:** external/prebuilt/third-party-hosted Request Objects, general reference hosting and
  resolution, third-party request certification and broader signing/encryption algorithm profiles. These are optional or
  separate roles, not reasons to duplicate an OP inside this RP.
- **Deployment obligations:** OP client-key registration and downgrade/replay enforcement, trustworthy metadata/keys,
  suitable TLS identities and reference lifetime/entropy. Local REQUIRED and positive expires_in do not prove those rules.
- **Resolved scoped finding:** 9101-F01's demonstrated signed-JAR+PAR CN-only acceptance now fails before HTTP/request
  credentials are sent (`9a9873498f`). The baseline did not claim trust bypass, mismatched-SAN acceptance or an executed
  impersonation; the quality notes remain separate from this finding.
- **Useful optional hardening:** explicit JAR typ with an agreed OP profile, purpose-specific signing keys and focused
  error/type/privacy regressions. None is presented as a newly proven exploit solely because a test or optional header is absent.

Existing tests cover signed field placement, PAR composition, encrypted-object processing (including independent
Nimbus decryption/signature verification), key eligibility, metadata conflicts, failure boundaries and the added
signed-JAR+PAR certificate controls. Tests for all four JAR errors and untyped/typed/sub behavior would
make the intended profile clearer. Those coverage opportunities are not additional protocol defects.

Method: read the supplied RFC's substantive sections 1–11, current implementation and selected existing test bodies; checked
the official edition and current project guidelines. Inspected the installed JDK version/bytecode read-only for the TLS
identity question. No tests, TLS handshakes, OP interoperability/attack probes or benchmarks were run, and no erratum was
adopted. No runtime code, Common or legacy provider was changed. The original eight-spec inventory and the seventy earlier
RFC feature rows/findings are preserved. Detailed PAR coverage follows in section 5.

## 5. RFC 9126 — Pushed Authorization Requests (PAR)

Source: [RFC 9126, OAuth 2.0 Pushed Authorization Requests](https://www.rfc-editor.org/rfc/rfc9126.html),
Standards Track, September 2021, matching the supplied `oidc-specs/rfc9126.html`. Assessed: 2026-09-29.
Scope: PAR as the back-channel leg of OIDC-next's authorization-code login, including authentication, optional JAR
composition, reference handling, policy and OP responsibilities. This is not a new general OAuth grant/server audit.
Assessment is complete for this scope: 25 entries. The success-response interoperability gap recorded below was fixed
as 9126-F01; it was not an authentication-bypass finding. Separate quality notes are not additional protocol defects.

### Back-channel request and transport

Spec references: [purpose and example](https://www.rfc-editor.org/rfc/rfc9126.html#section-1),
[PAR endpoint](https://www.rfc-editor.org/rfc/rfc9126.html#section-2), and
[request construction](https://www.rfc-editor.org/rfc/rfc9126.html#section-2.1).

| ID / Requirement or boundary | What RFC 9126 requires or describes | Current behavior and evidence | Qualification or remaining responsibility |
| --- | --- | --- | --- |
| 9126-01 — Push before browser authorization | Submit the authorization payload directly to the AS and use the returned reference in the subsequent browser request. | **Implemented conditional PAR branch.** Login builds its transaction and authorization parameters, calls the endpoint client when PAR is selected, and constructs the browser authorization URI only after a successful result. [Request factory], [endpoint client]. | PAR is a back-channel request, not a browser form POST to the authorization endpoint. The RP does not host the PAR endpoint or obtain user consent at the push step. Mode selection and required-policy behavior are assessed below. |
| 9126-02 — POST/form encoding with UTF-8 | Send an HTTP POST entity using application/x-www-form-urlencoded with UTF-8 encoding. | **Implemented through existing form media support.** The client sets the form media type and submits Common Parameters. The standard FormParams writer defaults to UTF-8 and URL-encodes parameter names/values. A focused test asserts POST, media type and the complete form. [Endpoint client], [form media support], [code exchange tests]. | This credits the normal configured writer, not arbitrary user replacement media services. No new hand-written encoder is needed. A Request Object, when used, is a parameter in this form rather than a replacement JSON/JWT HTTP body. |
| 9126-03 — OIDC and extension parameters, including client ID | Push the authorization parameters relevant to the chosen flow, including client_id; applicable extensions such as OIDC, PKCE and resource indicators are allowed. | **Implemented for the supported login parameter set.** The factory supplies code response type, client ID, callback, scopes, state and nonce, plus selected prompts/resources/PKCE. The client copies all values, preserving repeated resource parameters. Direct form tests cover those values. [Request factory], [endpoint client], [code exchange tests]. | This is not support for every optional authorization extension. Client-ID placement in the JAR form has the separate section-3 rules, assessed later; the ordinary non-JAR form includes it even when Basic authentication is in the header. |
| 9126-04 — Do not push request_uri or token-grant data | request_uri MUST NOT be supplied to PAR. Token Endpoint fields unrelated to client authentication have no meaning in a pushed authorization request. | **Implemented request separation.** The normal input contains no request_uri; the endpoint method also explicitly rejects that name. It copies authorization parameters and then adds only the selected client-authentication material, not grant_type/code/refresh_token fields from token-request methods. [Request factory], [endpoint client], [client authentication]. | This prevents a local nested-reference input. It does not implement the OP's own rejection/validation rules. Authentication parameters are separate from the authorization data stored by the AS. |
| 9126-05 — HTTPS and credential forwarding boundary | The PAR endpoint URL MUST use HTTPS, and direct client credentials need the protected Token Endpoint-style transport. | **PAR HTTPS enforced regardless of the general TLS opt-out.** Configured/discovered selected PAR endpoints are URI-validated; the endpoint client also refuses to POST to an HTTP PAR URL. Redirect following stays disabled. [Endpoint configuration], [endpoint URI validation], [tenant validation], [tenant metadata validation], [endpoint client]. | `endpoints.tls-required=false` cannot relax PAR's HTTPS requirement (`fdd089914d`). A scheme check does not certify arbitrary TLS/trust/proxy settings; the separately resolved signed-JAR+PAR DNS-SAN case is documented in 9101-F01. |

### Client authentication and Request Object composition

Spec references: [authentication and assertion audience](https://www.rfc-editor.org/rfc/rfc9126.html#section-2),
[ordinary request fields](https://www.rfc-editor.org/rfc/rfc9126.html#section-2.1),
[required signed requests](https://www.rfc-editor.org/rfc/rfc9126.html#section-2.3), and
[the request parameter](https://www.rfc-editor.org/rfc/rfc9126.html#section-3).

| ID / Requirement or boundary | What RFC 9126 requires or describes | Current behavior and evidence | Qualification or remaining responsibility |
| --- | --- | --- | --- |
| 9126-06 — Reuse Token Endpoint client-authentication rules | The registered Token Endpoint authentication method and advertised supported-method set also govern direct PAR requests. | **Shared authentication implementation used.** PAR uses the tenant's selected Basic, secret-post, secret-JWT, private-key-JWT, mTLS or NONE method. Credential material is added after authorization-data assembly. For plain forms, secret-post/mTLS/NONE avoid adding another client_id when one is already present. [Endpoint client], [client authentication], [client authentication validation], [code exchange tests]. | There is no need for a divergent PAR-only credential API to satisfy this RFC. Registration, keys/certificates and server method support must agree. This pass assesses PAR integration, not every requirement of the later JWT-assertion/mTLS RFC passes. |
| 9126-07 — JWT client-assertion audience | The AS issuer identifier SHOULD be the audience; the AS MUST also accept its Token Endpoint or PAR endpoint URL as identifying audiences. | **Recommended audience implemented.** PAR supplies the resolved issuer URI to the shared assertion producer; if no issuer is available to that internal client path, it uses the selected PAR endpoint. The normal OIDC flow requires a resolved issuer. A focused private-key-JWT PAR test checks the issuer audience and signed client identity. [Client authentication], [endpoint client], [code exchange tests]. | Accepting the three audience alternatives is an AS requirement, not a need for the RP to send three audiences or retry different values. A client assertion authenticates the request sender; it is distinct from the JAR Request Object even when both are JWTs. |
| 9126-08 — Public clients and mTLS integration | Authentication follows the existing OAuth method rules; public identification is not equivalent to possession of client credentials. Applicable mTLS endpoint selection comes from its companion protocol. | **Configured profiles distinguished.** NONE identifies the client without inventing a secret and the public code-flow guard requires S256 PKCE. mTLS methods add client_id as needed, use configured TLS credentials and prefer an advertised PAR alias over the ordinary/static endpoint. Existing tests exercise alias preference and client ID. [Client authentication], [tenant validation], [endpoint client], [code exchange tests]. | This does not make public clients eligible for the authenticated-client redirect relaxation or prove certificate-bound token support. Neither the mere client_id field nor a parsed metadata entry certifies that the OP actually authenticates/enforces the selected profile. |
| 9126-09 — JAR form layout and credential separation | When using request, authorization parameters MUST be JWT claims; outside it, only parameters needed by the authentication method belong in the form. | **Implemented special composition.** The full authorization set is signed/optionally encrypted first. The PAR wrapper then retains only request; authentication adds its method-specific fields separately. Basic can leave a request-only body because its credentials are in the header. Body-based methods add the needed credential/identification fields. Tests verify the Basic/JAR form has no duplicated scope/state/nonce and preserves the protected claims. [Request factory], [request object processor], [client authentication], [endpoint client], [code exchange tests]. | The ordinary form's unconditional client_id placement must not be mechanically applied to every JAR/authentication combination. The object still carries the authorization client_id, and the AS must compare it with an authenticated client where applicable. Credential parameters must not be mistaken for authorization claims to store behind the reference. |
| 9126-10 — Optional JAR and required signed profiles | PAR may accept Request Objects; JAR processing rules apply. If signed objects are required by server/client policy, the OP rejects other requests with invalid_request. | **Local JAR selection/failure controls implemented.** Signing/encryption are supported over PAR. Known require_signed_request_object and local REQUIRED policies demand a usable signing key; failures do not silently switch to an unsigned push. The by-value front-channel request support flag is not incorrectly required for a JAR-through-PAR request. [Request object processor], [tenant metadata validation], [request factory], [code exchange tests], [metadata tests]. | PAR support alone does not prove an OP implements optional JAR processing. Key/algorithm agreement and OP/client-registration enforcement remain necessary. The RP's selected mode does not enforce the OP's rejection of requests constructed by others. Earlier JAR limitations/findings are not duplicated as new PAR findings here. |

### Success response, reference value and browser use

Spec references: [successful response](https://www.rfc-editor.org/rfc/rfc9126.html#section-2.2) and
[authorization request/reference use](https://www.rfc-editor.org/rfc/rfc9126.html#section-4).

| ID / Requirement or boundary | What RFC 9126 requires or describes | Current behavior and evidence | Qualification or remaining responsibility |
| --- | --- | --- | --- |
| 9126-11 — Recognize a successful 201 JSON response | A successful PAR result uses HTTP status code 201 with an application/json object containing request_uri and expires_in. | **Implemented, including custom/absent reason phrases.** The endpoint now compares the numeric status with Status.CREATED_201_CODE, then checks JSON media type and parses the required fields. Raw HTTP/1.1 loopback tests cover both alternative reason phrases; existing tests cover ordinary success and missing lifetime. [Endpoint client], [HTTP status values], [HTTP/1 status parser], [HTTP/1 response], [PAR response], [code exchange tests]. | A PAR-shaped body under non-201 status is not accepted as success (a 202 regression confirms this); OAuth error handling remains separate. See resolved 9126-F01. |
| 9126-12 — Preserve the AS's reference format | The AS chooses the request_uri format; the registered urn:ietf:params:oauth:request_uri: form is optional. The URI refers to AS-held data and need not expose that data to other parties. | **Opaque forwarding implemented.** The parser requires a nonblank JSON string and preserves it. The client neither decodes its internal structure nor fetches it, and does not require the example URN prefix or a hard-coded 512-character limit. [PAR response], [request factory], [endpoint client]. | The generic JAR by-reference constraints discussed previously must not be turned into an unwritten PAR prefix restriction. The parser is not a URI-syntax/entropy validator; the AS must return an appropriate secure reference. Absence of a local URI fetcher is correct, not a missing feature or evidence of SSRF. |
| 9126-13 — Parse the reference lifetime | expires_in is a JSON number representing a positive integer lifetime in seconds. The AS chooses it; 5–600 seconds is illustrative, not a mandatory range. | **Positive integral parsing implemented.** The parser uses the numeric JSON accessor and exact long conversion, rejecting absent/wrong-type, nonintegral, nonpositive or unrepresentable values. A missing-field regression exists. [PAR response], [code exchange tests]. | Values must fit the implementation's signed-long representation; no artificial 5/600 bound is imposed. The value is parsed but not used for a local expiry timer—the returned reference is used immediately, not cached for delayed reuse. The OP must reject an expired reference. |
| 9126-14 — Browser request carries the reference and matching client ID | Use the returned request_uri in the subsequent authorization request, identifying the client that lodged it. | **Implemented with form-query encoding.** The factory adds client_id from the same tenant and the unchanged returned handle. It does not copy credentials, the full payload or a request JWT into the PAR browser URL. Common UriQueryWriteable encodes reserved characters and preserves the endpoint's existing query. A regression checks plus/percent/ampersand handling without parameter injection. [Request factory], [code exchange tests]. | This is reduced browser exposure, not a claim that the handle/client ID are confidential. A request URI containing punctuation is not another browser parameter or an instruction to redirect to that URI. OP client binding is still a separate check. |
| 9126-15 — One use by the client; expiry/replay at the OP | The client MUST use a request_uri only once. The AS SHOULD enforce one-time use, MAY tolerate user-agent reloads, and MUST reject expired references. | **Fresh submission per initiation; no RP handle reuse cache.** Each initiation creates a new transaction, performs a new selected PAR call and constructs one authorization request from its result. The handle is not persisted for another login. [Request factory], [PAR response]. | This is not a global replay ledger or proof that the OP returns fresh handles. Browser reload behavior and expiration/replay enforcement belong to the OP. The client has no automatic refresh/retry of an expired handle; initiating a new login creates a new push. A local lack of an expiry scheduler is not itself a protocol defect for this immediate-use flow. |

### Error handling, metadata, required policy and redirect management

Spec references: [errors](https://www.rfc-editor.org/rfc/rfc9126.html#section-2.3),
[redirect management](https://www.rfc-editor.org/rfc/rfc9126.html#section-2.4),
[required-PAR enforcement](https://www.rfc-editor.org/rfc/rfc9126.html#section-4),
[AS metadata](https://www.rfc-editor.org/rfc/rfc9126.html#section-5), and
[client metadata](https://www.rfc-editor.org/rfc/rfc9126.html#section-6).

| ID / Requirement or boundary | What RFC 9126 requires or describes | Current behavior and evidence | Qualification or remaining responsibility |
| --- | --- | --- | --- |
| 9126-16 — Errors, HTTP failures and recovery | Use Token Endpoint-style error responses with relevant authorization/extension error codes; 405, 413 and 429 may also be used. Initial PAR processing does not involve user interaction. | **Failure handling implemented, limited diagnostic detail.** Valid JSON error fields are parsed without a closed error-code enum; malformed/non-JSON replies become failures. A failed push stops request creation and produces the generic 503 login-unavailable response, without a weaker authorization retry. A focused invalid_request test exists. [Endpoint client], [OAuth error response], [PAR result], [request factory], [authentication orchestrator], [code exchange tests]. | The result does not retain the HTTP status or Retry-After and provides no automatic backoff, payload resizing or recovery. Those would be optional operational improvements, not missing RFC9126 client MUSTs. The OP must avoid interaction-dependent errors at this stage; the RP does not manufacture consent success from an error. Existing tests do not establish a 405/413/429 matrix. |
| 9126-17 — Advertise the endpoint and default the requirement to false | pushed_authorization_request_endpoint signals PAR availability; require_pushed_authorization_requests is Boolean and defaults to false. PAR handles remain usable regardless of request_uri_parameter_supported or require_request_uri_registration. | **Relevant metadata consumed.** The model reads the endpoint and Boolean with the specified default, retains a loaded true requirement during merge, and supports an explicitly configured endpoint. PAR selection is not gated by the two generic reference-support/registration flags. [Discovery metadata model], [tenant metadata validation], [request factory], [metadata tests]. | This applies to metadata actually loaded. An absent requirement does not mean PAR is unavailable or forbidden. The reference-registration exemption concerns request_uri handles, not an exemption from the distinct redirect_uri rules. The RP does not publish AS metadata. |
| 9126-18 — Local modes and no silent fallback | An OP can require PAR, and a client can choose PAR whenever the endpoint is advertised; the RFC does not prescribe a local mode API or mandatory discovery fetch on every login. | **AUTO, REQUIRED and DISABLED implemented.** AUTO is the default and selects a known endpoint or known requirement. REQUIRED demands a usable endpoint; loaded require_pushed_authorization_requests=true conflicts with DISABLED and fails tenant validation. Once a push is selected, its failure does not retry as a front-channel payload. [Authorization configuration], [PAR modes], [tenant metadata validation], [request factory], [metadata tests]. | With otherwise complete static settings, AUTO does not fetch well-known metadata solely to discover optional PAR; an existing test asserts that behavior. Operators needing a local guarantee should select REQUIRED and supply or discover its endpoint. AUTO proceeding normally when no PAR capability/requirement is known is not the same as downgrading after a failed push. |
| 9126-19 — Global/client PAR-only policy and registration | An AS may require PAR globally or for an individual client. Client metadata require_pushed_authorization_requests is Boolean, defaults to false, and can be managed without Dynamic Client Registration. | **Local sender policy, not remote registration.** The RP consumes the global requirement when loaded and offers local REQUIRED for its own initiations. That setting does not send a client-registration request or configure the OP's per-client policy. [Authorization configuration], [tenant metadata validation], [request factory], [Discovery metadata model]. | The OP must enforce its global/registered-client policy and reject non-PAR attempts; a client setting alone cannot prevent requests constructed elsewhere. Configure the corresponding OP policy through its supported administration/registration process. No Dynamic Client Registration service is required to use PAR, and no such new workflow is implied by this feature. |
| 9126-20 — Optional relaxation of registered redirect matching | The AS MAY accept previously unregistered redirect_uri values from clients with established authentication credentials and MAY restrict that freedom. It MUST NOT grant this facility to unauthenticated clients. | **Compatible with OP-controlled relaxation; no dedicated URI-minting facility.** PAR uses the same configured callback as ordinary login. An absolute URI is preserved; a configured local path is resolved against the request origin. The selected client-authentication method is then applied to the push. [Authorization configuration], [request factory], [client authentication], [tenant validation]. | This does not request or grant a registration bypass, and NONE/client_id alone does not authenticate a public client. Per-transaction/per-OP dynamic callback generation and third-party client-permission administration are not supplied by this flow. When an OP relaxes registration checks, deployments must still control the external origin used for relative callbacks; an explicitly configured absolute callback avoids that origin derivation. No reachable Host-header exploit is established by this observation. |

### Server validation, reference security, privacy and registered fields

Spec references: [initial validation](https://www.rfc-editor.org/rfc/rfc9126.html#section-2.1),
[reference binding/lifetime](https://www.rfc-editor.org/rfc/rfc9126.html#section-2.2),
[authorization-stage validation](https://www.rfc-editor.org/rfc/rfc9126.html#section-4),
[security considerations](https://www.rfc-editor.org/rfc/rfc9126.html#section-7),
[request-URI swapping](https://www.rfc-editor.org/rfc/rfc9126.html#section-7.5),
[privacy](https://www.rfc-editor.org/rfc/rfc9126.html#section-8), and
[registrations](https://www.rfc-editor.org/rfc/rfc9126.html#section-9).

| ID / Requirement or boundary | What RFC 9126 requires or describes | Current behavior and evidence | Qualification or remaining responsibility |
| --- | --- | --- | --- |
| 9126-21 — Validation at push and authorization time | The AS authenticates the client and validates the request. Checks it cannot perform at push time MAY be deferred but MUST be performed later. Previously performed checks may be omitted later only if the request and relevant policy have not changed. | **Compatible client behavior; validation service is OP-side.** The RP sends its configured flow parameters and waits for successful acceptance before constructing the browser request. It does not treat push acceptance as login, consent or an authorization response. The normal callback, token exchange and ID Token checks still run. [Request factory], [endpoint client], [callback processor], [HTTP feature], [ID Token validator]. | Scope/redirect/client-policy checks, JAR verification and detecting policy changes between the two requests belong to the OP. PAR does not authorize this RP to infer user consent from a successful push or skip later OIDC validation. No AS-policy checker is missing from the RP implementation. |
| 9126-22 — Handle entropy, client binding, expiration and replay | The AS must generate an unpredictable reference and bind it to the pushing client, reject expired references, and should enforce one-time use subject to the reload allowance. New redirect URIs require authenticated clients. | **RP reference use is compatible; issuer controls are external.** Helidon forwards the received handle with the same client ID, performs a new push for each initiation and does not act as a reference resolver or issuer. [Request factory], [PAR response], [endpoint client]. | Client-side transaction randomness is not evidence of AS handle entropy. A positive expires_in is not proof of server expiration/replay enforcement or client binding. The OP owns its reference storage, acceptance rules and replay ledger; adding such a server inside this RP would not secure the actual OP's handles. |
| 9126-23 — Defend against request-URI swapping | Clients SHOULD bind the pushed transaction using PKCE, unique state or OIDC nonce. | **Existing transaction protections retained.** The factory generates fresh random state/nonce and, by default, an S256 challenge; those fields remain in the pushed form or protected Request Object. The cookie-backed callback matches state/tenant/expected issuer/callback before redemption. The saved verifier is redeemed, and the ID Token nonce must match before UserInfo/session creation. [Request factory], [authorization configuration], [cookie state handler], [callback processor], [HTTP feature], [ID Token validator]. | Confidential-client compatibility options can disable/change PKCE; state and nonce are still generated. This PAR integration does not close or negate the separately recorded PKCE/mix-up findings or certify arbitrary OP behavior. PAR alone must not replace callback and token validation. |
| 9126-24 — Reduce browser exposure, with explicit privacy limits | Sending authorization data in the protected back-channel body instead of the browser URL can reduce inadvertent disclosure; PAR is not a complete OAuth privacy framework. | **Mechanism implemented.** The browser URL carries client_id and request_uri, while scopes, state, nonce, PKCE challenge and any Request Object are sent in the direct form. Optional JAR encryption is also composable. [Request factory], [endpoint client], [request object processor], [code exchange tests]. | The client ID/reference and later authorization response still traverse the browser. TLS, OP retention/access control, application logging and user-consent/data-minimization policy remain necessary. The RP's reduced front-channel payload does not certify proxy/OP logs or make PAR a substitute for transport security. |
| 9126-25 — Registered names and optional reference namespace | The RFC registers two AS metadata names, the per-client requirement name, and the urn:ietf:params:oauth:request_uri: sub-namespace. | **Names consumed in the appropriate role.** The metadata reader uses pushed_authorization_request_endpoint and require_pushed_authorization_requests; success processing uses request_uri/expires_in. It preserves AS references without generating or requiring the registered URN prefix. [Discovery metadata model], [PAR response], [request factory]. | Registering names does not require the RP to become a metadata publisher, Dynamic Client Registration service or URN allocator. The per-client requirement is an OP registration/administration concern, distinct from Helidon's local mode. An AS may choose another valid reference format. |

### Resolved interoperability gap 9126-F01 — valid 201 rejected for its reason phrase

[RFC9126 section 2.2](https://www.rfc-editor.org/rfc/rfc9126.html#section-2.2) requires status code 201 for a successful
push. HTTP/1.1 permits a different or absent reason phrase; clients should not use that text to determine the response's
meaning. [HTTP/1.1 status-line rules](https://www.rfc-editor.org/rfc/rfc9112.html#section-4). This HTTP reference is used
only to interpret PAR's status requirement, not as a separate HTTP feature review.

Before the fix, the check was `response.status() == Status.CREATED_201`. The failure trace was:

1. Http1StatusParser passes the numeric code and received phrase to `Status.create(code, phrase)`.
2. Status returns the canonical 201 object only for the known phrase (case-insensitively) or a null phrase. A different
   phrase, including the parser's empty string for an omitted phrase, produces another Status instance with code 201.
3. The HTTP/1 response retained that instance. The PAR client's identity comparison failed, so it read an otherwise valid
   success JSON object as an OAuth error body. With no error field, that parse failed and returned a PAR failure.
4. Request creation threw rather than producing the authorization redirect; the authentication orchestrator returned the
   generic authentication-unavailable result (503).

Evidence: [HTTP status values], [HTTP/1 status parser], [HTTP/1 call chain], [HTTP/1 response], [endpoint client],
[OAuth error response], [request factory], [authentication orchestrator], [authentication responses]. Existing PAR
success tests use the ordinary status representation, and the parser's own tests check custom reason text against the
numeric code. [Code exchange tests], [HTTP/1 status tests].

Before the fix, loopback HTTP/1.1 responses starting with `201 Request Stored` or `201 ` and containing a valid PAR
success body both reproduced the failure. The fix compares `response.status().code()` with `Status.CREATED_201_CODE`,
preserving existing media-type, `request_uri` and `expires_in` checks and the non-201 OAuth error path. Both cases now
pass; the canonical 201 case and a 202 containing a PAR-shaped body are also covered. This was a confirmed login
interoperability/availability defect, not a credential leak, authentication bypass or live-tested OP failure. No Common
status/parser code, public API or legacy provider changed.

### Separate usability, test and reuse observations

These are optional improvements, not additional proven security or RFC-conformance defects.

- **Operational error detail.** The internal PAR result loses HTTP status and Retry-After; the external login failure is
  deliberately generic, and debug logging records a fixed reason/exception type rather than the raw OP error description.
  Retaining safe status/retry metadata internally could distinguish throttling, oversized requests and invalid requests
  without exposing credentials or Request Objects. It does not require automatic retries or a public API.
  [PAR result], [endpoint client], [authentication orchestrator].
- **Repeated selection policy.** The request factory and tenant validator each implement the same PAR-mode decision;
  mTLS-alias/ordinary-endpoint selection also appears in the endpoint client. They currently agree. If consolidating them,
  keep the shared logic package-private in an appropriate existing component, preserve mTLS alias preference and do not
  add a public abstraction just for this. This is maintenance-risk reduction, not an observed security mismatch or measured
  performance gain. [Request factory], [tenant metadata validation], [endpoint client].
- **Additional regressions.** Custom/absent/canonical 201 reason-phrase cases and a non-201 success-shaped body are covered.
  Further useful coverage includes the expires_in type/integrality/positivity boundaries, 405/413/429 JSON/non-JSON
  failures, and PAR references remaining usable when the OP advertises generic reference-registration restrictions.
  Existing test bodies cover the ordinary form/authentication path, issuer-audience assertion, mTLS alias, JAR/JWE
  composition, encoded reference, missing lifetime, ordinary OAuth error and required-policy conflicts; they do not prove
  these additional cases. [Code exchange tests], [metadata tests], [HTTP/1 status tests].

Existing Common Parameters, FormParamsSupport and UriQueryWriteable already provide parameter storage/form/query encoding;
the module also reuses the Token Endpoint authentication code. No extra PAR encoder or Common utility is needed.
Parameters.Builder has add/set by name, not a bulk-copy-from-Parameters operation; the existing value-preserving copy loop
is not a duplicate of an available Common bulk-copy API. [Common parameters], [form media support], [request factory],
[endpoint client], [client authentication].

### Section-to-role cross-check

| RFC area | Coverage in this pass | Qualification |
| --- | --- | --- |
| 1–1.2 — purpose, examples and conventions | 9126-01, 09–10, 24. | Direct RP-to-OP submission precedes browser authorization; Request Objects are optional. |
| 2 — endpoint/authentication | 9126-02, 05–08. | HTTPS form POST, Token Endpoint method reuse and issuer audience; no separate grant. |
| 2.1 — pushed request/initial checks | 9126-03–04, 06, 21. | Current OIDC extensions preserved; forbidden reference rejected; AS validates the incoming request. |
| 2.2 — success/reference | 9126-11–13, 22, 25; 9126-F01. | Numeric 201 requirement, integral lifetime, opaque format and AS binding/entropy duties. |
| 2.3 — errors | 9126-10, 16. | OAuth error format, signed-request policy and additional failure statuses; no mandatory client retry loop. |
| 2.4 — redirect management | 9126-20. | Optional authenticated-client relaxation is OP policy, not a public-client bypass. |
| 3 — request parameter | 9126-09–10. | Protected authorization data and method-specific credentials are kept separate. |
| 4 — authorization request | 9126-14–15, 18–19, 21–22. | One client use, OP expiry/replay/policy checks and PAR-only enforcement. |
| 5 — AS metadata | 9126-17–18, 25. | Endpoint/Boolean/default and independence from generic reference-registration flags. |
| 6 — client metadata | 9126-19, 25. | Registration/administration is external; local REQUIRED is not remote client registration. |
| 7.1–7.4 — guessing/redirection/replay/policy | 9126-20–22. | Actual reference issuer controls entropy, authenticated redirect flexibility and acceptance after policy changes. |
| 7.5 — reference swapping | 9126-23. | Fresh state/nonce/default PKCE and ordinary callback/token validation remain relevant. |
| 8 — privacy | 9126-24. | Less browser payload, not blanket confidentiality or a privacy-policy certification. |
| 9–9.3 — IANA registrations | 9126-17, 19, 25. | Exact field names consumed; namespace allocation and metadata publication are not RP services. |

### Practical outcome and validation limits

- **Implemented client capability:** direct OIDC PAR with form encoding, shared client authentication, optional signed/
  encrypted Request Objects, reference-based browser requests, known/local required-policy checks and no weaker retry.
  The response-status check now accepts numeric 201 independent of the HTTP/1.1 reason phrase.
- **Resolved finding:** 9126-F01 previously rejected otherwise valid HTTP/1.1 201 responses with custom/empty reason
  text. The impact was login failure, not an authentication bypass; focused regressions now exercise the corrected path.
- **Operational limits:** static AUTO does not force optional discovery; no automatic failed/expired-handle retry,
  throttling backoff, payload resizing or dedicated per-transaction redirect generator is provided. Those omissions are
  not mandatory-client violations of this RFC. Safe error detail and selection-policy reuse are separate quality notes.
- **External responsibilities:** OP reference entropy/binding/expiry/replay, request validation, redirect/required-PAR
  policy and client registration, plus trustworthy deployment transport/origin configuration. None can be established just
  by finding a corresponding parameter in this RP's request.

Method: read the supplied RFC's substantive sections 1–9, relevant current implementation and selected existing test bodies;
checked the official edition and current project guidelines. Consulted HTTP/1.1 section 4 only to interpret the PAR status
requirement. No runtime tests, live OP/interoperability/attack probes or benchmarks were run, and no erratum was adopted.
This is not an exhaustive errata audit. No runtime code, Common or legacy provider was changed. The original eight-spec
inventory and the one hundred earlier RFC feature rows/findings are preserved. Detailed OIDC-relevant RFC8414 coverage
follows in section 6.

## 6. RFC 8414 — OAuth 2.0 Authorization Server Metadata

Source: [RFC 8414, OAuth 2.0 Authorization Server Metadata](https://www.rfc-editor.org/rfc/rfc8414.html), Standards Track,
June 2018, matching the supplied `oidc-specs/rfc8414.html`. Assessed: 2026-09-29.
Scope: discovery/metadata consumed for OIDC authentication, including relevant endpoint and capability fields. This is
not a general OAuth server, registration, revocation or resource-server feature audit. Assessment is complete for this scope:
30 entries and two source-confirmed findings, with explicit preconditions and no executed attack claim.

### Discovery profile, location and retrieval policy

Spec references: [purpose and discovery boundaries](https://www.rfc-editor.org/rfc/rfc8414.html#section-1),
[metadata location](https://www.rfc-editor.org/rfc/rfc8414.html#section-3),
[GET and path transformation](https://www.rfc-editor.org/rfc/rfc8414.html#section-3.1), and
[OIDC compatibility](https://www.rfc-editor.org/rfc/rfc8414.html#section-5).

| ID / Requirement or boundary | What RFC 8414 requires or describes | Current behavior and evidence | Qualification or remaining responsibility |
| --- | --- | --- | --- |
| 8414-01 — Metadata consumer versus publisher and OP selection | Clients obtain endpoint/capability metadata; how a client chooses its AS is outside this RFC. The AS publishes the document. | **OIDC-oriented consumer implemented.** Tenant configuration supplies the issuer and/or explicit metadata URI; the loader reads JSON into a shared endpoint/capability model used by the OIDC runtime. [Endpoint configuration], [Discovery metadata model], [metadata loader], [tenant metadata validation]. | This does not supply an AS metadata publisher or an automatic WebFinger/OP-selection service. Those are different roles, not missing mandatory RP mechanisms. A generic RFC8414 document also need not contain all fields required by the OIDC profile used by this client. |
| 8414-02 — Well-known suffix selection | The general OAuth default is /.well-known/oauth-authorization-server; applications can use another registered suffix, including openid-configuration. | **OIDC default and explicit URI supported; no generic OAuth suffix selector.** With no explicit URI, the model derives /.well-known/openid-configuration from the issuer. endpoints.well-known-uri can name a specific RFC8414 document instead. [Discovery metadata model], [endpoint configuration], [configuration tests]. | Setting an explicit URL does not make that document an OIDC OP or add missing OIDC capabilities. The supplied URL is used when discovery is needed; its presence alone does not force a fetch with otherwise complete static settings. Automatic oauth-authorization-server lookup is not implemented. |
| 8414-03 — Path issuers and compatibility lookup | RFC8414 inserts the well-known segment before the issuer path; OIDC Discovery appends it. Section 5 describes trying the RFC8414 transformation first and falling back to the OIDC location for transitional openid-configuration deployments. | **OIDC path transformation only; RFC8414 location can be explicit.** The helper removes trailing slashes for URL construction and appends the OIDC suffix. It does not generate the RFC8414 prefix-style path or perform two-location fallback. [Discovery metadata model], [metadata loader]. | This is a concrete automatic-discovery capability gap, not an incorrectly implemented OIDC append rule. Do not silently replace OIDC's path algorithm. Configure the intended RFC8414 URI explicitly and pin the expected issuer when using that location. Section 5's transition advice is not rewritten here as a new uppercase client MUST. |
| 8414-04 — Static configuration and when metadata is fetched | The RFC defines metadata retrieval, not a mandatory fetch on each login or a ban on explicit endpoint configuration. | **Demand-driven loading implemented.** OIDC initialization loads missing issuer/authorization/token/JWK data and required extension endpoints; otherwise it can use static settings. Existing tests check discovery with static authorization/token endpoints but a missing JWKS source, and no fetch merely to discover optional PAR. [Tenant metadata validation], [Discovery metadata model], [metadata tests]. | Static configuration means capability/identity consistency is partly the operator's responsibility. It does not prove that unpublished or unqueried metadata has no restrictions. In particular, AUTO does not guarantee discovery of every optional advertised extension. Metadata refresh/caching is addressed separately below. |
| 8414-05 — GET and protected retrieval | Query the selected metadata document with HTTP GET over HTTPS. | **GET/JSON and pre-fetch TLS policy implemented.** The loader validates the selected metadata URI against the tenant TLS policy before network I/O, disables redirects, and closes the response. This also covers static authorization/token endpoints with missing JWKS and required-PAR discovery. [Metadata loader], [endpoint configuration], [endpoint URI validation], [tenant validation], [tenant metadata validation]. | See resolved 8414-F02. Explicit `tls-required=false` remains a non-conforming local-test compatibility option; redirect blocking is an additional trust boundary, not a claim that RFC8414 universally prohibits redirects. [Metadata tests]. |

For issuer `https://as.example/tenant`, the location distinction is:

| Profile | Metadata URL | Automatic OIDC-next lookup |
| --- | --- | --- |
| OIDC Discovery | https://as.example/tenant/.well-known/openid-configuration | Yes. |
| RFC8414 with the OIDC suffix | https://as.example/.well-known/openid-configuration/tenant | No; explicit metadata URI required. |
| RFC8414 with its default suffix | https://as.example/.well-known/oauth-authorization-server/tenant | No; explicit metadata URI required. |

### Response processing, issuer binding and string semantics

Spec references: [field types](https://www.rfc-editor.org/rfc/rfc8414.html#section-2),
[response format/status](https://www.rfc-editor.org/rfc/rfc8414.html#section-3.2),
[issuer validation](https://www.rfc-editor.org/rfc/rfc8414.html#section-3.3),
[string operations](https://www.rfc-editor.org/rfc/rfc8414.html#section-4), and
[impersonation resistance](https://www.rfc-editor.org/rfc/rfc8414.html#section-6.2).

| ID / Requirement or boundary | What RFC 8414 requires or describes | Current behavior and evidence | Qualification or remaining responsibility |
| --- | --- | --- | --- |
| 8414-06 — Successful HTTP status and JSON object | A successful response uses HTTP status code 200 and an application/json object; errors use the appropriate HTTP status. | **Numeric 200 success validation implemented.** The loader compares the status code with `Status.OK_200_CODE` before checking JSON media type and reading `JsonObject`. Custom/empty HTTP/1.1 reason phrases succeed; a non-200 response still fails. [Metadata loader], [HTTP status values], [HTTP/1 status parser], [HTTP/1 response], [metadata tests]. | See resolved 8414-F01; accepting numeric 200 does not mean accepting arbitrary 2xx or dropping JSON/issuer validation. |
| 8414-07 — Typed values, arrays and extension fields | Metadata is a JSON object; multiple values use arrays, zero-element claims are omitted by the server, and additional claims may be returned. | **Typed known-field consumer, not a complete server-schema validator.** The model reads known strings/Booleans/arrays through Helidon JSON accessors, converts array elements to strings and keeps immutable lists. Wrong types on consumed fields fail parsing; unrecognized fields are not consumed. [Discovery metadata model], [JSON object access], [JSON value types]. | An empty array is retained rather than normalized to absence, so capability checks do not accidentally apply an omission default to an explicit empty set. The model does not globally reject every empty optional array or certify all server-side publication rules. Ignoring unrelated extension fields is not a protocol defect. |
| 8414-08 — Exact expected-issuer match before using metadata | Returned issuer MUST exactly equal the expected issuer used to construct the metadata URL; mismatching metadata MUST NOT be used. | **Issuer and selected metadata source bound.** Configured issuer pins are compared as exact strings; fetched metadata is also checked against the issuer-derived well-known URI before its endpoints are used. Mismatches are deterministic failures. [Discovery metadata model], [metadata loader], [tenant metadata validation], [runtime metadata tests], [metadata tests]. | Issuer equality is necessary but not a replacement for the pre-fetch TLS policy fixed in 8414-F02. Metadata-only bootstrap and noncanonical URLs have the restrictions described in resolved 9207-F01. |
| 8414-09 — JSON unescaping without identity normalization | Compare decoded JSON strings by exact Unicode code points; do not apply Unicode normalization. Issuer is an HTTPS URL without query or fragment. | **Exact representation retained.** Helidon JSON decoding resolves escapes/UTF-8; issuer equality uses String.equals rather than URI.equals, case folding or path normalization. URI conversion is used for syntax/transport checks, which reject issuer query/fragment and normally require HTTPS. [JSON strings], [JSON decoding], [Discovery metadata model], [endpoint URI validation], [tenant metadata validation], [runtime metadata tests]. | Trimming trailing slashes while constructing a discovery URL does not trim the issuer stored for identity comparison. A URI's host may be case-insensitive for routing while the issuer identifier still requires exact spelling. Pre-fetch TLS and source binding are separate checks; see resolved 8414-F02 and 9207-F01. |
| 8414-10 — Trust bootstrap for an explicit metadata URI | Discovery presupposes a trusted choice of AS; exact issuer validation and certificate checks prevent metadata from impersonating another server. | **Issuer-derived URI check now applies to fetched metadata.** When issuer is omitted, the returned issuer is checked against the actual well-known URI used, with the supported OIDC and RFC8414 path transformations. Arbitrary noncanonical metadata aliases cannot bootstrap a conflicting issuer. [Discovery metadata model], [tenant metadata validation], [metadata tests]. | Operators must still choose a trustworthy AS and its HTTPS discovery location. Configuring issuer gives an independent exact-string pin; wholly static/no-fetch configuration is distinct. See resolved 9207-F01 for valid shared-OP registrations and alias limits. |

### Endpoints, keys, scopes and flow capabilities

Spec reference: [metadata fields and defaults](https://www.rfc-editor.org/rfc/rfc8414.html#section-2).

| ID / Requirement or boundary | What RFC 8414 requires or describes | Current behavior and evidence | Qualification or remaining responsibility |
| --- | --- | --- | --- |
| 8414-11 — Authorization and Token Endpoint locations | authorization_endpoint is required for grants using it; token_endpoint is required except for implicit-only servers. | **Required for this code-flow client.** Both fields are parsed, merged with explicit endpoints, then required and URI-validated for an enabled OIDC code flow. Missing effective locations fail initialization. [Discovery metadata model], [tenant metadata validation], [endpoint URI validation], [metadata tests]. | The checks apply to the effective OIDC configuration, not every flow a generic OAuth server might offer. An implicit-only/token-only metadata document is not enough to operate this code-flow client. Static overrides can provide locations absent from a document; that is explicit configuration, not proof that the OP published a fully conforming document. |
| 8414-12 — JWK Set location and key roles | jwks_uri is optional in generic OAuth metadata, must use HTTPS when present, and can identify signing/encryption keys. A server publishing both purposes must include use on every key. | **JWK source integrated with OIDC's stricter needs.** The URI is parsed/merged and required for this ID Token validation path, with the configured TLS policy checked. The shared JWK Set manager supplies the key source to token validation and Request Object encryption. [Discovery metadata model], [tenant metadata validation], [tenant context], [JWK Set manager], [request object processor]. | Generic optionality does not make keys optional for the chosen OIDC signature-validation profile. A metadata URI is not itself a key, proof of possession or proof that every published key satisfies the AS's mixed-use labeling rule. This row does not re-audit all JOSE/JWKS rules; the document-source integrity issue is the resolved 8414-F02. |
| 8414-13 — Supported scopes are not an exhaustive allowlist | scopes_supported is RECOMMENDED, but the AS may omit some supported scope values even when it publishes the list. | **Not consumed for automatic scope selection or rejection.** The request uses locally configured scopes, including required openid, through the existing scope validation/serialization support. The metadata model does not treat scopes_supported as an exhaustive list. [Discovery metadata model], [authorization configuration], [tenant validation], [request factory]. | There is no scope-discovery UI or automatic scope negotiation. Failing every configured scope absent from this optional/incomplete list would be incorrect. Client registration, actual OP authorization and user consent still constrain what is granted. |
| 8414-14 — Supported response types | response_types_supported is a required array of supported response_type values, including complete combinations where applicable. | **Current flow checked.** When metadata is loaded for OIDC login, the array must be present and contain the exact code value. Missing/unsupported-code tests exist. The request builder always selects code. [Discovery metadata model], [tenant metadata validation], [request factory], [metadata tests]. | Merely advertising hybrid/implicit values does not enable those flows in this RP. A code-containing hybrid combination is not the same request as the standalone code response type. This is compatibility validation for the selected flow, not a conformance test of every OP response type. |
| 8414-15 — Supported grant types and omission default | grant_types_supported is optional; omission means authorization_code and implicit, not all grants. | **Omission default applied correctly to code flow.** A present list must contain authorization_code; an absent list uses the specified default. Existing tests distinguish unsupported explicit grants from omission. [Discovery metadata model], [tenant metadata validation], [metadata tests]. | Applying the metadata default does not add implicit-flow support to OIDC-next, select another grant or authorize an otherwise unregistered client. Static-only operation relies on explicit deployment agreement rather than a fetched capability list. Broader grant implementations are outside this RFC's OIDC-focused pass. |

### Response mode, authentication, PKCE and extension metadata

Spec references: [response-mode/authentication/PKCE fields and extensibility](https://www.rfc-editor.org/rfc/rfc8414.html#section-2)
and [additional response claims](https://www.rfc-editor.org/rfc/rfc8414.html#section-3.2).

| ID / Requirement or boundary | What RFC 8414 requires or describes | Current behavior and evidence | Qualification or remaining responsibility |
| --- | --- | --- | --- |
| 8414-16 — Response-mode capabilities | response_modes_supported is optional; omission defaults to query and fragment. Other registered modes may be advertised. | **Fixed query code-flow profile; capability selection not implemented.** The metadata model does not consume this list, the authorization request does not select response_mode, and the HTTP feature registers GET callbacks that read query parameters. [Discovery metadata model], [request factory], [HTTP feature]. | Advertising fragment or form_post does not make those callbacks supported here. There is no metadata-driven mode negotiation or early compatibility check for an OP profile that cannot serve this request's default query mode. The RFC does not require every client to implement every advertised optional mode; this is a feature boundary, not a demonstrated security issue. |
| 8414-17 — Token Endpoint authentication-method default | token_endpoint_auth_methods_supported is optional; omission means client_secret_basic. | **Configured method checked against the specified default/list.** Loaded metadata must permit the tenant's selected method. Omitted metadata accepts Basic but does not imply NONE, secret-post, JWT or mTLS support. Existing tests cover the Basic omission default and unsupported-method rejection. [Discovery metadata model], [tenant metadata validation], [client authentication], [metadata tests]. | The RP does not automatically change client credentials or authentication method just because another is advertised. The valid public-client method named none is distinct from the forbidden unsigned JWT algorithm also named none. Static-only operation relies on operator/registration agreement. |
| 8414-18 — JWT client-authentication algorithms | The signing-algorithm list is required when the AS advertises private_key_jwt or client_secret_jwt; it has no omission default and must not contain none. RS256 support is recommended. | **Selected JWT-authentication profile checked.** For either configured JWT method, loaded metadata must supply the list, include the chosen assertion algorithm and exclude none. Missing/mismatching/none regressions exist. [Tenant metadata validation], [client authentication], [metadata tests]. | Choosing a local default signing algorithm is not permission to assume the OP advertised it. Validation is conditional on the method actually used; a Basic client is not a general auditor of metadata for unused JWT methods. The OP's RS256 SHOULD is not an unconditional RP requirement to select RSA. Assertion construction details await RFC7523's own pass. |
| 8414-19 — PKCE metadata omission means no support | code_challenge_methods_supported is optional, but omission signals that the AS does not support PKCE. | **Selected method enforced when PKCE is required.** The default S256 profile requires a loaded list containing S256. Missing/incompatible methods fail initialization; explicitly disabling PKCE for an eligible confidential configuration skips this capability check. Existing tests cover all three cases. [Tenant metadata validation], [authorization configuration], [tenant validation], [metadata tests]. | Optional publication does not imply optional compatibility for a client requiring PKCE. The validator does not silently switch S256 to plain when metadata differs. The separate explicit-plain compatibility exception is documented in 7636-F01; this metadata check does not make it RFC-conformant. |
| 8414-20 — OIDC and companion extension metadata | Additional metadata members, including those defined by OIDC Discovery, may be used alongside the base fields. | **Selected extensions integrated.** The model consumes OIDC ID Token/UserInfo algorithms and endpoints, end-session, issuer-response support, PAR/JAR requirements and algorithms, and mTLS aliases/certificate-bound-token support. Their consumers apply feature-specific defaults/guards. An alias is selected for the corresponding mTLS method rather than automatically for every client. [Discovery metadata model], [tenant metadata validation], [client authentication], [endpoint client], [metadata tests]. | This is not blanket support for every registered extension or every field in an OP document. An extension flag is not a substitute for the complete protocol it describes. Earlier OIDC/PAR/JAR passes and the later mTLS/DPoP passes retain their own scope and findings; this row credits integration only. |

### Optional signed metadata, auxiliary fields and configuration precedence

Spec references: [metadata fields](https://www.rfc-editor.org/rfc/rfc8414.html#section-2),
[signed metadata](https://www.rfc-editor.org/rfc/rfc8414.html#section-2.1), and
[role of OpenID-named fields](https://www.rfc-editor.org/rfc/rfc8414.html#section-5).

| ID / Requirement or boundary | What RFC 8414 requires or describes | Current behavior and evidence | Qualification or remaining responsibility |
| --- | --- | --- | --- |
| 8414-21 — Optional signed_metadata bundle | Metadata may include a signed/MACed JWT with an iss identifying the attesting party. Unsupported consumers MAY ignore it; supporting consumers MUST give its claims precedence over corresponding plain members. | **Not implemented; permissible unsupported-feature behavior.** The reader consumes plain JSON members and does not inspect signed_metadata, verify its signature, resolve attestor trust or merge its claims. [Discovery metadata model], [metadata loader]. | This is an optional feature Helidon could implement if needed, not something inherently unsuitable for an RP. Current deployments need usable plain metadata over authenticated transport; required values present only in the signed bundle are not supplied to this client. The bundle's attestor iss must not be confused with the AS metadata issuer or with a configured expected issuer. Existing JWT/JAR support does not imply signed-metadata support. |
| 8414-22 — Registration, documentation, policy and locale information | registration_endpoint, service_documentation, ui_locales_supported, op_policy_uri and op_tos_uri are optional. Registration UI should display supplied policy/terms links; an omitted locale list is unspecified. | **Not consumed by this authentication client.** The metadata model does not expose these members, invoke registration, select a UI locale or display remote documentation/policy pages. [Discovery metadata model], [endpoint configuration], [tenant options]. | These are useful for optional onboarding/registration/application UI, but no such workflow is part of this RP's login path. They can be implemented or handled externally; omission is not a broken OIDC login invariant. The human-readable documentation URL need not be HTTPS under this field definition, so do not extend protocol-endpoint TLS rules mechanically to every informational link. |
| 8414-23 — Introspection metadata is a separate consumer role | Introspection endpoint/method/algorithm fields are optional. An absent methods list has no Basic default; support must be determined otherwise. JWT methods have their stated algorithm-publication rules. | **Fields parsed for the optional protected-resource role, not used instead of ID Token validation.** The model contains the endpoint and both capability lists. If introspection is selected, present method lists must allow the local method and selected JWT authentication requires a matching signing-algorithm list. [Discovery metadata model], [tenant metadata validation], [client authentication], [metadata tests]. | An absent methods list leaves compatibility to configured/out-of-band agreement; it is not an advertised Basic guarantee. This inventory does not claim every registered introspection authentication mechanism or certify every publication rule for unused algorithms. A full RFC7662/resource-server review remains outside the narrowed OIDC companion queue. |
| 8414-24 — Revocation metadata does not imply token revocation support | revocation_endpoint and its method/algorithm lists are optional; omitted methods default to Basic, with the stated JWT-algorithm constraints when applicable. | **Not consumed.** The metadata model does not read the endpoint or either revocation capability list, so their presence does not start a revocation operation or configure one. [Discovery metadata model], [endpoint configuration]. | OIDC logout/local session clearing must not be credited as OAuth token revocation on this basis. A revocation client could be a separate optional capability, but is not required merely to consume this metadata for OIDC. No standalone RFC7009 audit is being added. |
| 8414-25 — Static overrides versus discovered values | The standard defines AS metadata and, for supported signed bundles, signed-over-plain precedence. It does not define precedence for a local static-configuration API. | **Explicit local values retained.** After issuer agreement, merge fills absent endpoint/JWKS fields from discovery and preserves explicit ordinary locations. Loaded positive requirement flags remain true; mTLS aliases retain their separate method-specific selection. Existing tests verify endpoint and JWKS override behavior. [Discovery metadata model], [tenant metadata validation], [runtime metadata tests], [metadata tests]. | This is operator-controlled endpoint configuration, not an application of signed_metadata precedence or proof that the resulting cross-source configuration is coherent. It must not bypass known required security policies. The explicit-URI transport gap F02 and unpinned-bootstrap boundary remain applicable; local precedence alone does not authenticate discovered data. |

### Lifetime, transport, trust roles and registries

Spec references: [retrieval and responses](https://www.rfc-editor.org/rfc/rfc8414.html#section-3),
[TLS requirements](https://www.rfc-editor.org/rfc/rfc8414.html#section-6.1),
[impersonation](https://www.rfc-editor.org/rfc/rfc8414.html#section-6.2),
[publication security](https://www.rfc-editor.org/rfc/rfc8414.html#section-6.3),
[protected-resource selection](https://www.rfc-editor.org/rfc/rfc8414.html#section-6.4), and
[registries](https://www.rfc-editor.org/rfc/rfc8414.html#section-7).

| ID / Requirement or boundary | What RFC 8414 requires or describes | Current behavior and evidence | Qualification or remaining responsibility |
| --- | --- | --- | --- |
| 8414-26 — Metadata lifetime, errors and initialization retry | The RFC specifies retrieval/response processing but no fixed client refresh interval or particular initialization API. | **Resolved tenant snapshot with bounded retry behavior.** The runtime retains successful metadata with its ready tenant; it does not refetch per login or implement a metadata TTL/conditional-GET refresh loop. Fetch/parse failures are retryable after the configured initialization interval; issuer mismatch is deterministic failure. Existing tests distinguish recovery from a transient HTTP failure and retained mismatch failure. [Metadata loader], [tenant metadata validation], [tenant runtime registry], [metadata tests]. | A later lookup triggers an eligible retry; this is not a background polling promise. Endpoint/capability changes need new initialization rather than being picked up by JWKS key refresh. That operational limitation is not a missing RFC8414 refresh MUST. The pre-fix 200-identity failure is resolved in 8414-F01. |
| 8414-27 — TLS support and certificate verification | Use TLS with confidentiality/integrity protection and verify server identity/certificates under the referenced TLS identity rules; the AS has its stated TLS-version support obligations. | **Shared transport with pre-fetch scheme policy.** Metadata uses the configured WebClient/Common TLS stack, with URI validation before the fetch; Common defaults to HTTPS endpoint identification. [OIDC HTTP client factory], [Common TLS configuration], [Common TLS parameters], [TCP client connection]. | This is not certification of arbitrary user-supplied SSL contexts, disabled hostname verification, cipher policy or OP TLS versions. The separate JAR signed-JAR+PAR stricter certificate profile is scoped to its documented path (resolved 9101-F01), not a global TLS-policy switch. |
| 8414-28 — Metadata does not establish resource authorization | Standard publication does not replace normal server defenses, and secure association of an AS with appropriate protected resources is outside this RFC. | **Endpoint metadata is not treated as a resource-access grant.** This reader supplies protocol endpoints/capabilities; OIDC scopes/resource parameters and other application destinations remain separately configured. It neither publishes an AS metadata service nor automatically derives all permitted API targets from the issuer or Token Endpoint. [Discovery metadata model], [authorization configuration], [request factory], [tenant options]. | Operators/applications must still choose the right OP, resource/audience and token destination. TLS and a matching issuer do not prove an arbitrary resource should receive a token. No full resource-server authorization or publication-service audit is claimed in this OIDC pass. |
| 8414-29 — Registered names, case sensitivity and registry roles | Metadata names are case-sensitive; IANA/expert procedures govern additions, cross-registry collision avoidance and the oauth-authorization-server well-known suffix. | **Literal registered names consumed.** The JSON reader looks up exact member names and preserves string values rather than case-normalizing names/identifiers. Known base and selected extension fields are handled as described above. [Discovery metadata model], [JSON object access], [JSON decoding]. | Registry administration and publication of metadata/well-known resources are AS/IANA roles, not new RP services. The registration rules do not require a client to implement every listed feature or reject every unknown extension. Registration of the default OAuth suffix does not add its automatic lookup to this OIDC implementation. |
| 8414-30 — AS capabilities versus client registration and local policy | The document describes server-wide endpoints/capabilities; it is not itself a registration response that provisions a particular client. | **Local credentials/choices remain distinct.** Client ID, secret/key material, selected authentication method, scopes and token/request algorithm policies come from configuration. Metadata validates compatibility and can activate or require extensions under their local modes; it does not supply a new RP secret/private key or register the client. [Tenant options], [client authentication], [tenant metadata validation], [request factory], [Discovery metadata model]. | OP-specific client registration and policy must agree with those choices. A globally supported algorithm/method does not imply that every registered client can use it. Implementing optional registration or signed-metadata trust would be separate functionality, not a reason to duplicate existing authentication/key components. |

### Resolved interoperability gap 8414-F01 — valid 200 rejected for its reason phrase

**Remediation status — fixed, verified and committed as `0170fa3bae` on 2026-09-30.** The shared discovery loader
now compares the numeric response status with `Status.OK_200_CODE`. Against the original implementation, an otherwise
valid OP metadata response with a custom `200 Metadata Available` phrase left the code-flow tenant unavailable, and a
raw HTTP/1.1 `200` response with the required separator but no reason phrase failed despite reporting `status=200`.
Both regressions now pass. An existing non-200 (201) regression and existing JSON-content-type and issuer-validation
tests remain unchanged; all 1,606 module tests, 42 synthetic integrations, Checkstyle, maximum-effort
SpotBugs/FindSecBugs, copyright and dependency checks passed. All 18 real-Keycloak integration tests also passed
against the installed snapshot. No new configuration, dependency, public API, Common
or legacy-provider change. The analysis below records the pre-fix behavior, not a remaining failure.

Historical pre-fix analysis follows; the source calls and proposed tests below were superseded by this fix.

[RFC8414 section 3.2](https://www.rfc-editor.org/rfc/rfc8414.html#section-3.2) requires the 200 status code, not a particular
reason-phrase object. HTTP/1.1 permits custom or absent reason text, which clients should ignore for response semantics.
[HTTP/1.1 status-line rules](https://www.rfc-editor.org/rfc/rfc9112.html#section-4).

OidcProviderMetadataLoader uses `response.status() != Status.OK_200`. Http1StatusParser calls Status.create(code, phrase),
which preserves a different/empty phrase in a distinct Status object. The HTTP/1 call chain and response retain that object.
Consequently, `HTTP/1.1 200 Metadata Available` with an otherwise usable JSON document fails before JSON/issuer validation.
An omitted phrase with the required separator space has the same outcome. [Metadata loader], [HTTP status values],
[HTTP/1 status parser], [HTTP/1 call chain], [HTTP/1 response].

The loader wraps this as RetryableDiscoveryException, and tenant initialization returns a retryable FAILED context. A later
lookup may retry after the configured interval, but receiving the same representation fails again; the required OIDC tenant
does not become ready. This is availability/interoperability impact, not acceptance of bad metadata or an authentication
bypass. [Tenant metadata validation], [tenant context], [tenant runtime registry].

Existing tests cover non-200 rejection; the HTTP parser's own tests already preserve noncanonical 200 reason text and check
the numeric code. Add discovery regressions for standard/custom/empty 200 and non-200 statuses. The focused remedy is numeric
200 comparison while preserving JSON/issuer checks. This was a second affected callsite of the status-identity pattern found
in PAR, not evidence that changing the PAR method alone fixed discovery. The tests and runtime fix are described above.
[Metadata tests], [HTTP/1 status tests].

### Resolved conditional security/conformance gap 8414-F02 — metadata fetch bypassed the TLS policy

**Remediation status — fixed and verified 2026-09-29; committed as `dacfb25e88` on 2026-09-30.** [Metadata loader] now
validates the actual selected discovery URI before network I/O, using the existing [endpoint URI validation] helper and
the tenant's TLS policy supplied by both initialization and deferred outbound discovery. Policy violations are
deterministic configuration failures, not retryable network failures. Explicit HTTP opt-out and wholly static/no-discovery
behavior remain unchanged. No public API,
new configuration, dependency, Common or legacy-provider change.

The baseline was reproduced: missing-JWKS and required-PAR initialization made an HTTP metadata request and returned READY
despite default TLS enforcement; deferred loading also accepted it. Six focused regressions now pass, including zero-I/O
refusal, concurrent virtual-thread callers, actual trusted HTTPS and the HTTP-opt-out/static controls. All 1,564 module
tests, 42 synthetic integration tests, Checkstyle, maximum-effort SpotBugs/FindSecBugs and dependency analysis pass.
Keycloak was not rerun for this focused guard. The original analysis below is retained as the pre-fix baseline; it is not
a claim that the bypass remains in the current working tree.

Historical pre-fix analysis follows; the following call path and proposed remedy are not current behavior.

[RFC8414 section 3](https://www.rfc-editor.org/rfc/rfc8414.html#section-3) requires HTTPS for metadata retrieval, and
[section 6.1](https://www.rfc-editor.org/rfc/rfc8414.html#section-6.1) requires TLS confidentiality/integrity protection.
The source permits a fetch over HTTP even with Helidon's normal `endpoints.tls-required=true` policy in this configuration:

- An enabled OIDC code-flow tenant has an HTTPS issuer and static HTTPS authorization/token endpoints.
- endpoints.well-known-uri is explicitly HTTP; jwks-uri is omitted, so initialization must discover the JWK source.
- The usual client/cookie/HTTPS callback settings are valid. No additional enabled feature independently rejects that
  metadata URI; an authorization-code-only tenant with UserInfo/logout/protected-resource options absent suffices.
- For the credential-disclosure consequence below, the client uses secret-based authentication, has no static PAR endpoint,
  and retains the normal AUTO PAR mode.

The call path is:

1. OidcTenantConfigDecorator validates each configured authorization/token endpoint through requireEndpointOrWellKnown.
   That helper validates well-known-uri only if the corresponding ordinary endpoint is absent. Both are present here, so
   the HTTP override is not checked. The endpoint Blueprint has no unconditional metadata-URI validator.
2. OidcTenantContextFactory nevertheless selects discovery because jwkSetUri is absent.
3. OidcProviderMetadataLoader immediately issues GET to that explicit URI. Neither it nor OidcWebClientFactory applies the
   tenant's endpoint TLS policy before that network operation. Redirect blocking does not prevent this initial HTTP fetch.
4. Returned issuer/endpoints are checked only after retrieval. A response can retain the exact pinned HTTPS issuer and
   provide syntactically valid HTTPS endpoints/keys, so those later checks do not establish the document's integrity.

Evidence: [tenant options], [endpoint configuration], [tenant validation], [endpoint URI validation],
[tenant metadata validation], [metadata loader], [OIDC HTTP client factory], [Discovery metadata model]. The existing missing-JWKS discovery
test confirms that this trigger fetches even when authorization/token endpoints are static; it uses tls-required=false
and therefore is not a regression for this gap. [Metadata tests].

**Conditional security impact:** an attacker who can modify the HTTP metadata response can advertise an attacker-controlled
HTTPS PAR endpoint while copying the legitimate issuer and compatible code/S256/client-authentication/ID-Token algorithm
fields. AUTO selects that discovered PAR endpoint; the endpoint client sends the selected client authentication there.
With client_secret_basic or client_secret_post, this exposes the reusable client secret. The attacker needs control of the
cleartext response and the described configuration; no claim is made that default issuer-derived HTTPS discovery is
attackable or that an attacker can rewrite trusted local configuration. Issuer pinning alone does not stop this path.
[Request factory], [endpoint client], [client authentication], [tenant metadata validation].

The TLS bypass and downstream credential path are source-confirmed, not an executed interception/OP test. A focused fix
should validate the actual selected metadata URI against the applicable TLS policy before any I/O, reusing the existing
OIDC URI validation machinery without adding public API. Cover static endpoints plus missing JWKS and discovery needed
only for another required capability, while retaining intentional isolated-test HTTP behavior where allowed. Do not rely
on validating only returned URLs or require every legitimate OP endpoint to share the issuer's host. The remedy was applied
in `dacfb25e88`.

### Separate code-quality, reuse and usability observations

These are baseline observations, not additional security findings or new work authorization. Recheck any style or
documentation suggestion against subsequent guideline and remediation commits before treating it as open work.

- **Member order — Rule 2.1.** OidcProviderMetadata.wellKnownUri is a package-private static helper declared after instance
  getters; OidcTenantContextFactory.validateMutualTlsIntrospectionMetadata is a package-private static helper among later
  private methods. Move such declarations into the non-private static-method group to follow the permanent
  [member-order rule](https://github.com/helidon-io/helidon/blob/main/DEV-GUIDELINES.md#rule-2-1), without changing visibility
  or behavior. [Discovery metadata model], [tenant metadata validation].
- **Configuration clarity.** Explain that well-known-uri selects a source but does not force discovery when static data is
  sufficient, that path issuers use the OIDC append rule, and that ready tenant metadata is a snapshot rather than a
  periodically refreshed document. These distinctions avoid surprises without adding speculative new configuration.
  [Endpoint configuration], [Discovery metadata model], [tenant metadata validation], [tenant runtime registry].
- **Focused test coverage.** The F02 pre-I/O refusal (including static endpoints, missing JWKS and required PAR), HTTPS
  and isolated-test HTTP controls, and F01 canonical/custom/empty-200 and non-200 regressions were added with their fixes.
  Additional useful cases include unknown fields, decoded
  equivalent JSON escapes, exact issuer spelling and explicit empty-versus-omitted arrays. These are recommended tests,
  not claims that absent tests alone create vulnerabilities. [Metadata tests], [runtime metadata tests].

Reuse is already appropriate for the main machinery: Helidon JSON for typed/unescaped values, the provider-owned WebClient
and Common TLS for protocol I/O, and the existing URI guards and JWK manager. F02 was fixed at the metadata-fetch boundary
using that URI policy, without adding a public utility or switching discovery to an unconstrained generic Resource fetch.
Keep issuer identity comparison separate from URI normalization. A plain LazyValue is not a replacement for the runtime's
retry interval, failure classification and lifecycle/admission behavior. No performance improvement is claimed without a
measurement, and no Common or legacy-provider change is needed for the confirmed callsite defects.

### Section-to-role cross-check

| RFC area | Coverage in this pass | Qualification |
| --- | --- | --- |
| 1–1.2 — purpose/terminology | 8414-01, 10, 30. | OIDC consumer, trusted OP selection and AS publisher/client-registration roles remain distinct. |
| 2 — identity/endpoints/keys | 8414-08–12, 25. | Exact pin/URI requirements, effective configuration and OIDC's stronger key needs. |
| 2 — scopes/response/grant/authentication/PKCE | 8414-13–20. | Correct selected-flow defaults/guards; no automatic scope or response-mode negotiation. |
| 2 — auxiliary and non-login fields | 8414-22–24. | Registration/UI not consumed; introspection has a separate consumer; revocation fields ignored. |
| 2.1 — signed metadata | 8414-21. | Optional unsupported feature; no attestor verification or signed-claim precedence claimed. |
| 3–3.1 — metadata location/retrieval | 8414-02–05, 26; 8414-F02. | OIDC suffix/path default, explicit override, no generic RFC8414 automatic lookup; selected URI now passes pre-fetch TLS policy. |
| 3.2 — response | 8414-06–07, 26; 8414-F01. | Numeric 200 (including custom/empty reason phrases), JSON fields, arrays and failure handling. |
| 3.3, 4 — validation/string operations | 8414-08–10. | Exact decoded issuer pin when configured; metadata-only bootstrap remains an explicit trust boundary. |
| 5 — compatibility | 8414-02–03, 22. | Different path transformation and broader meanings of OpenID-named informational fields. |
| 6.1 — TLS | 8414-05, 27; 8414-F02. | Shared TLS stack plus selected-metadata-URI pre-fetch scheme guard. |
| 6.2 — impersonation | 8414-08–10; 8414-F02. | Issuer comparison plus trustworthy transport/source; earlier 9207-F01 is not counted again. |
| 6.3–6.4 — publication/resources | 8414-28, 30. | Metadata publicity does not replace server defenses or authorize arbitrary resource destinations. |
| 7–7.1.2 — metadata registry | 8414-07, 11–24, 29. | All initial field families classified; case-sensitive names and expert-registration duties kept separate. |
| 7.2–7.3.1 — collisions/well-known registry | 8414-02–03, 23, 29. | Registry procedures are not client feature implementations or an automatic URI lookup mechanism. |

### Practical outcome and validation limits

- **Implemented OIDC consumer:** JSON metadata, explicit/derived locations, exact configured issuer binding, static merge,
  selected code-flow/grant/authentication/PKCE checks, relevant OIDC extension fields and reusable tenant state.
- **Resolved TLS finding:** 8414-F02's pre-fix default-TLS bypass with static endpoints/missing JWKS was closed by checking
  the selected discovery URI before any request (`dacfb25e88`). The historical conditional tampering impact is recorded above.
- **Resolved interoperability finding:** 8414-F01 now accepts numeric 200 responses with custom/empty reason phrases
  while retaining non-200/JSON/issuer checks (`0170fa3bae`). The PAR fix alone would not have fixed this callsite.
- **Optional/partial features:** automatic RFC8414 prefix-style/default-OAuth lookup and transition fallback, signed metadata,
  response-mode negotiation, informational/registration field exposure and automatic metadata refresh are absent. An explicit
  URI covers lookup location but does not supply missing OIDC features or independent signed-metadata trust.
- **Other roles:** AS metadata publication, IANA registration administration, registration UI and general protected-resource/
  revocation services are not requirements to build into this OIDC authentication client. Optional client features can be
  added when needed; this inventory does not label them impossible for Helidon.

Method: read the supplied RFC's substantive sections 1–7, current metadata/initialization/HTTP/JSON/URI consumers and selected
existing test bodies; checked the official edition and complete current project guidelines. HTTP/1.1 section 4 is only a
supporting status-semantics reference, not another RFC audit. No runtime tests, live metadata/OP requests, interception probes,
TLS handshakes or benchmarks were performed in the original pass. No erratum was adopted or exhaustive errata audit claimed.
The original pass changed no runtime code, tests, Common or legacy provider; later remediations are recorded above. The 125 earlier
RFC feature rows/findings are preserved. Detailed OIDC RP client-assertion coverage follows in section 7.

## 7. RFC 7523 — JWT Client Authentication

Source: [RFC 7523, JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants](https://www.rfc-editor.org/rfc/rfc7523.html),
Standards Track, May 2015, matching the supplied `oidc-specs/rfc7523.html`. Assessed: 2026-09-29.
Scope: JWT assertions used to authenticate this OIDC RP during code redemption, refresh and the supported PAR composition.
The independent JWT-bearer authorization grant, generic JWT formats and an AS assertion-validation service are not added to
this phase. Assessment is complete for this scope: 25 entries, with required sender behavior, optional features and receiver
duties kept separate. No new confirmed security or mandatory-protocol defect is recorded; quality observations follow.

### Authentication role and HTTP binding

Spec references: [separate assertion uses](https://www.rfc-editor.org/rfc/rfc7523.html#section-1),
[HTTP bindings](https://www.rfc-editor.org/rfc/rfc7523.html#section-2),
[client authentication](https://www.rfc-editor.org/rfc/rfc7523.html#section-2.2), and
[privacy/transport](https://www.rfc-editor.org/rfc/rfc7523.html#section-7).

| ID / Requirement or boundary | What RFC 7523 requires or describes | Current behavior and evidence | Qualification or remaining responsibility |
| --- | --- | --- | --- |
| 7523-01 — Client authentication is not the authorization grant | A JWT can authenticate a client independently of the mechanism providing authorization. Client authentication must accompany a meaningful protocol request. | **Correct role separation.** CLIENT_SECRET_JWT and PRIVATE_KEY_JWT authenticate requests while code redemption keeps grant_type=authorization_code and refresh keeps grant_type=refresh_token. This is not a switch to the JWT-bearer grant. [Client authentication], [endpoint client], [client authentication methods]. | JWT client authentication neither logs in an end user by itself nor proves support for arbitrary assertion grants. The RFC's separate grant profile and its example are not credited as OIDC RP features merely because both profiles use JWTs. |
| 7523-02 — Exact client assertion parameter names and type | Use client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer and client_assertion containing the JWT; names/values are case-sensitive. | **Implemented.** The shared authentication branch adds the registered type and one generated assertion to the form. It does not use the grant-profile assertion parameter or grant-type URN in their place. Existing secret-JWT/private-key-JWT token tests check the form binding. [Client authentication], [endpoint client], [code exchange tests]. | A separate form client_id is not newly required by this binding when the assertion authenticates/identifies the client. The required client_id subject claim is assessed below. The public-client NONE method is a different branch, not an unsigned JWT assertion. |
| 7523-03 — Exactly one assertion and correct form transport | client_assertion MUST NOT contain more than one JWT; the HTTP parameter binding is used within the normal Token Endpoint request. | **Single compact assertion in the normal form.** Each code/refresh request starts with a new Parameters builder; authentication adds one signed token value and the shared POST uses application/x-www-form-urlencoded. Existing form support handles encoding rather than concatenating JWTs or hand-building an HTTP body. [Client authentication], [endpoint client], [form media support], [code exchange tests]. | The assertion authenticates the client; it does not sign every grant/code/redirect/resource form field as a request object. Those fields retain their own protocol checks and transport protection. This credits the normal provider-owned request, not arbitrary conflicting headers injected through a user-customized HTTP client. |
| 7523-04 — One implementation for code, refresh and PAR authentication | Client assertions are separable from grant choice; another protocol may explicitly reuse the authentication mechanism. | **Shared sender implementation.** Code redemption and refresh use the retained Token Endpoint authentication support. PAR reuses it through its protocol-specific adapter while keeping pushed authorization fields separate. [Endpoint client], [client authentication], [request factory]. | PAR's permission and issuer-audience recommendation come from RFC9126, already assessed, not from treating PAR as a Token Endpoint grant. Optional introspection/outbound consumers do not expand this pass into general OAuth grant/resource-server reviews. |
| 7523-05 — Assertion confidentiality and request destination | Privacy-sensitive assertions should travel over encrypted channels; the referenced OAuth security requirements also apply. | **Protected protocol transport by default; PAR always HTTPS.** Selected Token Endpoint traffic follows tenant TLS policy; PAR requires HTTPS even when the ordinary TLS opt-out is selected, and both POSTs disable redirects. JWT branches send neither the raw client secret nor private key as an authentication form field. [Endpoint URI validation], [tenant metadata validation], [endpoint client], [client authentication]. | A signature/MAC does not encrypt the claims or make a stolen unexpired assertion harmless. Trustworthy discovery/destination selection and TLS settings remain necessary. The pre-fix explicit-HTTP metadata path was fixed in 8414-F02; test-only HTTP for eligible non-PAR traffic is not production compliance. |

### Issuer, subject, audience and expiration

Spec references: [required claims and comparisons](https://www.rfc-editor.org/rfc/rfc7523.html#section-3) and
[out-of-band profile agreement](https://www.rfc-editor.org/rfc/rfc7523.html#section-5).
The more specific issuer/subject/audience conventions also come from
[OIDC Core client authentication](https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication);
this supporting reference is not a new OIDC Core review.

| ID / Requirement or boundary | What RFC 7523 requires or describes | Current behavior and evidence | Qualification or remaining responsibility |
| --- | --- | --- | --- |
| 7523-06 — Assertion issuer | iss identifies the entity issuing the assertion; identifiers require agreement and default to simple string comparison. OIDC specifies client_id as the issuer for its JWT authentication methods. | **OIDC issuer profile implemented.** Every generated assertion uses the configured client ID as iss, not the OP issuer or the end user's identity. The shared JWT serializer preserves that string. Existing tests verify the claim and separation between clients sharing key material. [Client authentication], [JWT serialization], [client assertion reuse tests], [code exchange tests]. | RFC7523's general issuer possibilities do not require an OIDC client to offer a third-party issuer override. Client-ID and key registration must agree with the AS. Issuer comparison at assertion receipt is the AS's responsibility. |
| 7523-07 — Client identity in subject | For client authentication, sub MUST be the OAuth client's client_id. The authorization-grant subject rules are different. | **Implemented.** The same configured client ID is placed in sub; no resource-owner subject, tenant display name or ID Token subject is substituted. Assertions for different client configurations retain their own iss/sub even when the configured signing resource is shared. [Client authentication], [client assertion reuse tests], [code exchange tests]. | Anonymous/user-subject examples in the grant/privacy portions of RFC7523 must not be copied into this client-authentication subject. A separate form client_id is not needed to repair an assertion that already supplies the required authenticated identity. |
| 7523-08 — Token Endpoint audience and exact value | aud must identify the AS as an intended recipient. The Token Endpoint URL MAY be used; the exact audience strings require out-of-band agreement and normally exact comparison. | **Token Endpoint audience implemented.** Token authentication adds the selected endpoint URI's toString value as the single audience element. No issuer/endpoint case folding or URI normalization is applied by this construction. The JWT serializes an audience array, and existing tests verify the value. [Client authentication], [endpoint client], [JWT serialization], [client assertion reuse tests], [code exchange tests]. | This follows OIDC's recommended Token Endpoint audience; it is not a claim that every RFC7523 deployment must accept that value. There is no independent custom-audience/multiple-audience configuration. An AS requiring another token-authentication audience needs an agreed supported profile or future explicit capability, not an automatic audience-guessing retry. |
| 7523-09 — PAR audience uses its companion profile | A protocol reusing JWT authentication can specify which AS identifier is appropriate; audience validation still belongs to the receiver. | **PAR-specific audience adapter implemented.** PAR uses the resolved AS issuer URI, falling back to the PAR endpoint only if issuer is absent on that internal path. Normal OIDC login requires a resolved issuer. Tests exercise Token Endpoint and repeated PAR assertions from the same support object with distinct audience values. [Client authentication], [tenant metadata validation], [client assertion reuse tests], [code exchange tests]. | RFC9126 supplies this issuer-audience recommendation and its AS acceptance alternatives; this is not a reason to globally replace the Token Endpoint audience for code/refresh. Audience flexibility in RFC7523 does not excuse ignoring the applicable companion profile. |
| 7523-10 — Expiration and agreed lifetime | exp is required and limits assertion validity; the AS rejects expired assertions subject to clock skew and may reject excessively distant expiry. Maximum acceptable lifetime requires agreement. | **Expiration generated, positive lifetime required for the tenant.** The assertion uses current time plus client-assertion.lifetime, default PT1M. Tenant validation rejects zero/negative values; copied-configuration tests check a distinct 20-second lifetime. JWT serialization writes epoch seconds. [Client authentication], [client assertion configuration], [client authentication validation], [JWT serialization], [configuration tests], [client assertion reuse tests]. | One minute is a local default, not a mandated RFC value. No hard maximum or client clock-skew/backdating option is imposed. Sub-second durations are accepted by positive-duration validation but lose fractional precision on the wire and may provide no usable positive validity window; documenting/guarding that configuration is a usability improvement, not an invented RFC minimum-lifetime rule. |

### Optional timing claims, replay identifiers and signing profile

Spec references: [claim/signature rules](https://www.rfc-editor.org/rfc/rfc7523.html#section-3),
[algorithm and deployment agreement](https://www.rfc-editor.org/rfc/rfc7523.html#section-5), and
[replay-policy scope](https://www.rfc-editor.org/rfc/rfc7523.html#section-6).

| ID / Requirement or boundary | What RFC 7523 requires or describes | Current behavior and evidence | Qualification or remaining responsibility |
| --- | --- | --- | --- |
| 7523-11 — Optional iat and nbf | iat and nbf are optional. The AS may reject an unreasonably old iat; nbf, when present, prohibits earlier acceptance. | **iat emitted; nbf omitted.** Each assertion receives the current issue time. There is no configured not-before delay, backdating or custom clock offset in this sender. Existing exact-claim-set tests include iat and omit nbf. [Client authentication], [JWT serialization], [client assertion configuration], [client assertion reuse tests]. | Omitting an optional nbf is not a conformance gap. Receiver clock/skew and age policies still need agreement; setting a short lifetime cannot correct a misconfigured system clock. The RFC does not require a caller-configurable clock API. |
| 7523-12 — Unique jti, fresh assertions and replay responsibility | RFC7523 permits jti and leaves replay protection optional; the selected OIDC profile requires jti and one use unless reuse is negotiated. | **Fresh assertion per provider request.** The producer generates a new UUID jti, current timestamps and a signature on every call; it caches key material rather than a finished JWT. Existing tests check unique IDs across repeated PAR calls, different clients and concurrent virtual-thread consumers. [Client authentication], [client assertion reuse tests], [code exchange tests]. | Generating a unique identifier enables but does not prove server replay enforcement. This client does not implement the AS's used-jti store or negotiate assertion reuse. The OIDC one-use rule must not be weakened by applying only RFC7523's generic optional-replay wording. |
| 7523-13 — Cryptographic protection and RS256 support | Assertions must be digitally signed or MACed. The AS must reject invalid protection; RS256 is mandatory to implement for this profile. | **Signed/MACed producer with RS256 available.** The code always invokes SignedJwt with the selected key. PRIVATE_KEY_JWT includes RS256 and uses it as the default for an RSA key without declared/configured alg; CLIENT_SECRET_JWT uses a supported HMAC algorithm. The OIDC guards reject none rather than emitting an unsecured authentication assertion. RSA assertions are independently verified with Nimbus in existing tests. [Client authentication], [JOSE key policy], [JWT signing], [client authentication validation], [client assertion reuse tests]. | Mandatory implementation of RS256 does not mean every assertion must use RSA, nor does it invalidate the OIDC HMAC method. The sender's use of a signature library is not proof that an arbitrary AS checks signatures correctly. No new cryptographic implementation or whole-JOSE certification is implied. |
| 7523-14 — Supported algorithms and unsupported extensions | Algorithm/key agreement is necessary; RFC7523 does not require every JWS algorithm in every client profile. | **Explicit supported subset.** Secret JWT supports HS256/HS384/HS512, default HS256. Private-key JWT supports RS256/RS384/RS512 and ES256/ES384/ES512; key type, declared alg and EC parameters constrain the selection. RSA-PSS, EdDSA and other algorithms are not accepted by this component. [Client authentication], [client assertion configuration], [JOSE key policy]. | These unsupported algorithms are optional capability gaps, not violations of the RS256 baseline. A configured algorithm must match a declared JWK alg; an omitted JWK alg can use a compatible configured/default choice. Metadata agreement is additionally checked for the selected JWT method. |
| 7523-15 — Signing key selection and permitted use | The parties must agree on the signing/MAC key and identifiers; the receiving AS must validate the resulting assertion. | **Local selection/eligibility guards implemented.** PRIVATE_KEY_JWT requires an RSA/EC private key. key-id selects it, or the private resource must contain exactly one key. Signing policy honors declared alg, use=sig and key_ops allowing sign when those restrictions are present, enforces RSA size and compatible EC algorithm, and writes the selected kid when available. [Client authentication], [client assertion configuration], [JOSE key policy], [JOSE key policy tests], [code exchange tests]. | These are reused JOSE/key-policy controls, not requirements to invent a new key store for RFC7523. The private resource's cardinality does not reveal the OP's registered public-key set; operators must still register matching public material/kid and manage rotation. Missing/public-only/unknown-key selections fail rather than falling back to another authentication method. |

### Key lifecycle, deployment agreement, customization and errors

Spec references: [assertion acquisition boundary](https://www.rfc-editor.org/rfc/rfc7523.html#section-1),
[signature/MAC requirements](https://www.rfc-editor.org/rfc/rfc7523.html#section-3),
[client-authentication errors](https://www.rfc-editor.org/rfc/rfc7523.html#section-3.2), and
[interoperability agreement](https://www.rfc-editor.org/rfc/rfc7523.html#section-5).

| ID / Requirement or boundary | What RFC 7523 requires or describes | Current behavior and evidence | Qualification or remaining responsibility |
| --- | --- | --- | --- |
| 7523-16 — Private signing material and resource lifetime | Acquisition of assertions and exchange of key/registration information are outside the RFC; the sender still needs the agreed signing key. | **Explicit local private JWKS configuration.** ResourceConfig supports file paths, classpath resources and supplied plain/Base64 content. URI sources are rejected before opening, including on independent assertion-config construction. Each authentication-support instance loads/selects and retains its parsed private key; the configuration is a repeatable description, not a shared consumed stream. [Client assertion configuration], [client assertion configuration validation], [client authentication], [JOSE key policy], [private key source tests], [client assertion reuse tests]. | The OP's public jwks_uri cannot supply the RP private key. Applications may obtain material from a trusted external secret store and supply content explicitly, but the provider does not fetch private keys from arbitrary URIs or provision/register them remotely. Existing instances do not automatically reload a changed local source; new consumers must still be able to load it. |
| 7523-17 — Shared-secret MAC key and strength policy | A MAC is allowed, with the agreed key and algorithm; the OIDC secret-JWT profile defines UTF-8 client-secret octets as the key. | **Correct secret representation and minimum sizes enforced.** The sender creates its octet JWK from UTF-8 bytes, not from a decoded interpretation of the configured secret string. Shared policy requires at least 32/48/64 UTF-8 octets for HS256/384/512. Tests include exact boundaries and multibyte text. [Client authentication], [JOSE key policy], [client authentication validation], [JOSE key policy tests], [configuration tests]. | These are implementation/JOSE strength controls, not a new RFC7523 password policy. Minimum byte length is not proof of secret entropy; weak human-chosen secrets remain unsuitable. The symmetric secret must already be registered/agreed with the OP. A private-key-JWT configuration cannot substitute an octet key. |
| 7523-18 — Metadata and per-client agreement | Interoperability requires agreed identifiers, endpoints, keys, permitted reuse, lifetime and claims; exchanging that information is outside this RFC. | **Configured choices plus available metadata validation.** Loaded metadata must permit the selected JWT authentication method and matching assertion algorithm, and cannot list none for that selected profile. Missing/mismatching algorithm tests exist. The client does not infer a new secret/key or registration merely from server capabilities. [Tenant metadata validation], [client authentication], [client assertion configuration], [metadata tests]. | Static-only configuration relies on operator agreement. Server-wide support is not proof that this client is registered for that method, key or lifetime. In particular, client key registration/rotation, replay policy and accepted audience strings remain deployment responsibilities. |
| 7523-19 — Alternative issuers, custom claims and external assertion suppliers | Additional claims are allowed; obtaining a JWT is out of scope, and further profiles may prescribe other requirements. | **Fixed OIDC assertion producer.** Public assertion options cover algorithm, kid, private resource and lifetime. There is no arbitrary claim map, independent issuer/subject override, custom audience list, pre-signed-JWT supplier or remote/HSM signing hook in this component. [Client assertion configuration], [client authentication]. | These are optional/profile-specific capabilities that could be added for a concrete need; their absence does not violate the selected OIDC client-authentication profile. Fixed iss/sub correctly prevents substituting an end-user subject. The general RFC's third-party authorization-grant example is not evidence that this RP must accept externally supplied client assertions. |
| 7523-20 — invalid_client versus invalid_grant | An invalid client-authentication JWT produces invalid_client; the separate JWT authorization-grant path uses invalid_grant. Optional description/URI fields may explain the error. | **Generic OAuth error handling is compatible.** The endpoint parses valid error strings and optional fields without a closed enum, so invalid_client is preserved. Code-flow failure stops before ID Token/session processing and returns the existing generic Token Endpoint error response; there is no automatic retry with a weaker method or guessed audience. [Endpoint client], [OAuth error response], [HTTP feature], [client authentication]. | Emitting the correct code is an AS duty. The inspected generic error regression uses invalid_grant for an expired authorization code; it is not a focused invalid_client/JWT test. Such a regression would improve coverage, but missing it is not evidence that invalid_client is currently rejected or authentication is bypassed. [Code exchange tests]. |

### Privacy, concurrent use and receiver/grant boundaries

Spec references: [receiver validation](https://www.rfc-editor.org/rfc/rfc7523.html#section-3),
[independent authorization-grant processing](https://www.rfc-editor.org/rfc/rfc7523.html#section-3.1),
[grant example](https://www.rfc-editor.org/rfc/rfc7523.html#section-4),
[privacy](https://www.rfc-editor.org/rfc/rfc7523.html#section-7), and
[registered URNs](https://www.rfc-editor.org/rfc/rfc7523.html#section-8).

| ID / Requirement or boundary | What RFC 7523 requires or describes | Current behavior and evidence | Qualification or remaining responsibility |
| --- | --- | --- | --- |
| 7523-21 — Minimal claims and optional assertion encryption | Include only information necessary for the exchange. Encrypted transport reduces disclosure; encryption to the AS can hide externally issued sensitive claims from the client when that use case applies. | **Minimal self-produced client assertions; no JWE assertion mode.** The payload contains iss/sub/aud/iat/exp/jti, with derived principal claims suppressed. Tests assert that exact set. The assertion stays in the back-channel authentication form, not the authorization browser URL. [Client authentication], [JWT serialization], [client assertion reuse tests], [endpoint client], [request factory]. | Signed/MACed JWT contents remain readable; this is not a confidentiality guarantee for logs/intermediaries. Encryption that hides claims from the client has no such benefit when this client itself creates those claims. Externally issued/encrypted assertions are an optional unsupported profile, not a missing mandatory JWE layer for current OIDC client authentication. |
| 7523-22 — Shared key material without shared assertion/signing state | Assertions still need the correct identity, audience, validity and cryptographic protection when requests overlap; the RFC does not prescribe a Java concurrency primitive. | **Operation-local JWT and JCA state.** Builders/timestamps/jti are created per assertion. Private key material is retained per support instance, while JwkPki/JwkOctet obtain a new Signature/Mac for each operation. Existing tests create 128 virtual-thread consumers from shared configuration and check independent claims/IDs/signatures. [Client authentication], [JWT signing], [JWT asymmetric signing], [JWT HMAC signing], [JWT cryptographic factories], [client assertion reuse tests]. | The virtual-thread test constructs separate support objects; it is not a direct stress test of one retained support instance. The source does not share a mutable JCA signing engine, and no race is established here. A focused shared-instance concurrent test would strengthen evidence. Do not cache a finished assertion or a mutable Signature/Mac as a key-loading optimization. |
| 7523-23 — Assertion validation is the AS's responsibility | The AS verifies issuer, client subject, intended audience, expiry/optional timing, signature/MAC and general JWT validity, applying its additional agreed policy. | **Compatible producer, not an AS verifier.** This RP supplies the required claims/protection and refuses unusable local credentials. It does not expose an incoming client-assertion validation endpoint or a server-side replay database. [Client authentication], [client authentication validation], [JOSE key policy], [HTTP feature]. | Local configuration validation and ID Token validation are different operations from authenticating an incoming OAuth client. The OP must perform the receiver checks; generated exp/jti and a locally valid signature do not prove that it does so. The supported OIDC profile's one-use semantics remain relevant even though generic RFC7523 replay enforcement is optional. |
| 7523-24 — Separate JWT-bearer grant and example | Sections 2.1/3.1/4 describe a JWT used as the grant, potentially issued by a third party and referring to a resource owner/delegate; client authentication is independent. | **Not this OIDC login flow.** Code/refresh requests use their own grants plus client_assertion fields. The RFC example's grant_type and assertion parameter are not emitted by these paths, and its user subject is not substituted for client_id. [Endpoint client], [client authentication]. | This pass does not certify or introduce a general JWT-bearer grant, assertion broker or RFC7521/7522 implementation. A JWT used as a token-exchange subject elsewhere would also be a different protocol. Those optional/separate OAuth workflows remain outside the approved OIDC-focused queue. |
| 7523-25 — Registered assertion and grant namespaces | The RFC registers distinct OAuth URNs for the JWT-bearer grant and JWT client-assertion type. | **Client-authentication namespace used accurately.** The producer uses urn:ietf:params:oauth:client-assertion-type:jwt-bearer in client_assertion_type. OIDC authentication-method names select the local signing profile; they are not substituted for that URN. Existing tests check the exact string. [Client authentication], [client authentication methods], [code exchange tests], [client assertion reuse tests]. | Registry publication is not a new RP service, and recognizing the client-assertion URN does not establish support for the separate grant URN. No proprietary token type, mandatory extra JWT claim or public discovery endpoint is needed merely to implement this binding. |

### Separate code-quality, reuse and usability observations

No new numbered security or mandatory-protocol finding is established in this pass. The observations below are separate
maintenance, efficiency and test/configuration improvements, not reasons to weaken required claims or signing checks.

- **Member order — Rule 2.1.** OidcClientAuthenticationSupport interleaves non-private static helpers with instance/private
  methods, and places private applyAuthentication before later non-private instance methods. Group members according to
  the permanent [member-order rule](https://github.com/helidon-io/helidon/blob/main/DEV-GUIDELINES.md#rule-2-1) without changing
  API or behavior. [Client authentication].
- **Positive-path JUnit assertions — Rule 10.6.** The inspected HMAC boundary tests in OidcProviderConfigTest and
  OidcJoseKeyPolicyTest use JUnit assertDoesNotThrow. The current
  [permitted JUnit exceptions](https://github.com/helidon-io/helidon/blob/main/DEV-GUIDELINES.md#rule-10-6) are assertAll and
  assertThrows. Invoke expected-success operations directly and, where useful, assert their observable result with Hamcrest.
  This is test style, not evidence that HMAC validation is wrong. [Configuration tests], [JOSE key policy tests].
- **HMAC material work per assertion.** clientSecretJwk repeats UTF-8 conversion/length validation, Base64/JSON assembly and
  octet-JWK construction for every JWT. Retaining the already constructed key material within the existing support object's
  lifetime could avoid that work, if worth optimizing. Keep each JWT/jti and JCA Mac operation independent. The current
  JwkOctet.Builder has no raw-key setter, so do not suggest a nonexistent shortcut API or add a public wrapper just for this.
  No benchmark or speedup is claimed. [Client authentication], [JWT HMAC signing], [JWT cryptographic factories].
- **Repeated initialization key resolution.** With loaded metadata and PRIVATE_KEY_JWT selected, capability validation
  constructs an authentication-support instance to obtain its algorithm, loading the local private key. Runtime endpoint
  construction creates another support instance and loads it again. Reusing validated material within that initialization
  could avoid duplicate loading/parsing while preserving client/algorithm separation. This is not a per-token-request key
  reload, and does not justify a global cross-tenant key/assertion cache. [Tenant metadata validation], [tenant context],
  [endpoint client], [client authentication].
- **Lifetime precision and focused regressions.** Document epoch-second precision or reject unsupported sub-second
  configurations explicitly; the RFC supplies no mandatory one-minute or other fixed minimum. Add a shared-support-instance
  virtual-thread test, a focused invalid_client response case, and independent HMAC/EC verification where coverage is useful.
  Existing concurrent tests cover independent support construction, so do not overstate them as shared-instance stress tests.
  [Client assertion configuration], [JWT serialization], [client assertion reuse tests], [code exchange tests].

The implementation already reuses SignedJwt/JwkKeys, Common ResourceConfig/Parameters and the provider-owned WebClient,
plus the OIDC key policy. JwkKeys closes the resource stream during loading; the retained configuration remains a reusable
description. [JWT key-set loading], [client authentication]. Keep those ownership boundaries and do not replace
operation-local JCA state with a shared mutable signer.
No new JWT implementation, signing utility or key-resource wrapper is needed for the current feature.

### Section-to-role cross-check

| RFC area | Coverage in this pass | Qualification |
| --- | --- | --- |
| 1–1.2 — purpose/conventions | 7523-01–04, 19, 24–25. | Authentication and grants are independent; selected OIDC claim profile and exact parameter names. |
| 2, 2.2 — client HTTP binding | 7523-02–05, 25. | Single assertion/type in the ordinary form; no fabricated JWT-bearer grant or mandatory extra client_id form field. |
| 2.1, 3.1, 4 — JWT authorization grant/example | 7523-01, 07, 20, 24. | Separate profile deliberately not audited as an OIDC login capability. |
| 3, list items 1–3 — iss/sub/aud | 7523-06–09, 19, 23. | Client identity, agreed exact audience and PAR-specific profile. |
| 3, list items 4–6 — timing | 7523-10–11, 23. | Required expiry, optional issued-at/not-before, negotiated lifetime and clock policy. |
| 3, list items 7–8 — ID/additional claims | 7523-12, 19, 21–23. | Fresh jti, minimal fixed claims and qualified OIDC versus generic replay rules. |
| 3, list items 9–10 — cryptography/validity | 7523-13–17, 22–23. | Signed/MACed production and local key guards; AS still performs incoming JWT validation. |
| 3.2 — client-authentication errors | 7523-20. | invalid_client is an AS response requirement; generic RP parser/failure handling is compatible. |
| 5 — interoperability/RS256 | 7523-08–10, 13–19. | Mandatory RSA baseline exists; registration/audience/lifetime/key agreement remains external. |
| 6 — security/replay | 7523-05, 12, 22–23. | Generic optional replay protection does not erase the selected OIDC one-use semantics. |
| 7 — privacy | 7523-05, 07, 19, 21. | Encrypted transport/minimal client claims; third-party grant subject and encryption use cases are distinct. |
| 8–8.2 — URI registration | 7523-02, 24–25. | Client-assertion and grant URNs are not interchangeable. |

### Practical outcome and validation limits

- **Implemented OIDC sender:** secret-JWT/private-key-JWT authentication, exact binding and client identity, endpoint/PAR
  audiences, fresh exp/iat/jti, RSA MTI plus the stated HMAC/EC subset, local key guards and compatible OAuth error handling.
- **Optional/profile-specific limits:** no custom audience/claim/issuer supplier, prebuilt or encrypted assertion mode,
  remote/HSM signer integration, automatic client-key registration/rotation or additional PSS/EdDSA algorithms. These could
  be added for concrete needs; none is presented as a missing universal RFC7523 requirement for this OIDC profile.
- **AS/deployment responsibilities:** client key/secret registration, exact audience agreement, acceptable lifetime/clock skew,
  signature/identity validation, replay policy and trustworthy transport. Client-generated jti and local signature checks do
  not certify the OP. The prior metadata/TLS/PKCE/issuer findings remain open and are not repeated as new assertion findings.
- **Result:** no new confirmed security or mandatory-protocol defect in the assessed sender path. The separate quality notes
  identify concrete style/efficiency/usability/test improvements; they do not authorize runtime changes.

Method: read the supplied RFC's substantive sections 1–8, relevant sender/configuration/key/serialization/error code and
selected existing test bodies; verified the official edition and current full project guidelines. Read the local OIDC
Core section-9 claim rules as supporting profile context, not as a new specification pass. Existing RSA checks include an
independent Nimbus implementation, but no tests were rerun here. No live OP/registration/attack probes, TLS handshakes or
benchmarks were performed, and no exhaustive errata audit is claimed. No runtime, test, Common or legacy-provider code was
changed. The original eight-spec inventory and 155 earlier RFC feature rows/findings are preserved.
Detailed OIDC-relevant mutual-TLS coverage follows in section 8.

## 8. RFC 8705 — Mutual-TLS Client Authentication and Certificate-Bound Tokens

Source: [RFC 8705, OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens](https://www.rfc-editor.org/rfc/rfc8705.html),
Standards Track, February 2020, matching the supplied `oidc-specs/rfc8705.html`. Assessed: 2026-09-29.
After clarifying that this is an OAuth extension rather than an OIDC-specific specification, the user explicitly approved
this pass. Scope: OIDC RP client authentication, associated bound-token use/refresh and relevant existing validation building
blocks, with client/OP/protected-resource duties kept distinct. This is not a new AS implementation or general resource-server
audit. Assessment is complete for this scope: 30 entries and two since-resolved alias gaps. Configured mTLS capability
is not blanket proof of every bound-token combination; the role/lifecycle limits and quality notes are separate.

### Independent mechanisms and the existing authentication path

Spec references: [independent mechanisms and TLS terminology](https://www.rfc-editor.org/rfc/rfc8705.html#section-1),
[client authentication and client_id](https://www.rfc-editor.org/rfc/rfc8705.html#section-2),
[PKI method name](https://www.rfc-editor.org/rfc/rfc8705.html#section-2.1.1), and
[self-signed method name](https://www.rfc-editor.org/rfc/rfc8705.html#section-2.2.1).

| ID / Requirement or boundary | What RFC 8705 requires or describes | Current behavior and evidence | Qualification or remaining responsibility |
| --- | --- | --- | --- |
| 8705-01 — Client authentication and token binding are independent | mTLS can authenticate the client, constrain access tokens to a certificate, or serve both purposes; these mechanisms need not be deployed together. | **Distinct controls/building blocks exist.** OIDC-next exposes TLS client-authentication methods separately from certificate-bound access-token validation configuration. The code/refresh/PAR paths reuse the configured protocol WebClient. [Client authentication methods], [client authentication], [certificate-bound configuration], [endpoint client]. | Selecting a TLS authentication method does not by itself guarantee that an OP issues bound tokens. Conversely, another authentication method or a public client can use certificate-bound tokens. The inbound validation configuration is not automatically an RP issuance request; those combinations are assessed below. Neither mechanism defines ID Token validation or browser end-user certificate login. |
| 8705-02 — Registered TLS client-authentication methods | The RFC defines tls_client_auth for PKI matching and self_signed_tls_client_auth for registered-certificate matching. | **Both method values implemented.** Configuration selects either enum, their metadata wire names match the registered values, and the authentication sender has explicit branches for both. Existing configuration and token tests cover both choices. [Client authentication methods], [client authentication], [configuration tests], [code exchange tests]. | The same TLS client machinery can present the certificate for either profile; their different identity checks belong at the AS. Merely providing a client certificate is not a reason to silently replace another explicitly selected OAuth authentication method. |
| 8705-03 — Actual TLS credentials and secure endpoint policy | The connection must exchange the client certificate and proof of its private key; normal server authentication remains necessary. | **TLS configuration and HTTPS guards implemented for TLS-authentication methods.** Validation requires enabled TLS plus key/certificate material, a supplied SSLContext or a custom TLS manager. The provider-owned WebClient preserves those settings and Common TLS performs the handshake. Token/selected PAR endpoints remain HTTPS-required for these methods even under the ordinary test relaxation. Tests cover missing/disabled credentials, supported configuration shapes and an HTTPS fixture requiring client certificates. [Client authentication validation], [tenant validation], [tenant metadata validation], [OIDC HTTP client factory], [TCP client connection], [configuration tests], [code exchange tests]. | A configured opaque SSLContext/custom manager is accepted as a provider of credentials, not introspected as proof that every connection will negotiate the intended certificate. Correct OP TLS configuration and certificate acceptance remain necessary. These tests do not implement every OP registration/subject-matching rule, and were inspected rather than rerun. |
| 8705-04 — Include client_id without adding another credential method | Every request using mTLS client authentication includes client_id so the AS can bind the certificate to the correct registered client. | **Shared form handling implemented.** The TLS branches add client_id and no Basic secret/header or JWT assertion of their own. Code redemption and refresh tests assert the expected forms. PAR preserves an existing plain-form client ID instead of duplicating it; the authentication branch can supply it when the JAR wrapper has removed ordinary outer fields. [Client authentication], [endpoint client], [request factory], [code exchange tests]. | A client_id field alone is not authentication; the AS must enforce the certificate-to-client binding. Credit is for the normal provider-owned request, not arbitrary conflicting authentication headers a user may inject through a customized HTTP client. |
| 8705-05 — Method support and local selection | Authentication method metadata/registration identifies the chosen profile; the AS's client policy determines whether mTLS authentication is required. | **Known capability agreement checked.** When metadata is loaded, the selected TLS method must appear in token_endpoint_auth_methods_supported. Omission retains the ordinary Basic default rather than implying TLS-method support. Local mode/credentials remain explicit. [Discovery metadata model], [tenant metadata validation], [client authentication validation], [client authentication methods], [metadata tests]. | Static-only operation relies on out-of-band agreement. Selecting the method locally does not register it at the OP, prove the OP checks the certificate or require bound-token issuance. The AS client's certificate policy and the separate token-binding flags are not interchangeable. |

### Certificate registration and endpoint aliases

Spec references: [PKI identity matching](https://www.rfc-editor.org/rfc/rfc8705.html#section-2.1),
[PKI client metadata](https://www.rfc-editor.org/rfc/rfc8705.html#section-2.1.2),
[self-signed matching](https://www.rfc-editor.org/rfc/rfc8705.html#section-2.2),
[certificate/JWK registration](https://www.rfc-editor.org/rfc/rfc8705.html#section-2.2.2), and
[mTLS endpoint aliases](https://www.rfc-editor.org/rfc/rfc8705.html#section-5).

| ID / Requirement or boundary | What RFC 8705 requires or describes | Current behavior and evidence | Qualification or remaining responsibility |
| --- | --- | --- | --- |
| 8705-06 — PKI certificate identity registration | PKI authentication validates the chain and matches exactly one registered DN/SAN selector. The defined selectors are tls_client_auth_subject_dn and tls_client_auth_san_dns/uri/ip/email; IP comparison is binary. | **Certificate presentation supported; registration/matching external.** The RP selects tls_client_auth and supplies TLS key/certificate material. It does not send those subject selectors with each grant or implement the OP's registration/identity-comparison service. [Client authentication methods], [client authentication validation], [client authentication], [tenant options]. | Configure the corresponding single expected subject at the OP through its registration/administration mechanism. Certificate chain/revocation/subject checks at the OP are not replaced by the RP checking that local credentials are configured. PKI certificate renewal can preserve the registered subject, but bound-token certificate lifetime has separate rules. |
| 8705-07 — Self-signed client certificates and public registration | The client registers certificates via client jwks/jwks_uri, with x5c carrying the certificate and the required JWK public-key members agreeing with its first certificate. The AS matches the registered certificate rather than validating a PKI chain. | **Sender supports the method; no certificate publisher/registration workflow.** The configured WebClient presents the local certificate/key while the sender includes client_id. The client-authentication enum and configuration expose the self-signed profile. [Client authentication methods], [client authentication validation], [OIDC HTTP client factory]. | Register the client certificate, not the OP's public signing JWKS or a bare public-key-only assertion configuration. This method does not instruct the RP to disable validation of the OP's server certificate. Remote client-key publication/rotation remains an external deployment function, not a missing AS service inside this RP. |
| 8705-08 — Alias preference for the TLS authentication methods | A client intending mTLS uses a corresponding advertised alias instead of the conventional endpoint; if no alias exists it uses the ordinary endpoint. Non-direct endpoints inside the alias object have no meaning. | **Implemented for applicable direct endpoints.** The model retains Token Endpoint, PAR, introspection and OP UserInfo aliases independently. Token/PAR/UserInfo use outbound mTLS intent (implied by TLS client authentication or set with `outbound-mutual-tls` for binding-only Basic/JWT/NONE); introspection's alias remains governed by its separate authentication configuration. Selected mTLS endpoints use HTTPS checks. [Discovery metadata model], [client authentication], [endpoint client], [tenant metadata validation], [code exchange tests]. | The authorization browser redirect is not an mTLS back-channel request and is not redirected to an invented certificate alias. An alias failure is not retried at the conventional endpoint. See resolved 8705-F01/F02 for the exact scopes and fallback rules. |
| 8705-09 — Alias selection when mTLS is only for token binding | Alias preference also applies to clients using mTLS to acquire/use certificate-bound tokens, independently of their OAuth client-authentication method. | **Explicit binding-only mTLS intent now supported.** `outbound-mutual-tls` with TLS/client certificate material selects advertised Token/PAR aliases even for Basic/JWT/NONE client authentication; absent aliases fall back to the configured conventional endpoint. [Client authentication], [endpoint client], [request factory], [tenant metadata validation]. | See resolved 8705-F01. This is a valid independent combination, not a reason to change OAuth authentication methods or infer client intent from the AS-wide support flag. |
| 8705-10 — Alias for an OP-hosted UserInfo request | The alias rule covers applicable direct requests to the AS; endpoint names can come from extensions to the base metadata. Certificate-bound token use requires mTLS at the resource. | **OP UserInfo alias selection implemented.** Discovery retains `mtls_endpoint_aliases.userinfo_endpoint`; the UserInfo client prefers that validated HTTPS alias when outbound mTLS is intended and otherwise uses the ordinary endpoint. [Discovery metadata model], [endpoint client], [UserInfo support]. | See resolved 8705-F02. This does not imply that arbitrary application resource servers advertise aliases or that every UserInfo call always needs mTLS. There is no retry at a conventional endpoint after an advertised alias fails. |

### Bound-token capability, client intent and OIDC use

Spec references: [token binding and resource requests](https://www.rfc-editor.org/rfc/rfc8705.html#section-3),
[AS capability metadata](https://www.rfc-editor.org/rfc/rfc8705.html#section-3.3),
[client intention metadata](https://www.rfc-editor.org/rfc/rfc8705.html#section-3.4),
[public clients](https://www.rfc-editor.org/rfc/rfc8705.html#section-4), and
[suitable grants/implicit-flow exclusion](https://www.rfc-editor.org/rfc/rfc8705.html#section-6.4).

| ID / Requirement or boundary | What RFC 8705 requires or describes | Current behavior and evidence | Qualification or remaining responsibility |
| --- | --- | --- | --- |
| 8705-11 — AS support flag and its false default | AS metadata tls_client_certificate_bound_access_tokens is optional and defaults to false. It signals support for issuing bound access tokens. | **Parsed with the correct default.** The model retains the Boolean. When metadata is loaded, the locally REQUIRED protected-resource validation profile requires advertised support; IF_PRESENT does not impose that capability prerequisite. [Discovery metadata model], [tenant metadata validation], [certificate-bound configuration], [certificate-bound modes]. | This is a consumed server capability and a local validation-policy check, not a per-client issuance request. A true flag does not prove that each received token is bound, that this client is registered for binding, or that a particular connection presented a certificate. |
| 8705-12 — Client binding intention and allowed AS fallback | The separate client metadata member of the same name indicates intent to use bound tokens, defaults false, and may be configured out of band. Without mTLS, the AS may reject or issue an unbound token even for an intending client. | **Outbound intent configurable; registration/issuance external.** `outbound-mutual-tls` selects the mTLS transport/aliases independently of client authentication, but does not send a nonstandard bound-token field or dynamically register the client Boolean. Inbound certificate-bound validation is a different role. [Tenant options], [endpoint client], [token validation configuration], [certificate-bound configuration]. | Operators must arrange OP client policy and actual mTLS transport. The RFC-permitted unbound fallback made the pre-fix F01 alias error consequential; configuring local TLS keys still does not guarantee that a particular AS token was issued bound. |
| 8705-13 — Present the issuing certificate when using the access token | Bound-token resource requests use the same certificate as issuance, over mTLS; the normal RFC6750 request format remains applicable. | **Common transport building blocks, with qualified RP coverage.** Token/refresh and OP UserInfo use the configured protocol WebClient and select mTLS aliases when outgoing intent applies. With a stable client certificate and correct certificate-requesting endpoints, this can present the matching credential. UserInfo sends `Authorization: Bearer`; no new mTLS token_type is invented. [OIDC HTTP client factory], [endpoint client], [token response], [UserInfo support]. | The shared TLS configuration is not a per-token record of the actual certificate selected by an opaque/multi-key manager or automatic certificate-rollover coordination. Resolved F01/F02 remove alias omissions, not the OP issuance or application-owned API transport obligations. |
| 8705-14 — Public client with a certificate used only for possession | A public client can use a self-signed certificate for token binding without registering that certificate as OAuth client-authentication credentials. | **Binding-only intent and alias handling supported.** NONE remains a public-client method, supplies client_id and requires S256 PKCE for code flow; `outbound-mutual-tls` uses separately configured TLS client keys and aliases without inventing a client secret. [Client authentication], [tenant validation], [OIDC HTTP client factory]. | Do not force self_signed_tls_client_auth as a workaround: that is a different registered-certificate authentication profile. The client/application must provision the instance certificate and arrange AS binding policy; automatic per-instance certificate generation/registration is not provided. See resolved 8705-F01. |
| 8705-15 — Token Endpoint grants, not browser-issued implicit tokens | The RFC covers binding at a direct Token Endpoint connection and explicitly excludes implicit tokens issued through the browser authorization endpoint. | **Aligned with the implemented flow.** OIDC-next uses authorization-code redemption and refresh POSTs through the protocol client; the browser authorization redirect is separate. TLS client credentials are not sent by turning the browser into this RP's mTLS client. [Request factory], [endpoint client], [HTTP feature]. | Existing absence of implicit/hybrid OIDC login is not a missing certificate-bound implicit implementation under this RFC. No browser certificate prompt or client private-key distribution to the browser is needed for the RP's back-channel profile. |

### Certificate confirmation and the existing validation boundary

Spec references: [resource possession check](https://www.rfc-editor.org/rfc/rfc8705.html#section-3),
[JWT certificate thumbprint](https://www.rfc-editor.org/rfc/rfc8705.html#section-3.1),
[introspection confirmation](https://www.rfc-editor.org/rfc/rfc8705.html#section-3.2), and
[TLS termination](https://www.rfc-editor.org/rfc/rfc8705.html#section-6.5).

| ID / Requirement or boundary | What RFC 8705 requires or describes | Current behavior and evidence | Qualification or remaining responsibility |
| --- | --- | --- | --- |
| 8705-16 — Certificate thumbprint representation | x5t#S256 represents SHA-256 of the certificate's DER encoding, Base64url without padding/whitespace, inside cnf. It is not a public-key thumbprint. | **Implemented shared helper.** The validator requires a string with the expected unpadded length/decodability, hashes Certificate.getEncoded() with SHA-256 and compares the canonical Base64url output. JWT and introspection consumers read cnf rather than a similarly named JWS header. [Certificate-bound validation], [JWT access-token validator], [introspection access-token validator]. | The full certificate is the binding input; replacing a certificate while retaining its public key still changes the binding. Exact comparison with the computed canonical string also prevents accepting another spelling of the digest. These are certificate-binding building blocks, not a new standalone JOSE/JWK-thumbprint audit. |
| 8705-17 — JWT and introspected token confirmation | A resource validates the token and compares its associated certificate with the current TLS peer. Introspection conveys cnf with the same structure. | **Both existing token-validation paths invoke the same binding check.** JWT signature validation precedes the confirmation check; the remaining JWT claim validation still runs. Introspection validates the response/claims and then checks its cnf against the current validation request. Authentication constructs that request with the current peer certificate. [JWT access-token validator], [introspection access-token validator], [access-token validation request], [authentication orchestrator]. | Binding supplements issuer/audience/time/active-token checks rather than replacing them. The current introspection validator makes a protocol call; no imaginary proof-result cache is credited. Any future claim-cache optimization must still apply the current request's certificate check. This is bounded coverage of the existing shared mechanism, not a general resource-server audit. |
| 8705-18 — Local acceptance modes and recognized binding failures | Certificate-bound requests require matching possession proof; a server can separately decide whether unbound tokens are permitted. | **Explicit, fail-closed handling for recognized certificate binding.** DISABLED is the default and rejects tokens carrying x5t#S256. IF_PRESENT validates that binding when present but allows unbound tokens; REQUIRED also rejects missing binding. Wrong-type/malformed thumbprints, absent peer certificates and mismatches fail. Existing JWT/introspection tests cover these branches. [Certificate-bound configuration], [certificate-bound modes], [certificate-bound validation], [JWT binding tests], [introspection binding tests]. | These modes govern protected-resource access, not OP issuance or RP outbound TLS setup. The helper targets its known confirmation members, not every possible cnf extension/schema. It also rejects a DPoP jkt on a Bearer path; that does not implement the separate DPoP protocol. |
| 8705-19 — Trusted peer-certificate source and terminated TLS | The resource obtains the certificate from its TLS layer. Secure handoff behind a TLS terminator is outside this RFC. | **Transport-derived default integration.** Webserver security places request.remotePeer() into the typed remotePeer attribute. OIDC extracts the first TLS certificate from PeerInfo; it does not accept a caller-supplied fingerprint or parse an arbitrary certificate-forwarding header as proof. [Webserver security integration], [request context], [access-token validation request], [certificate-bound validation]. | Custom integrations must preserve that trusted provenance. Behind TLS termination, the backend connection's proxy certificate is not automatically the original client's certificate; a secure, authenticated handoff requires deliberate deployment integration. A header containing a matching certificate is not evidence of private-key possession by itself. |
| 8705-20 — Browser refresh is not an incoming protected-resource proof | The certificate for RP-issued tokens belongs to the OAuth client connection; it need not be the browser/API caller's certificate. | **Documented fail-closed limitation when optional AT validation is enabled.** Browser refresh creates a separate validation use with no incoming peer certificate. If the tenant has a JWT/introspection access-token validation method, that validation rejects recognized certificate-bound replacement access tokens before processing an optional refreshed ID Token. The Blueprint states this restriction. [Refresh manager], [token validation configuration], [access-token validation request], [certificate-bound validation]. | This is not evidence that all bound-token refresh fails: a pure RP without that optional validator skips this step, and can retain/validate ID Token identity normally. Combined RP/AT-validation configurations lack an RP-outbound-certificate-aware validation path. Do not fix it by comparing to the browser's certificate or weakening protected-resource possession checks; treat it as an explicit unsupported combination, not a new authentication bypass. |

### Certificate lifetime, refresh, failures and TLS ownership

Spec references: [confidential/public refresh binding](https://www.rfc-editor.org/rfc/rfc8705.html#section-7.1),
[public refresh-token recommendation](https://www.rfc-editor.org/rfc/rfc8705.html#section-4),
[certificate renewal and bound access tokens](https://www.rfc-editor.org/rfc/rfc8705.html#section-6.3),
[client-authentication errors](https://www.rfc-editor.org/rfc/rfc8705.html#section-2),
[resource errors and handshake ordering](https://www.rfc-editor.org/rfc/rfc8705.html#section-3), and
[AS/resource TLS responsibilities](https://www.rfc-editor.org/rfc/rfc8705.html#section-6).

| ID / Requirement or boundary | What RFC 8705 requires or describes | Current behavior and evidence | Qualification or remaining responsibility |
| --- | --- | --- | --- |
| 8705-21 — Refresh binding differs by client profile | Confidential refresh tokens are bound to the client; TLS-authenticated clients get an indirect certificate binding through client ID/authentication. For public binding-only clients, the AS SHOULD bind/check refresh tokens against the certificate. | **Refresh request machinery reuses the configured client credentials.** The refresh POST goes through the same endpoint/authentication/WebClient path, with client_id for the TLS/NONE methods. The RP treats the refresh token as opaque, not as a JWT requiring its own cnf parser. [Endpoint client], [client authentication], [refresh manager], [code exchange tests]. | Actual refresh-token binding/checking is AS-side. Do not rewrite the public-client SHOULD as a universal MUST or require every confidential refresh token to pin the exact issuing leaf certificate. F01 also affects alias selection for binding-only refresh; optional refreshed-AT validation has the separate row20 limitation. |
| 8705-22 — Certificate replacement and access-token usability | A bound access token requires its specific certificate. Replacing that certificate means obtaining an appropriate new access token, often using refresh, before continuing protected access. | **No automatic certificate-aware rollover coordination.** Local authentication stores tokens/lifetimes; it does not store an issuance-certificate selection or trigger refresh merely because the WebClient TLS identity changed. UserInfo failure is reported rather than transparently retrying with a newly bound token. [Local authentication result], [refresh manager], [endpoint client], [UserInfo support], [OIDC HTTP client factory]. | Deployments must keep the appropriate certificate usable with its tokens and coordinate renewal/token replacement. A multi-key/opaque TLS manager must select the intended certificate consistently across Token/UserInfo endpoints. Public refresh-token certificate binding may constrain rollover differently from PKI client authentication. This operational limitation is not evidence of a possession bypass; a correctly checking resource rejects the mismatch. |
| 8705-23 — Client-authentication versus resource-access failures | Wrong/missing client-authentication certificates lead to invalid_client at the AS; a certificate-bound resource mismatch is rejected with HTTP401/invalid_token. | **Existing failure paths are compatible.** The OAuth error parser accepts invalid_client without a weaker-method retry. For the existing protected-resource validation path, binding failures become invalidBearerToken, yielding401 and a Bearer invalid_token challenge. Both JWT and introspection test helpers assert these public responses. [OAuth error response], [endpoint client], [authentication orchestrator], [authentication responses], [JWT binding tests], [introspection binding tests]. | TLS handshake rejection can occur before an OAuth HTTP error exists. OP client-registration matching/error production remains external. A failure while this RP calls UserInfo is an upstream error and is not mislabeled as the RP resource's own401 possession challenge. |
| 8705-24 — Request the certificate before reading the access token | TLS certificate negotiation precedes HTTP application data; this RFC does not specify opportunistic post-handshake authentication after inspecting a token. | **Listener policy remains in the TLS layer.** OIDC reads PeerInfo already established for the request; its HTTP feature installs routes and does not retroactively initiate a client-certificate handshake. The test infrastructure separately configures a client-certificate-requiring socket. [Request context], [HTTP feature], [webserver security integration], [code exchange tests]. | Enabling certificate-bound validation does not automatically make a Webserver listener request client certificates. Applications must configure suitable required/optional client-auth TLS or separate listeners, especially when browser and certificate-bearing API clients coexist. Lack of a token-triggered renegotiation feature is not a missing mechanism required by this RFC. |
| 8705-25 — Distinct client-PKI, resource-possession and server-trust checks | PKI client authentication uses certificate-chain/registered-subject checks at the AS. A proof-only resource need not validate that chain; normal TLS server authentication is still required. | **No redundant PKI parser in the binding helper.** It hashes the certificate supplied by the transport and checks token binding; TLS/X.509 processing is delegated to the existing stack. The configured client stack retains normal server endpoint identification by default. [Certificate-bound validation], [Common TLS configuration], [Common TLS parameters], [TCP client connection]. | Do not demand CA trust or impose certificate notAfter as an access-token exp check inside this hash matcher merely to emulate AS PKI authentication. Conversely, self-signed client authentication is not permission for the RP to disable verification of the OP's server certificate. AS trust-anchor selection and additional certificate policies remain deployment/receiver responsibilities. |

### Privacy, registries, reference examples and application boundaries

Spec references: [TLS/trust/parser considerations](https://www.rfc-editor.org/rfc/rfc8705.html#section-7.3),
[PKI spoofing](https://www.rfc-editor.org/rfc/rfc8705.html#section-7.4),
[established X.509 libraries](https://www.rfc-editor.org/rfc/rfc8705.html#section-7.5),
[privacy](https://www.rfc-editor.org/rfc/rfc8705.html#section-8),
[registered fields](https://www.rfc-editor.org/rfc/rfc8705.html#section-9),
[certificate/thumbprint example](https://www.rfc-editor.org/rfc/rfc8705.html#section-appendix.a), and
[relationship to Token Binding](https://www.rfc-editor.org/rfc/rfc8705.html#section-appendix.b).

| ID / Requirement or boundary | What RFC 8705 requires or describes | Current behavior and evidence | Qualification or remaining responsibility |
| --- | --- | --- | --- |
| 8705-26 — TLS policy, certificate privacy and trusted CAs | Use appropriate TLS security policy and established certificate libraries. Earlier-than-1.3 initial handshakes can expose the client certificate for tracking; the AS's PKI trust anchors must protect against subject spoofing. | **Existing configurable TLS stack reused.** Protocol requests use Common TLS/JDK configuration for versions, algorithms, trust and credentials rather than custom certificate parsing. [OIDC HTTP client factory], [Common TLS configuration], [Common TLS parameters], [TCP client connection]. | This is not certification of every custom SSLContext/trust setting or proof that every OP limits its CAs correctly. The RFC's privacy discussion distinguishes single-user clients from aggregate server-side clients; it does not define a mandatory OIDC-wide TLS1.3-only switch. Normal server-certificate validation and the earlier TLS-profile findings remain relevant. |
| 8705-27 — Registered names and separate metadata roles | The RFC registers x5t#S256, introspection cnf, AS aliases/support, the two authentication names, and client certificate/binding metadata. | **Relevant consumed names represented.** Method wire names, known aliases (including OP UserInfo), AS capability and token/introspection confirmation fields use the registered names. Client DN/SAN and certificate-registration information remains external to this RP's runtime configuration. [Client authentication methods], [Discovery metadata model], [certificate-bound validation]. | The identically named AS support/client-intent Boolean does not collapse their roles. Registration of a field does not require a client-side AS publisher or make all registry entries local configuration switches. F01/F02 alias coverage is addressed in their remediation notes. |
| 8705-28 — Independent certificate/thumbprint example | Appendix A supplies a concrete DER certificate, its cnf thumbprint and a compatible public JWK/x5c representation. | **Correct computation visible; independent vector coverage would improve evidence.** The helper hashes the encoded certificate as specified. Inspected JWT/introspection proof tests use OidcTestCertificates, whose certificate bytes are synthetic and whose expected thumbprint repeats the same digest/encoding formula. [Certificate-bound validation], [certificate test fixtures], [JWT binding tests], [introspection binding tests]. | Those tests exercise comparison/policy but do not independently establish real DER interoperability. The RFC's published A4DtL2JmUMhAsvJj5tKyn64SqzmuXbMrJa0n761y5v0 vector is useful for a focused known-answer regression. Missing such a test is not an additional product/security defect; no vector test was run or added here. |
| 8705-29 — Token Binding is a different mechanism | Appendix B compares TLS-certificate-bound tokens with the separate Token Binding work; related motivation does not make the protocols identical. | **No Token Binding support inferred.** This implementation's confirmed mechanism is X.509-certificate hashing/possession plus the configured TLS transport. Recognizing cnf or using a TLS connection does not itself implement another proof protocol. [Certificate-bound validation], [client authentication]. | The appendix's deployment observations describe its publication context, not current browser/platform support. A Token Binding implementation is not required for RFC8705, and no separate Token Binding or DPoP review is started here. |
| 8705-30 — Application-owned protected-resource transports | Every client use of a bound token must carry the appropriate certificate proof, including calls outside the Token Endpoint/UserInfo helper. | **Protocol WebClient scope is explicit.** OIDC-next creates its own WebClient from tenant settings for its protocol operations. Access tokens remain usable credentials for application integration, but those settings do not automatically configure every unrelated application HTTP client. [OIDC HTTP client factory], [endpoint client], [local authentication result]. | Applications must arrange the same-certificate transport for their own API calls. Attaching a Bearer header alone is not possession proof, and a resource server cannot automatically forward an original client's private-key capability. This is a credential-use responsibility, not a new audit of all outbound/resource-server features or a demand to expose private keys through public token objects. |

### Resolved conformance/design gap 8705-F01 — token-binding-only mTLS missed advertised aliases

**Remediation status — fixed, verified and committed as `282a094dee` on 2026-09-30.** A single tenant-level
`outbound-mutual-tls` option declares mTLS intent independently of OAuth client authentication; it defaults to false,
while the two existing TLS authentication methods continue to imply the intent. The configured WebClient must have
enabled TLS and a client certificate source, and mTLS-selected Token/PAR and fetched discovery URIs must be HTTPS,
regardless of the ordinary development HTTP opt-out. One package-private effective-intent decision and metadata
resolution path choose an advertised alias ahead of a static or discovered conventional URI; when the alias is absent,
the conventional URI is used, with no retry to it after alias failure. Token exchange, code, refresh, and Client
Credentials share the Token Endpoint choice. PAR AUTO also recognizes alias-only discovery. The inbound
protected-resource certificate-bound-token validation mode and independently configured introspection authentication
are unchanged. Basic, private_key_jwt, NONE, and the existing TLS methods were tested against real HTTPS listeners
with and without required client certificates. Static-only tenants still have no advertised alias and must configure
their intended mTLS listener URI directly; no new discovery fetch is forced for a fully static tenant.

This change fixes the conditional endpoint-selection gap, **not** the separate guarantee that an opaque access token
was issued certificate-bound. The AS's client registration and certificate negotiation still matter; RFC 8705 section
3.4 explicitly permits an unbound token if no certificate was presented. The source-backed scenario below describes
the pre-fix implementation, not a remaining request path under the new opt-in.

[RFC8705 section 5](https://www.rfc-editor.org/rfc/rfc8705.html#section-5) requires alias preference for clients intending
mTLS for authentication **and/or** certificate-bound token acquisition/use. Sections
[1](https://www.rfc-editor.org/rfc/rfc8705.html#section-1) and
[4](https://www.rfc-editor.org/rfc/rfc8705.html#section-4) expressly separate those mechanisms, including the public-client
case. Using a certificate for token binding alongside Basic/JWT authentication is not automatically a forbidden combination
of two OAuth client-authentication methods.

Historical pre-fix source path follows; the added `outbound-mutual-tls` option and alias resolver supersede it.

The implementation's decision was narrower: OidcClientAuthenticationSupport.usesMutualTls checked only TLS_CLIENT_AUTH and
SELF_SIGNED_TLS_CLIENT_AUTH. OidcEndpointClient uses that result to choose the Token Endpoint for code/refresh and the PAR
endpoint. The request factory and tenant validation repeat the same authentication-method-only decision for PAR availability
and selected-URI checks. TLS client credentials in the WebClient, or an agreed bound-token-only profile, do not affect it.
[Client authentication], [endpoint client], [request factory], [tenant metadata validation], [OIDC HTTP client factory].

A concrete conforming deployment illustrating the gap:

1. The RP uses client_secret_basic, has a TLS client certificate/key configured and has arranged certificate-bound token use
   with the AS. Metadata advertises distinct ordinary and mTLS Token Endpoints.
2. To avoid unnecessary certificate prompts, the ordinary endpoint does not request client certificates; the alias does.
   This separation is precisely a purpose of section 5.
3. The RP selects the ordinary endpoint because its OAuth method is Basic. TLS cannot send a client certificate unsolicited,
   so the intended certificate proof is absent even though local key material is configured.

This can cause token/PAR failure or **loss of the intended sender constraint**: under
[section 3.4](https://www.rfc-editor.org/rfc/rfc8705.html#section-3.4), an AS may issue an unbound token when a client that
declared bound-token intent connects without mTLS. If that fallback is used and the resource permits ordinary bearer tokens,
a stolen token would lack the expected certificate-possession barrier. No stolen-token attack was executed; this is a
conditional consequence of the source-confirmed alias selection, not a claim that every AS takes that branch. A conventional
endpoint that already negotiates mTLS may mask the interoperability impact, but does not cover the distinct-alias deployment.

An explicit ordinary-endpoint override pointing to the alias can work around a particular deployment, but does not implement
automatic preference. A focused follow-up must consistently represent outgoing mTLS intent independently of the OAuth
authentication method, across URI selection, PAR eligibility and validation. Do not infer that intent solely from global AS
capability metadata, and preserve ordinary behavior for clients not intending mTLS. Add Basic/JWT/public-client certificate-
binding cases alongside existing TLS-authentication alias tests. These tests and the runtime fix were subsequently added.

### Resolved interoperability gap 8705-F02 — an advertised mTLS UserInfo alias was ignored

**Remediation status — fixed, verified and committed as `282a094dee` on 2026-09-30.** Discovery now retains an
OP-advertised `mtls_endpoint_aliases.userinfo_endpoint` independently of the ordinary `userinfo_endpoint`. For a tenant
intending outbound mTLS, selected UserInfo requests prefer that alias, require HTTPS and reject fragments; a missing
alias falls back to the conventional endpoint, and an alias failure never triggers a downgrade retry. Alias-only
UserInfo metadata is accepted when that selected endpoint exists. An actual certificate-requiring HTTPS UserInfo
listener received the expected client certificate and bearer token; insecure/fragmented aliases failed before bearer
use. This is scoped to an OP-advertised UserInfo endpoint, not a claim that RFC 8705 enumerates UserInfo by name or
that unrelated application resource servers inherit an OIDC alias. The evidence below describes the original gap,
not the current UserInfo lookup.

[RFC8705 section 5](https://www.rfc-editor.org/rfc/rfc8705.html#section-5) permits alias members for direct endpoints defined
by metadata extensions and requires applicable clients to prefer them. userinfo_endpoint is such an OP metadata endpoint.
[OIDC Discovery metadata](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata).
This finding concerns an OP/AS-hosted UserInfo service for which mTLS is intended, not unrelated resource-server discovery.
It applies the RFC's generic direct-endpoint rule to the OIDC metadata member; RFC8705 does not enumerate UserInfo by name.

In the pre-fix implementation, OidcProviderMetadata.fromWellKnownMetadataJson retained only Token Endpoint, PAR and
introspection mTLS aliases. Its UserInfo
field comes only from the top-level member/static override. OidcEndpointClient.userInfo() unconditionally reads that ordinary
field; neither the helper nor OidcUserInfoSupport resolves an alias. This remains true with a TLS authentication method and
correctly configured client certificate, so fixing F01's authentication-method predicate alone would not fix this path.
[Discovery metadata model], [endpoint client], [UserInfo support].

For example, the RP can successfully obtain a certificate-bound access token at the selected mTLS Token Endpoint, then call
the ordinary UserInfo endpoint instead of its advertised certificate-requesting alias. If that ordinary listener does not
negotiate a client certificate, it cannot validate the token's possession proof and rejects access. The UserInfo helper
reports failure and the OIDC callback returns 502 before creating the local session. This is an avoidable login/refresh
interoperability failure, not an authentication bypass. [HTTP feature], [UserInfo support], [endpoint client], [refresh manager].

Follow-up: preserve/validate the UserInfo alias and apply it for the relevant outgoing mTLS request, with ordinary fallback
only when no applicable alias exists. Test distinct conventional/mTLS listeners and a bound-token UserInfo call. Do not
silently make the browser authentication endpoint or unrelated API destinations mTLS aliases. The remediation above
includes an HTTPS client-certificate UserInfo test; the original pass had no live probe.

### Separate code-quality, reuse and test observations

These are historical quality observations, not additional security findings. Subsequent guideline and alias fixes may
have addressed some; recheck current source before treating any suggestion as open work.

- **Unused exception binding — Rule 1.5.** validSha256Base64UrlThumbprint catches IllegalArgumentException as e without
  using it. The current [unnamed-binding rule](https://github.com/helidon-io/helidon/blob/main/DEV-GUIDELINES.md#rule-1-5)
  calls for an unnamed catch binding here. This is mechanical style, not a change to rejection behavior.
  [Certificate-bound validation].
- **One consistent alias decision.** Endpoint sending, PAR availability and tenant URI validation repeat the same narrow
  authentication-method predicate. F01 shows why mTLS authentication and outgoing mTLS intent must be represented distinctly.
  Reuse a consistent package-private resolution path when fixing the affected callers; do not add a speculative public
  utility or use the AS-wide support Boolean as an opt-in. Adding a UserInfo alias also needs its own metadata/validation
  wiring, not just changing the predicate. [Client authentication], [request factory], [endpoint client],
  [tenant metadata validation], [Discovery metadata model].
- **Self-signed registration wording.** The method enum's reference to a registered certificate or public key is broad.
  Clarify that this RFC's profile registers the certificate in client JWK x5c, alongside consistent required public-key
  members. This does not require restoring an unused public key-resource endpoint or implementing OP registration in the RP.
  [Client authentication methods].
- **Focused integration and known-answer coverage.** Add distinct ordinary/mTLS listeners for the F01 Basic/JWT/public
  combinations and F02 UserInfo call; force the ordinary listener not to request a certificate so it cannot mask alias
  mistakes. Complement synthetic PeerInfo/certificate unit tests with the RFC Appendix A digest vector and a real protected-
  resource TLS test using matching/mismatching client certificates. Also test DISABLED with an otherwise valid bound token
  and matching certificate, and the documented browser-refresh validation restriction. Existing malformed/no-peer cases
  alone do not isolate every acceptance-mode decision. [Code exchange tests], [JWT binding tests],
  [introspection binding tests], [certificate test fixtures].
- **Unused test-helper argument.** Both binding-test classes pass an ignoredDescription argument to assertInvalidToken,
  but the helper intentionally checks the generic public message instead. Remove the unused argument/call-site strings to
  make the asserted contract clearer; do not restore detailed public failure messages merely to satisfy stale expectations.
  [JWT binding tests], [introspection binding tests].

Reuse is already appropriate for the TLS/peer plumbing: Common TLS, WebClient and PeerInfo, plus one certificate-confirmation
helper shared by JWT/introspection. JDK certificate encoding and an operation-local MessageDigest avoid a new X.509 parser or
shared mutable digest. No extra Common hashing wrapper, legacy-provider change, global certificate cache or unmeasured
performance claim is needed. Certificate registration, trusted proxy integration and client-key lifecycle are substantial
external contracts, not functionality to infer from a single mode flag.

### Section-to-role cross-check

| RFC area | Coverage in this pass | Qualification |
| --- | --- | --- |
| 1–1.2 — mechanisms/terminology | 8705-01–03, 13–15, 30. | OAuth client authentication, token possession and OIDC user authentication are different roles. |
| 2 — authentication/client ID/errors | 8705-02–05, 23. | Configured client certificate and client_id; OP enforces registration and invalid_client. |
| 2.1–2.1.2 — PKI | 8705-06, 21–22, 25–26. | One registered DN/SAN selector, chain/trust policy and renewal distinct from token thumbprints. |
| 2.2–2.2.2 — self-signed profile | 8705-07, 25, 27. | Registered x5c certificate, no RP server-trust bypass; client registration external. |
| 3 — binding/resource presentation | 8705-01, 13–14, 16–20, 23–25, 30. | Same certificate, actual TLS proof, shared validation and role boundaries. |
| 3.1–3.2 — confirmation representations | 8705-16–18, 28. | Full DER certificate SHA256, exact Base64url and JWT/introspection consumers. |
| 3.3–3.4 — capability/client intent | 8705-11–12; 8705-F01. | Two metadata roles; permitted unbound fallback makes wrong endpoint selection security-relevant. |
| 4 — public binding-only clients | 8705-09, 14, 21; 8705-F01. | No registered OAuth authentication credential is required for this independent use; refresh binding SHOULD. |
| 5 — aliases | 8705-08–10; 8705-F01/F02. | Binding-only preference and OP UserInfo alias resolved; application API destinations remain external. |
| 6.1–6.2 — TLS listener/receiver roles | 8705-03, 19, 23–25. | Certificate request precedes the token; PKI client authentication and resource-only possession differ. |
| 6.3 — certificate replacement | 8705-13, 20–22. | Stable certificate selection and token rollover; optional browser AT validation is not RP proof tracking. |
| 6.4–6.5 — implicit/TLS termination | 8705-15, 19, 24. | No implicit binding or post-handshake mechanism required; trusted proxy handoff is deployment-specific. |
| 7.1–7.2 — refresh/hash binding | 8705-16, 21–22. | Indirect confidential-client RT binding versus public certificate binding; full-certificate digest. |
| 7.3–7.5 — TLS/trust/X.509 | 8705-03, 25–26. | Established stack, appropriately limited AS trust anchors, no full TLS-policy certification. |
| 8 — privacy | 8705-26. | Certificate visibility/tracking considerations, especially single-user clients; not a new OIDC login factor. |
| 9–9.5 — registrations | 8705-02, 06–12, 16–18, 27. | All registered field families classified without implementing an AS/registration service. |
| Appendices A–B | 8705-28–29. | Known-answer evidence opportunity and a distinct proof mechanism, not extra required features. |

### Practical outcome and validation limits

| OIDC-related use | Current support | Main boundary |
| --- | --- | --- |
| PKI/self-signed mTLS client authentication | Implemented configuration, transport and form handling. | OP registration, certificate policy and actual TLS negotiation still matter. |
| Basic/JWT/public client using mTLS only for binding | Explicit `outbound-mutual-tls` and advertised Token/PAR alias selection implemented. | 8705-F01 resolved; OP registration/issuance and actual certificate presentation still matter. |
| Bound-token use at OP UserInfo | Advertised UserInfo mTLS alias is preferred when outbound mTLS is intended. | 8705-F02 resolved; consistent certificate selection still matters. |
| Existing JWT/introspection certificate-bound validation | Implemented acceptance modes and current-peer matching. | Configure trustworthy TLS peer/listener integration; not automatic RP issuance policy. |
| RP refresh with optional access-token validation | Recognized bound replacements are rejected in that separate validation use. | Documented unsupported combination; pure RP without that validator is different. |
| Certificate rollover and application API transports | Deployment coordination required. | No automatic issuance-certificate tracking/rollover retry or provisioning of every application client. |

F01 and F02 are resolved alias-selection findings. F01's pre-fix consequence was a conditional loss of binding, not a
demonstrated token theft; F02 was a distinct UserInfo interoperability gap. The registration/publisher/receiver duties,
refresh limitation and operational lifecycle boundaries are not extra proven vulnerabilities. Added HTTPS certificate-
requiring tests cover both alias profiles, but cannot certify every OP issuance policy, client registration or TLS
deployment. Full RFC8705 interoperability is not established by local alias selection and token-validation helpers alone.

Method: read the supplied RFC's substantive sections 1–9 and Appendices A/B, relevant current OIDC/TLS/peer consumers and selected
existing test bodies; checked the official edition and current complete project guidelines. Consulted the local OIDC Discovery
UserInfo definition as supporting endpoint context. A supplementary compatibility search did not import iGov/FAPI requirements
or third-party findings into this review. No runtime tests, live OP/registration calls, TLS handshakes, interception/replay
probes or benchmarks were performed. No erratum was adopted or exhaustive errata audit claimed. No runtime/test/Common/legacy
code was changed and no finding was fixed. The original eight-spec inventory and 180 earlier RFC feature rows/findings are
preserved. RFC9449's subsequent scope disposition is recorded below; the next detailed pass is **RFC 9470 — Step-up challenges**.

## 9. RFC 9449 — DPoP (not supported)

Support boundary checked: 2026-09-29. **Not supported; intentionally outside the current implementation scope.** The user
asked to verify the existing decision and mark DPoP unsupported. The module's
[supported standards boundary](README.md#supported-standards-boundary) already explicitly lists DPoP as unimplemented.
Current source and existing test bodies agree with that documented boundary:

- The [token response] parser accepts only the Bearer token type, so a DPoP Token Endpoint response is rejected. The
  [endpoint client] sends Bearer credentials to UserInfo without a DPoP proof. There is no DPoP client/proof implementation
  in this module; DPoP proof generation/validation, protocol nonce handling and proof replay protection are not supported.
- The [certificate-bound validation] helper rejects recognized `cnf.jkt` binding on Bearer validation paths. Existing
  [JWT binding tests] and [introspection binding tests] cover this rejection, including tokens also carrying a matching
  certificate binding. The introspection tests also cover rejection of `token_type=DPoP`. These are safeguards against
  accepting unsupported credentials as Bearer, not partial DPoP protocol support.

This records an intentional support boundary, not a new security finding or implementation backlog item. It does not mean
DPoP would be technically unsuitable for Helidon; implementing it would require a separate scope decision. The detailed
RFC9449 pass is skipped at the user's direction, superseding earlier planning references to a later DPoP pass. No full-RFC
conformance assessment is claimed, no code was changed, and the inspected tests were not run. The eight completed detailed
RFC passes still contain 210 feature entries and eight unimplemented findings.

The next detailed pass, **RFC 9470 — Step-up challenges**, is recorded below.

## 10. RFC 9470 — Step-up authentication challenges in an OIDC client

Assessed: 2026-09-29. Source: the supplied local RFC9470 and the
[official September 2023 RFC Editor edition](https://www.rfc-editor.org/rfc/rfc9470.html). All substantive sections 1–10
have been read and traced against the relevant current implementation. This is an OIDC-focused capability assessment,
not a new general-purpose resource-server policy audit or an implementation request.

**Verdict: not implemented as an end-to-end protocol.** The provider has reusable login, callback-error, validated-claim
and refresh-continuity pieces, but neither generates nor consumes RFC9470 challenges and has no first-class acr_values,
max_age or step-up continuation. This pass identifies missing optional support, not a new demonstrated security bypass or
mandatory-protocol defect in an advertised RFC9470 implementation. Unlike DPoP, this mechanism has not been explicitly
excluded by the user; it remains a possible feature decision, not an automatically scheduled fix.

### Protocol roles and challenge contract

The RFC coordinates three roles: a resource server communicates unmet authentication requirements, a client returns to
the authorization server with those requirements, and the authorization server performs the authentication and issues
credentials describing it. A stronger/recent authentication demand is distinct from an invalid token or a missing scope.
The resource server's policy engine and the authorization server's authentication mechanisms are not defined here.
[RFC9470 sections 1–3](https://www.rfc-editor.org/rfc/rfc9470.html#section-2).

| Entry / feature | Specification requirement or boundary | Current implementation / evidence | Assessment / consequence |
| --- | --- | --- | --- |
| 9470-01 — End-to-end step-up roles | An already-token-bearing client receives a resource challenge, initiates authorization with the indicated requirements, obtains another token and retries the resource request. Section 2 does not define a universal hierarchy of authentication methods. | **No built-in challenge-driven cycle.** The [OIDC provider] exposes authentication and outbound request security; the [outbound orchestrator] attaches/acquires credentials without a resource-response challenge consumer. The [authentication orchestrator] handles Bearer/local-cookie authentication, not a retained downstream step-up demand. | Ordinary authorization-code login and token propagation are reusable pieces, not RFC9470 support. This is a missing optional protocol capability, not proof that an existing access-control policy is bypassed. |
| 9470-02 — Authentication-strength error challenge | Section 3 defines insufficient_user_authentication for the OAuth authentication challenge; its Bearer examples use HTTP401 and WWW-Authenticate. The error concerns how/when the user authenticated, not merely token validity. | **Not generated or interpreted.** [Authentication responses] emit ordinary missing-credential, invalid_token and invalid_request Bearer challenges. [Protected-resource configuration] provides a realm and token-validation settings, but no RFC9470 challenge policy/fields. | A generic401 or invalid_token does not carry this protocol's meaning. The extension is also usable with other OAuth challenge schemes; no DPoP support is inferred or requested. |
| 9470-03 — Preferred acceptable authentication contexts | Section 3's acr_values challenge parameter is a space-separated list in preference order; any listed context can meet the resource's requirement. Section 2 explicitly disclaims an absolute, interoperable ordering of authentication methods. | **No supported ACR challenge model or comparison.** Neither [protected-resource configuration] nor [endpoint policy configuration] expresses accepted ACRs or their challenge order; [authentication responses] do not serialize acr_values. | Do not equate a numeric-looking ACR, a role or an AMR method list with a universally stronger authentication level. An application/OP policy agreement would be needed; its absence is not an intrinsic Helidon limitation. |
| 9470-04 — Authentication-recency challenge | Section 3 defines max_age as elapsed seconds since the last active user authentication. The HTTP auth-param may be a token or quoted string, but must represent a non-negative integer. | **Not supported as a challenge or request constraint.** The challenge factory has no max_age parameter/parser, and the [authorization configuration] has no max_age option. Current expiry/refresh configuration addresses credential/session lifetimes instead. | A fresh access-token iat, longer session lifetime or successful refresh is not proof of recent active authentication. A future parser must handle both permitted HTTP forms without accepting negative/fractional challenge ages. |
| 9470-05 — Combined requirements and scope | Section 3 permits acr_values and max_age together, and optionally a scope attribute when the request also lacks needed scope. Its defined use of the new auth-params is with insufficient_user_authentication. | **No compound step-up challenge.** Existing [authentication responses] expose none of these challenge attributes. Configured authorization scopes/prompts in the [request factory] are independent of any response from a protected resource. | Meeting one requirement does not establish that the other was satisfied. Configured scopes or ordinary authorization denial cannot be credited as this negotiated challenge flow; the RFC does not require a built-in risk/policy engine. |

Normative references for these entries: [protocol overview](https://www.rfc-editor.org/rfc/rfc9470.html#section-2),
[challenge parameters](https://www.rfc-editor.org/rfc/rfc9470.html#section-3).

### Client reaction, OIDC authorization and error handling

| Entry / feature | Specification requirement or boundary | Current implementation / evidence | Assessment / consequence |
| --- | --- | --- | --- |
| 9470-06 — Consume the resource challenge | Section 4 says the client SHOULD parse acr_values/max_age from a challenge carrying insufficient_user_authentication and use present values in a new authorization request conveyed through the user agent. | **Not implemented.** The [outbound orchestrator] returns request credentials, not an interactive recovery result. [WebClient security propagation] applies those credentials and directly returns chain.proceed(request); it does not inspect the remote response for step-up. The [endpoint client]'s UserInfo consumer also has no such challenge handling. | Outbound propagation alone cannot recover from a downstream RFC9470 challenge. This is an absent extension, not a claim that every OAuth/OIDC client must implement every optional extension. The normative client behavior here is SHOULD, not MUST. |
| 9470-07 — Requested ACR/age through the authorization pipeline | Section 4 reuses OIDC's optional acr_values/max_age authorization parameters; it does not introduce a different authorization grant or redefine those parameters. | **No first-class request support.** [Authorization configuration] and the [request factory]'s parameter builder support scopes, prompts, resources, nonce and PKCE, but not acr_values/max_age. The [authentication request state] retains no corresponding requirement. Existing JAR/PAR processing reuses the constructed parameter set; it does not add the missing values. | A query suffix manually placed on an endpoint URI is not a challenge-aware, state-bound implementation and is not offered as a supported workaround. A future feature should integrate with the common authorization-parameter pipeline, including signed/PAR forms, rather than creating a second flow. |
| 9470-08 — Existing sessions and prompt=login | Sections 2 and 4 require a new authorization interaction to obtain suitable credentials after a step-up demand. OIDC Core equates max_age=0 with prompt=login for OP reauthentication; credential expiry and refresh are different events. | **Related prompt support, no step-up trigger.** The [request factory] emits configured prompts; [provider tests] cover login/consent serialization. The [authentication orchestrator] accepts a valid permitted local cookie before starting another authorization request. Its refresh path responds to token lifetime, not a resource's authentication-age/strength demand. | Configuring prompt=login is useful for fixed reauthentication requests that actually start; it does not itself invalidate an accepted local session or implement dynamic ACR/nonzero-age policy. Cookie clearing/logout is not equivalent to a scoped step-up continuation and is not recommended here as a substitute. |
| 9470-09 — ID Token semantics versus resource acceptance | Section 5 preserves OIDC's voluntary acr_values behavior for ID Tokens and the requirement on the OP to include auth_time when max_age is used. For this protocol's access tokens, the AS SHOULD treat the requested ACR as necessary to satisfy the authorization request. | **Ordinary ID Token validation, no requested-assurance policy.** The [ID Token validator] checks signature and ordinary issuer/audience/time/nonce rules but has no expected ACR or requested max_age input. The [subject mapper] preserves ID Token acr/auth_time/amr when merging UserInfo; preservation is not a comparison with requested requirements. | Do not label a nonmatching voluntary ID Token ACR an unconditional OIDC MUST violation. Conversely, a valid ID Token or UserInfo claim is not proof that a downstream access token satisfies the resource's policy. AS token issuance/enforcement belongs to the external OP; no unsupported step-up validation is credited. |
| 9470-10 — Unmet authentication error | Section 5 recommends failing authorization with unmet_authentication_requirements when the required access-token ACR cannot be achieved, to avoid repeatedly returning unsuitable tokens. This is distinct from the resource's insufficient_user_authentication challenge. | **Generic safe callback failure is available.** The [callback processor] accepts a syntactically valid error after state/issuer checks, without restricting it to a fixed enum. Thus this error is source-covered by the generic branch. The [HTTP feature] stops before code exchange, clears returned state cookies and returns a generic400 error page; [callback tests] exercise the branch with access_denied. | No special unmet-authentication UX or automatic recovery exists, but a new enum is not necessary merely to fail safely. This is not a completed RFC9470 flow, and the exact unmet_authentication_requirements case was not executed. The AS's recommended failure behavior must not be recast as a new RP-issued error obligation. |

Normative references: [client authorization request](https://www.rfc-editor.org/rfc/rfc9470.html#section-4),
[authorization response and AS behavior](https://www.rfc-editor.org/rfc/rfc9470.html#section-5).

### Authentication evidence, metadata and token lifecycle

| Entry / feature | Specification requirement or boundary | Current implementation / evidence | Assessment / consequence |
| --- | --- | --- | --- |
| 9470-11 — Authentication context in JWT access tokens | Sections 6/6.1 use access-token acr and auth_time to convey the actual user-authentication context/time to the resource server. Issuing these claims is the AS's responsibility; evaluating the resource requirement is the RS's responsibility. | **Claims can reach application policy; no built-in step-up evaluation.** The [JWT access-token validator] applies existing token validation, then the [subject mapper] exposes payload claims as principal attributes and the parsed JWT in TokenCredential. No accepted-ACR/maximum-authentication-age comparison is performed. | This is useful evidence plumbing in the RS role, not complete RFC9470 support. An application enforcing these requirements must check claim presence, type and meaning under its trusted issuer's policy. An RP must not substitute its ID Token's ACR for a resource's access-token evidence. |
| 9470-12 — Authentication context through introspection | Section 6.2 defines top-level acr as a string and auth_time as JSON numeric epoch seconds in introspection responses. Opaque access tokens can participate; a JWT-only approach is not required. | **Raw extension claims preserved, no typed step-up contract.** [Introspection access-token validator] validates the response's supported token fields. [Validated introspection] retains the full JSON; [subject mapper] exposes it in TokenCredential and principal attributes. Its internal JWT adapter maps ordinary claims, not acr/auth_time. | Correctly typed acr/auth_time values can be consumed by application policy without decoding the opaque token. The module does not validate these extensions' types or enforce an ACR/age threshold. Keeping the fields is not an assertion of their step-up acceptability, and unsupported-field tolerance alone is not a demonstrated bypass. |
| 9470-13 — Renewal is not new user authentication | Section 6.1 states that the access token's authentication-time/context values originate at user authentication and do not change merely because tokens are renewed. Token issuance time and active user-authentication time are different. | **Related ID Token continuity guard, not full access-token continuity enforcement.** [ID Token validator] compares a refreshed ID Token's auth_time with the current claim when the refreshed token includes it. [Refresh tests] cover a matching value and rejection of a changed value. [Refresh manager] retains the existing ID Token when no replacement is returned; it does not manufacture auth_time from the refresh time. | This guard concerns ID Tokens, not an RFC9470 comparison of old/new access-token acr/auth_time. A new ID Token may omit auth_time; there is no step-up policy requiring it. Optional refresh access-token validation is a separate configured path, not active user reauthentication or an ACR upgrade. |
| 9470-14 — AS capability metadata | Section 7 uses acr_values_supported from OIDC Discovery in AS metadata to signal understanding/honoring of acr_values and max_age. It does not introduce a separate max_age capability flag or require a particular OP authentication mechanism. | **Not consumed.** [Discovery metadata model] does not retain acr_values_supported and [tenant metadata validation] has no step-up negotiation/configuration branch. Other supported metadata, including PKCE/PAR/JAR, does not imply this capability. | An OP publishing the field does not automatically enable step-up in Helidon. Ignoring a currently unsupported extension is not itself a base-metadata violation. If implemented later, retain/validate the published ACR list without assuming that it defines a universal ordering or grants authorization. |
| 9470-15 — Opaque credentials and multiple token choices | Section 2 leaves caching to the application, notes that old/new tokens can suit different operations, and warns clients against examining access-token contents to infer authentication information during token selection/caching. A higher-context token need not replace all older tokens. | **Single-session token storage, no step-up token portfolio.** [Local authentication result] stores one access token and Token Endpoint lifetime/scope information. Local [subject mapper] propagation supplies that raw access token without attaching a decoded access-token JWT. The [outbound orchestrator]'s optional audience filter uses separately attached JWT/introspection evidence rather than decoding raw tokens. | No authentication-level-based token selection is implemented. A single slot is not an RFC violation: the RFC mandates no caching strategy. Resource-side validated claims are legitimate RS evidence, not permission to decode arbitrary RP tokens. The separately configured refresh validator is not credited as a step-up cache/selection algorithm. |

Normative references: [JWT authentication-event claims](https://www.rfc-editor.org/rfc/rfc9470.html#section-6.1),
[introspection extensions](https://www.rfc-editor.org/rfc/rfc9470.html#section-6.2),
[AS capability metadata](https://www.rfc-editor.org/rfc/rfc9470.html#section-7),
[token opacity and caching boundary](https://www.rfc-editor.org/rfc/rfc9470.html#section-2).
Supporting OIDC distinctions: [authorization request parameters](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
and [RP ID Token checks](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation). Core's requested ACR/auth_time
checks are SHOULDs; this pass does not turn the missing optional request feature into an unconditional MUST violation.

### Completion, deployment and security boundaries

| Entry / feature | Specification requirement or boundary | Current implementation / evidence | Assessment / consequence |
| --- | --- | --- | --- |
| 9470-16 — Resume and reevaluate the resource operation | Section 2 completes the interaction by retrying the protected-resource request with the new token and having the resource server evaluate that token's authentication event against its requirements. A successful OP round trip alone does not finish it. | **No resource-operation continuation.** The [authentication request state] stores the original local URI, not a challenged downstream request/resource/ACR/age bundle. After ordinary login the [HTTP feature] returns a303 to that local URI; [WebClient security propagation] has no post-challenge retry operation. | A browser redirect back to an RP page is not proof that the original API call succeeded. Replayability of an application's operation and selecting the proper resource-bound token need explicit integration; the RFC does not prescribe a generic HTTP request-body replay engine. |
| 9470-17 — Deployment policy and Helidon suitability | Sections 2, 3 and 8 leave risk decisions, accepted contexts, achievable authentication methods and the detailed user experience to the deployment. The RFC cannot make incompatible RS/AS policies or unavailable user factors satisfiable. | **Application/OP responsibilities, not framework impossibility.** Helidon already acts as an OIDC RP and protected-resource provider, but [endpoint policy configuration] chooses credentials/failure response rather than an authentication-strength policy. User interaction and token issuance remain external OP behavior. | This feature could fit Helidon with explicit client/RS integration; lack of native challenge support must not be dismissed as an AS-only feature. Equally, Helidon need not become an OP, define a universal assurance ranking or implement an MFA mechanism to participate. Service-only credential acquisition is not user reauthentication. |
| 9470-18 — Disclosure in authentication challenges | Section 9 warns that disclosed ACR requirements can reveal user/resource/privilege information. An RS MAY challenge before validating the presented token, but doing so exposes policy to a caller who has not proved possession of a valid token. | **No new step-up disclosure path exists in the reviewed implementation.** [Authentication responses] do not expose ACR/age requirements. Their fixed Bearer descriptions and configured realm are existing baseline behavior, not a reviewed RFC9470 policy. | Do not invent a MUST requiring validation before every challenge; the RFC explicitly permits the alternative. If added, the deployment must choose what to reveal and when. This is a design constraint for future support, not a confirmed information leak in an absent feature. |
| 9470-19 — Malicious resources and repeated user interaction | Section 9 highlights abuse by a resource that can trigger user interaction; section 5's recommended AS error behavior helps prevent repeatedly issuing unsuitable tokens. Section 8 allows that requirements can be impossible to satisfy. | **No automatic challenge-induced prompt/retry loop.** There is no response consumer that restarts login; generic authorization errors terminate their callback. Existing issuer/state/nonce protections in [request factory], [callback processor] and [ID Token validator] are useful but do not implement a trusted, bounded step-up continuation. | Any future integration needs deliberate resource/issuer association, application-controlled continuation and bounded recovery. These are derived implementation considerations, not a numeric retry limit mandated by RFC9470. Missing retry code is not an exploitable loop; no attack was executed or inferred solely from absent support. |
| 9470-20 — Registrations and authentication-layer boundary | Section 10 registers insufficient_user_authentication for resource-access errors and acr/auth_time for introspection. Section 9 says this must not position OAuth itself as an authentication protocol; a separate authentication/session layer still exists. | **No server/registration capability is implied.** Generic callback-error syntax can carry an OP error, and raw introspection fields survive mapping, but neither is a complete registered challenge implementation. OIDC remains the user-authentication layer for this provider; it does not issue AS tokens or operate an AS metadata/registration service. | Do not confuse insufficient_user_authentication, unmet_authentication_requirements and insufficient_scope, or claim that generic string/JSON support implements their protocols. No new Helidon IANA registration, standalone JWT review or DPoP support is required by this assessment. |

Normative references: [completed flow](https://www.rfc-editor.org/rfc/rfc9470.html#section-2),
[deployment limits](https://www.rfc-editor.org/rfc/rfc9470.html#section-8),
[security/privacy boundaries](https://www.rfc-editor.org/rfc/rfc9470.html#section-9),
[error registration](https://www.rfc-editor.org/rfc/rfc9470.html#section-10.1) and
[introspection registrations](https://www.rfc-editor.org/rfc/rfc9470.html#section-10.2).

### Practical support summary

| Capability | Current status | Reason / ownership |
| --- | --- | --- |
| Generate/consume the standardized resource challenge | Not supported. | No RFC9470 error/parameter model, resource-response consumer or corresponding RS policy integration. |
| Start authorization with requested ACR/age | Not supported as a first-class feature. | No configuration/request-state input or parameter generation; prompt=login is only a related existing option. |
| Complete browser reauthentication and retry the API operation | Not supported as a coordinated flow. | Ordinary login redirects to the original RP URI, without a protected-resource continuation. |
| Expose JWT/introspection authentication-event claims | Generic building blocks present. | Existing RS mapping preserves claims; application policy must validate and interpret them. |
| Handle an OP authorization error / preserve refresh auth_time | Related support present, with documented limits. | Generic state-checked error handling; returned ID Token auth_time comparison, not an access-token step-up policy. |
| Perform MFA, choose resource risk policy, issue compliant tokens | External responsibility. | OP/AS and resource application responsibilities; not a reason to exclude client-side RFC9470 support. |

The missing client/RS coordination is a meaningful optional feature gap. No default access-control guarantee was found
that promises this coordination and is then bypassed. No new numbered security/protocol finding is promoted. The eight
existing RFC-phase findings remain unimplemented; the following quality observations are separate.

### Code quality, reuse and evidence improvements

- **Public null contract — Rules 1.2.1/1.2.2.** [OIDC provider] deliberately allows authenticate(null) through the
  [authentication orchestrator], and [provider tests].providerWithoutRequestAbstains verifies this together with null
  outbound arguments. This conflicts with the current non-null public API/SPI rules. The inspected [authentication SPI]
  and [outbound security SPI] do not document a requirement to accept null. Align the boundary/tests with
  [Rule 1.2.1](https://github.com/helidon-io/helidon/blob/main/DEV-GUIDELINES.md#rule-1-2-1) and
  [Rule 1.2.2](https://github.com/helidon-io/helidon/blob/main/DEV-GUIDELINES.md#rule-1-2-2), or document an actual
  inherited-contract exception under [Rule 0.1](https://github.com/helidon-io/helidon/blob/main/DEV-GUIDELINES.md#rule-0-1).
  This is an API-contract guideline issue, not a step-up authentication bypass; changing it was not requested here.
- **Blueprint implementation constant — Rule 8.2.** [Protected-resource configuration] declares DEFAULT_CHALLENGE_REALM
  inside its Blueprint, and [authentication responses] reference it. The permanent
  [Rule 8.2](https://github.com/helidon-io/helidon/blob/main/DEV-GUIDELINES.md#rule-8-2) excludes implementation constants
  from Blueprint interfaces because they become public API. Keep the shared default in existing package-private support
  when addressing this; no new one-purpose public helper is warranted.
- **Member order — Rule 2.1.** The [request factory] places non-private static codeChallenge after the instance create
  method and interleaves private static helpers with private instance methods. This conflicts with the permanent
  [Rule 2.1 order](https://github.com/helidon-io/helidon/blob/main/DEV-GUIDELINES.md#rule-2-1). It is maintainability cleanup,
  not RFC9470 behavior, and does not require algorithm changes.
- **Qualified type name — Rule 3.1.** [Authentication orchestrator].authenticate uses the fully qualified
  io.helidon.security.ProviderRequest outside Javadoc with no conflicting imported simple name in that file. A normal
  import would follow [Rule 3.1](https://github.com/helidon-io/helidon/blob/main/DEV-GUIDELINES.md#rule-3-1).
- **Unused exception binding — Rule 1.5.** [OAuth error fields].validErrorUri catches RuntimeException as e without using
  the binding. [Rule 1.5](https://github.com/helidon-io/helidon/blob/main/DEV-GUIDELINES.md#rule-1-5) calls for an unnamed
  binding here; this is a small style correction, not a protocol-error handling defect.
- **Reuse the authorization pipeline if the feature is chosen.** Existing [Common parameters], [Common writable query]
  and [Common query construction] already provide parameter storage and component-safe query encoding used by the
  [request factory]. Carry requirements through that pipeline/state into JAR/PAR instead of duplicating encoding,
  signing or callback validation. Parameters/UriQuery do not parse the distinct WWW-Authenticate grammar; do not present
  either as a drop-in challenge parser. This pass identifies no measured performance problem and recommends no new
  generic Common class, cache or wrapper solely for the absent feature.
- **Document the prompt boundary clearly.** The [module README](README.md#supported-standards-boundary) lists supported
  standards without claiming RFC9470. Its prompt example nevertheless benefits from an explicit note that login prompts
  apply when a new authorization request starts, not when a valid local cookie is accepted. Generic claim exposure and
  refresh continuity should likewise not be advertised as step-up support.

| Evidence inspected | What it actually supports | What it does not establish |
| --- | --- | --- |
| [Provider tests]: missing Bearer challenge/configured realm | Ordinary401 Bearer response fields. | RFC9470 error, combined ACR/age/scope grammar or step-up policy. |
| [Provider tests]: prompt serialization and accepted local cookie | Static prompt construction and existing-session reuse. | Challenge-triggered reauthentication or requested-assurance validation. |
| [Callback tests]: authorizationErrorResponseIsHandledBeforeTokenExchange | State-checked generic error branch with access_denied. | An executed unmet_authentication_requirements interoperability case or tailored recovery UX. |
| [Refresh tests]: matching/changed authentication time | Existing returned ID Token auth_time continuity guard. | A max_age policy, changed access-token ACR detection or a new user-authentication event. |
| [Subject mapper], token validators and metadata source | Claim preservation/exposure and the absence of step-up fields/consumers. | End-to-end step-up conformance or type/policy checks for every preserved extension claim. |

If native support is selected later, focused coverage would need real challenge round trips (including quoted/token age,
multiple contexts, combined requirements and malformed input), browser continuation with an existing local session,
explicit OP failure, unchanged-authentication refresh, incompatible ACR policy, claim provenance and repeated hostile
challenges. JAR/PAR must carry the same selected request constraints. These are future feature-evidence needs, not failed
tests of a currently implemented protocol. The inspected tests use observable behavior/JUnit5/Hamcrest; no tests were run.

### Section traceability and validation limits

| RFC9470 section | Entries | Boundary retained |
| --- | --- | --- |
| 1–2 — purpose, roles, sequence, tokens | 9470-01, 06–08, 15–17. | RP/RS/AS separation; no global ACR ranking or prescribed token cache. |
| 3 — error and auth-params | 9470-02–05, 18, 20. | Authentication strength/age differs from token validity and scope. |
| 4 — client authorization request | 9470-06–09. | SHOULD reaction; existing OIDC optional parameters; no new grant. |
| 5 — authorization response | 9470-09–10, 19. | ID Token voluntary ACR differs from recommended AS access-token behavior. |
| 6–6.2 — access-token evidence | 9470-11–13. | JWT/introspection role, claim types and original authentication event. |
| 7 — metadata | 9470-14. | acr_values_supported; no invented separate max_age discovery flag. |
| 8 — deployment | 9470-03, 16–17, 19. | Policy compatibility and user interaction remain deployment-specific. |
| 9 — security | 9470-15, 18–20. | Opacity, disclosure, abusive user interaction and separate authentication layer. |
| 10–10.2 — registrations | 9470-12, 20. | Resource-error and introspection fields are not AS implementations. |

Method: read the local specification's complete substantive sections 1–10, checked the official edition/status page and
current complete development guidelines, and traced the relevant current source and selected existing test bodies.
Supporting local OIDC Core clauses were checked for prompt/max_age/ACR/ID Token distinctions. Code searches included main,
unit and the two selected OIDC integration trees; HTTP cookie max-age matches were not mistaken for OIDC max_age support.
The guideline review is scoped to the OIDC paths traced here; it is not a new whole-module/build/Common certification.
No runtime tests, live OP/resource calls, browser/MFA interactions, attack/replay probes, benchmarks or exhaustive errata
audit were performed. No runtime/test/Common/legacy source was changed and no feature was implemented. The original
eight-spec OIDC inventory, DPoP exclusion, 210 earlier RFC feature entries and all earlier findings are preserved.

The next dedicated pass, **RFC 8707 — Resource Indicators**, is recorded below, limited to OIDC authorization/token use.

## 11. RFC 8707 — Resource Indicators in OIDC authorization and token requests

Assessed: 2026-09-29. Source: the supplied local RFC8707 and the
[official February 2020 RFC Editor edition](https://www.rfc-editor.org/rfc/rfc8707.html). All substantive sections 1–5
have been read, including examples and registrations. This pass concerns OIDC authorization, code redemption, refresh and
the associated access-token resource boundary. Shared helper callers in other grants are considered only to establish
reuse/impact, not to open separate Client Credentials, Token Exchange or resource-server standards inventories.

**Verdict: configured static resource selection is implemented across the OIDC request lifecycle**, including query,
JAR/PAR, code redemption and refresh. The reproduced resource-URI validation gap 8707-F01 is now resolved. Selecting
different resource subsets/tokens from a multi-resource grant is deliberately not exposed by this static-login model;
that is an optional feature boundary, not another proven security defect. No new token-theft or authorization-bypass
claim is made.

### Resource parameter contract

| Entry / feature | Specification requirement or boundary | Current implementation / evidence | Assessment / consequence |
| --- | --- | --- | --- |
| 8707-01 — Resource versus scope | Sections 1/2 distinguish where a token will be used from what access is requested. Supplying resource is optional; the AS can choose defaults or require an explicit target. | **Explicit configuration supported.** [Authorization configuration] exposes resources through its configured Blueprint/list builder, independently of scopes. [Request factory] and [endpoint client] omit resource when the list is empty; neither derives it from the original RP page URI. | Do not confuse the browser return URI, issuer, OP endpoint, scope or ID Token audience with an API resource. An AS that requires resource can legitimately reject the omitted/default case. |
| 8707-02 — Absolute URI and no fragment | Section 2 requires an RFC3986 absolute URI without a fragment. Scheme syntax is not limited to HTTPS, because the identifier need not be a network locator. | **RFC3986 component validation added.** [Resource indicator validation] still checks Java URI structure, absolute scheme and no fragment, and now checks raw opaque values or hierarchical authority/path/query with [Common URI validation]. This rejects raw Unicode, unescaped path/query brackets, extra userinfo delimiters and nonnumeric ports at configuration time. [Tenant validation] reuses the helper. | See resolved 8707-F01. Valid percent-escaped URNs, reg-names, IPv6 hosts and optional queries remain unchanged, not automatically rewritten. Syntax validation does not establish AS registration or authorization. |
| 8707-03 — Query components and abstract identifiers | Section 2 says resource SHOULD NOT have a query, while explicitly allowing deployments that need one. The identifier may be an abstract URI rather than a dereferenceable URL. | **Supported policy flexibility.** [Resource indicator validation] permits query-bearing values and URNs, without requiring a host or HTTPS scheme. The value is passed as a parameter; the resource helper does not fetch it or use it as the OP request destination. | Query support is not a MUST violation. Keep it deliberate and properly encoded; resolved F01 concerned invalid characters, not the mere presence of a query. Endpoint TLS requirements and resource-identifier syntax are separate concerns; an arbitrary configured resource is not by itself an SSRF path. |
| 8707-04 — Multiple resources and duplicate policy | Section 2 permits repeated resource parameters for multiple target resources. Section 3 encourages a single target and explains the trust implications of multiple audiences. | **Multiple distinct values supported; duplicates rejected locally.** [Resource indicator validation] uses exact string uniqueness; [request factory] adds each resource separately to Common Parameters. [Configuration tests] exercise duplicate rejection. | Duplicate rejection is Helidon configuration hygiene, not a new RFC MUST. Distinct URI spellings are not silently normalized or treated as duplicates. Multiple values do not promise that an AS will issue a multi-audience token; it may reject such a request. |
| 8707-05 — Requested resource versus issued audience | Section 2 recommends AS audience restriction but permits the AS to map a resource URI to a different general URI or abstract audience identifier. The AS owns issuance, mapping and policy. | **No forced resource=aud equality.** The [request factory]/[endpoint client] transmit configured identifiers; [token response] does not decode the access token or insist that aud text equal resource. Existing [token validation configuration] has its own expected audience for its configured validation role. | This separation is correct. A syntactically valid resource is not proof of authorization or audience restriction, and sending it is not a substitute for validation at the receiving resource. Do not add naive equality against the RP's client_id or all requested resource strings. |

Normative references: [parameter and audience mapping](https://www.rfc-editor.org/rfc/rfc8707.html#section-2),
[authorization/default behavior](https://www.rfc-editor.org/rfc/rfc8707.html#section-2.1),
[multi-resource trust](https://www.rfc-editor.org/rfc/rfc8707.html#section-3).

### Authorization transport and grant binding

| Entry / feature | Specification requirement or boundary | Current implementation / evidence | Assessment / consequence |
| --- | --- | --- | --- |
| 8707-06 — Resource applies to the authorization grant | Section 2.1 makes resource in a code-flow authorization request apply to the full authorization grant, unlike its direct-token implicit-flow use. | **Supported selected code-flow profile.** [Request factory] creates response_type=code and includes the configured resource list alongside ordinary state, nonce, PKCE and scopes. [Provider tests].authorizationCodeFlowInitiationCanRequestResources verifies two returned query values. | The authorization grant can cover multiple resources even if a later token covers a subset. Helidon does not implement implicit/hybrid issuance/consumption, and this extension does not require it to add those flows. Grant consent/binding is the AS's responsibility. |
| 8707-07 — Repetition and outer query encoding | Multiple resources are separate occurrences of resource in the ordinary authorization request, not a comma-delimited synthetic identifier. Characters inside each identifier must survive transport without becoming unrelated authorization parameters. | **Correct parameter-container construction.** [Request factory] passes all values to [Common writable query].set and uses rawValue(); [Common query construction] encodes each value and emits repeated name=value pairs. The [code exchange tests] encoding case checks that nested ampersands, plus signs and percent data do not inject extra outer parameters. | This correctly reuses Common and preserves repeated values. Outer query encoding and nested RFC3986 validation are distinct: the resource is validated before it is encoded for transport. Keep rawValue(), not the Common query's diagnostic decoded value() representation that joins values with commas. |
| 8707-08 — Resource in a signed Request Object | Section 2.1 requires a single resource value to be a JSON string and multiple values to be a JSON string array when authorization parameters are represented in a JWT. | **Correct shape in the shared signing path.** [Request object processor] writes a single value as a string and multiple values as a list. [Provider tests].authorizationCodeFlowInitiationCanUseSignedRequestObject verifies a signed resource array and its absence from the outer request parameters. | Resources are inside the secured authorization payload, not an accidental outer-only hint. The exact single-resource branch is source-confirmed; the inspected resource assertion uses multiple values, so it is not claimed as a separate executed singular-resource test. |
| 8707-09 — Plain PAR transport | The same authorization resource semantics apply when a supported back-channel transport submits the authorization parameters. RFC8707 does not itself define PAR. | **Parameters retained.** [Request factory] passes the constructed parameter set to [endpoint client]; copyParameters retains every value. [Form media support] writes one encoded form field per value. [Code exchange tests] include a PAR body with repeated resource values. | PAR changes delivery, not the intended API or authorization-grant scope. The shared validator now checks resource syntax before either ordinary authorization or PAR submission; PAR itself does not correct an invalid URI. |
| 8707-10 — JAR with encryption/PAR | A resource-bearing JWT keeps the section2.1 string/array representation when the supported request is subsequently encrypted or submitted through PAR. | **Shared representation reused.** [Request object processor] signs the resource-bearing payload before optional encryption. For JAR+PAR, [request factory] submits the request object and [endpoint client] supplies authentication fields, rather than duplicating the resource outside the JWT. [Code exchange tests] inspect and verify the signed PAR payload's resource array. | No separate resource serializer or new Common wrapper is needed. Encryption/PAR do not select a narrower target, validate the AS's resource policy or prevent the AS from learning the identifiers. General JWE/JAR conformance remains with the prior scoped passes. |

Normative reference for grant/representation rules:
[RFC8707 authorization request](https://www.rfc-editor.org/rfc/rfc8707.html#section-2.1).
PAR/JAR transport evidence uses already-assessed mechanisms; it does not expand this into another specification pass.

### Code redemption, refresh and scope

| Entry / feature | Specification requirement or boundary | Current implementation / evidence | Assessment / consequence |
| --- | --- | --- | --- |
| 8707-11 — Resource on code redemption | Section 2.2 permits resource at the Token Endpoint, including authorization_code requests; its meaning is the target of the requested access token. | **Implemented.** [Endpoint client].exchangeAuthorizationCode adds every configured authorizationCodeResources value to the POST form together with grant/code/redirect/PKCE fields. [Code exchange tests].authorizationCodeExchangeSendsConfiguredResources checks two values; the ordinary no-resource test checks omission. | Resources are not only a front-channel hint. They survive the back-channel request through Common form encoding. The OP's authorization/token endpoints remain the actual network destinations; resource is not substituted into the request URI. |
| 8707-12 — Resource on refresh | Section 2.2 likewise applies resource to refresh_token requests. The AS decides which targets are acceptable under its policy and the original grant. | **Implemented fixed-list reuse.** [Endpoint client].refreshAccessToken emits the same copied tenant authorization-code resource list; [refresh manager] calls this method. Both [code exchange tests].refreshTokenGrantSendsConfiguredResources and [refresh tests].localAuthenticationRefreshSendsConfiguredResources check the repeated values. | Omitting resources from configuration omits them here too. This is resource-aware refresh, but not an application-call-specific token acquisition API. A changed deployment/OP policy does not make an old refresh token authorize arbitrary newly configured resources. |
| 8707-13 — Narrowing a multi-resource grant | Section 2.2 allows a code/token request to select a subset of originally granted resources; its code-flow example obtains one API token, then uses the full-grant refresh token to obtain a token for another API. The AS may limit acceptable resources to the grant/subset. | **Documented deliberate limitation.** [Authorization configuration] exposes one resources list; [endpoint client] reuses it for authorization-code redemption and every refresh. [Authentication request state] has no per-exchange subset and [local authentication result] has one access-token slot. The [module README](README.md#authorization-code-flow) explains why static login configuration does not identify the application's later resource-specific token needs. | The full multi-resource-grant/per-resource-token example is not implemented. Sending a configured list is allowed; always narrowing or maintaining a token portfolio is not a universal MUST. An AS unwilling to issue multi-resource tokens can reject this profile. Separate app-driven selection would be a feature decision, not a fix for a proven privilege escalation. |
| 8707-14 — Scope/resource combination | Section 2.2 describes the effective request as every requested scope at every requested resource, with AS downscoping where appropriate. It is not a list of independent scope/resource pairs. | **Matches the single-list request model.** [Request factory] emits one configured scope string and repeated resources, rather than inventing a per-resource scope map. The OIDC Token Endpoint code/refresh methods supply resources but have no independent per-operation scope selector. | Configure scopes and targets deliberately: scope A plus scope B and resource X plus resource Y does not by itself mean only A-at-X and B-at-Y. AS policy can reject an unacceptable combination with invalid_target or narrow the issued scope; scope/audience enforcement still belongs to the appropriate token consumer. |
| 8707-15 — Effective scope from token responses | Section 2.2 reiterates that the AS reports the access token's effective scope when it differs from what was requested. Narrowing access-token scope need not reduce the full grant represented by a refresh token. | **Reported scope consumed; no grant/token-portfolio model.** [Token response] validates the returned scope string. [Local authentication result] uses it, falling back to requested scopes when absent; [refresh manager] replaces scope when reported and otherwise retains the stored value. [Subject mapper] derives local scope grants from that result, not unrelated ID Token claims. Existing provider/refresh tests cover these behaviors. | Correct explicit downscoping information is not discarded. However, the stored current-token scope is not a separate record of every resource/scope in the original grant. This pass does not claim that omission handling supplies missing AS evidence or implements all future subset-selection cases. |

Normative reference: [Token Endpoint resource and scope semantics](https://www.rfc-editor.org/rfc/rfc8707.html#section-2.2).
The existing single-token/static-list model is an explicit coverage boundary, not an inferred need to add new public API.

### Errors and receiving-resource trust

| Entry / feature | Specification requirement or boundary | Current implementation / evidence | Assessment / consequence |
| --- | --- | --- | --- |
| 8707-16 — Authorization invalid_target | Sections 2/2.1 use invalid_target for unacceptable, missing, unknown or malformed targets, including an invalid resource/scope combination. The AS decides when the request is unacceptable. | **Generic authorization error handling is compatible.** [Callback processor] validates state/issuer and error syntax without a closed error enum, so invalid_target reaches its normal authorization-error result. [HTTP feature] aborts before code redemption and uses a generic400 page rather than automatically removing resource and retrying. | No special enum is needed just to handle this extension error safely. Exact invalid_target code-flow callback execution was not demonstrated in this pass; existing generic callback tests cover a different error. The end-user explanation is generic rather than a tailored resource-configuration message. |
| 8707-17 — Token Endpoint invalid_target | Sections 2/2.2 allow invalid_target at token issuance for unacceptable targets or combinations; a failure does not grant access to an alternative resource. | **Parsed and failed without a resource-less fallback.** [OAuth error response] accepts the extension code via syntax validation; [endpoint client] returns an error result. Initial OIDC code redemption fails. On refresh, [refresh manager] can retain an unexpired existing token after a non-invalid_grant failure, or remove expired authentication; it does not acquire a new token by stripping the target. | Preserving a previously usable token is not successful issuance for the failed request. A focused [Token Exchange tests] case already uses invalid_target and verifies a single failed shared-client call; that is not a complete RFC8693 review or an executed OIDC refresh/callback test. |
| 8707-18 — Validate the receiving resource's audience | Section 3's token-redirect protection depends on audience restriction at issuance and the recipient enforcing the intended audience. Section 2 allows the AS to map resource to another audience identifier. | **Separate validation available.** [JWT access-token validator] and [introspection access-token validator] use the configured expected audience when [token validation configuration].audienceValidationEnabled is true, which is the default. That expected audience is not derived from authorization-code.resources. | Configure the recipient's actual AS-issued audience, not necessarily the literal resource URI or the RP client_id. Turning audience validation off is an explicit relaxation. This pass verifies the wiring boundary, not every RS validation rule or an AS's issuance policy. |
| 8707-19 — Multiple audiences and minimum target set | Section 3 encourages one resource because any bearer-token recipient in a multi-audience set can reuse that token at the others; such deployment requires substantial mutual trust, and an AS may refuse it. | **Permitted, explicit configuration.** Multiple resources are not enabled implicitly; the [module README](README.md#authorization-code-flow) recommends one target and warns about multi-audience trust. No code forces an AS to create a separate token for each requested resource. | Supporting repeated values is correct, not a blanket safety guarantee. Multiple-resource issuance is not mandatory for the AS, and enabling certificate proof does not itself make unrelated resource policies interchangeable. The documented subset-selection limitation matters for deployments that require one audience per access token. |
| 8707-20 — Resource specificity and tenant isolation | Sections 2/3 recommend the most specific appropriate API base identifier, including tenant-identifying path information where needed to distinguish hosted applications or tenants. | **Deployment-controlled identifiers, preserved as configured.** [Request factory]/[endpoint client] do not collapse resources to the URI authority, discard tenant paths, or derive them from the inbound RP tenant/header/path. [Resource indicator validation] validates syntax policy, not the AS's tenant allocation or access rights. | A broad host identifier can intentionally or accidentally cover more than one resource/tenant. Configure the registered API/tenant identifier; no generic helper can infer the correct consent boundary from the current browser URL. Missing automatic tenant-path inference is not a demonstrated cross-tenant exploit. |

Normative references: [invalid_target and audience mapping](https://www.rfc-editor.org/rfc/rfc8707.html#section-2),
[token request policy](https://www.rfc-editor.org/rfc/rfc8707.html#section-2.2),
[recipient/tenant trust boundaries](https://www.rfc-editor.org/rfc/rfc8707.html#section-3).

### Destinations, privacy and extension boundaries

| Entry / feature | Specification requirement or boundary | Current implementation / evidence | Assessment / consequence |
| --- | --- | --- | --- |
| 8707-21 — Associate an abstract identifier with the right destination | Section 3 favors a network-addressable identifier when feasible and makes the client responsible for out-of-band association between an abstract resource identifier and the endpoint receiving its token. | **Explicit routing, not automatic discovery from resource.** [Outbound orchestrator] uses configured target matching or endpoint policy and applies the tenant TLS requirement to the actual outbound URI. Its optional audience filter uses attached JWT/introspection evidence, not the requested resource string or decoding arbitrary raw tokens. | The operator/application still needs to bind the chosen API/tenant destination to the registered audience. An arbitrary URI identifier cannot prove endpoint ownership. Local RP credentials hold the raw access token, not automatically attached decoded audience evidence; requesting a resource does not by itself make the optional outbound audience filter succeed. |
| 8707-22 — OIDC UserInfo is another token consumer | Resource identifies the intended protected service; section2 permits AS audience mapping. Resource indicators do not redefine OIDC's separate UserInfo endpoint or make every API token valid there. | **Same acquired token, configured OP destination.** [UserInfo support] calls [endpoint client].userInfo with the acquired access token when enabled. That method uses the metadata UserInfo URI, not authorization-code.resources. No UserInfo resource identifier is automatically appended to the grant or token request. | Coordinate the AS registration/issuance policy when both API resource selection and UserInfo are used. Do not automatically substitute the endpoint URI as its audience or broaden the requested target set: the AS may use a different mapping. This is a deployment compatibility boundary, not proof that all resource-restricted tokens break UserInfo. |
| 8707-23 — Privacy and resource disclosure | Section 4 notes that explicit resource information can let the AS observe behavior at finer granularity; section2.2 discusses limiting cross-service disclosure by downscoping. | **No additional privacy claim.** Direct authorization includes resource identifiers in the browser request; PAR carries them in the back-channel parameters, and JAR places them in its payload. A signed-only Request Object is not encrypted; optional encryption/PAR can change browser exposure but the AS still receives the identifiers. [Request factory], [request object processor], [endpoint client]. | Use the appropriate registered API base and avoid needless user-sensitive URI detail. Neither PAR nor encrypting a Request Object prevents AS-side observation. The RFC does not mandate a new resource-obfuscation option, token-cache design or confidentiality mechanism for every resource parameter. |
| 8707-24 — Defaults, metadata and AS resource policy | Sections 2/2.1 let the AS use a default, require an explicit resource or reject an unacceptable resource/scope combination. RFC8707 defines no resource-support discovery flag or registration protocol for a resource catalog. | **Explicit configuration without invented negotiation.** [Discovery metadata model] and [tenant metadata validation] do not gate resource emission on a nonstandard resource-capability flag. [Authorization configuration] supplies the list; AS acceptance remains a deployment contract. | No missing base-RFC metadata field is reported. Empty configuration means no resource parameter, not an inferred UserInfo/audience/default value chosen by Helidon. Vendor resource catalogs/registration rules are not automatically implemented or forbidden by this RFC. |
| 8707-25 — Other grant callers and IANA scope | Section2.2 gives the parameter the same target meaning across token grant types; section5 registers resource for authorization/token requests and invalid_target for applicable errors. This does not require a client to implement every OAuth grant. | **Shared validation/transport, bounded review.** [Outbound policy] reuses [resource indicator validation] for Client Credentials resource lists and a Token Exchange resource. [Endpoint client] already serializes those callers' fields. Generic error handling can carry invalid_target. | This corroborates reuse and F01's shared impact, not full RFC8693/Client Credentials/Device Flow conformance. The OIDC multi-resource refresh-selection limitation is not solved merely because a different outbound grant accepts its own target. No AS issuance/registration service or new IANA registration is implemented by Helidon. |

Normative references: [resource-to-endpoint trust](https://www.rfc-editor.org/rfc/rfc8707.html#section-3),
[privacy](https://www.rfc-editor.org/rfc/rfc8707.html#section-4),
[token request semantics](https://www.rfc-editor.org/rfc/rfc8707.html#section-2.2),
[parameter registration](https://www.rfc-editor.org/rfc/rfc8707.html#section-5.1),
[error registration](https://www.rfc-editor.org/rfc/rfc8707.html#section-5.2).

### Resolved 8707-F01 — Resource URI validation accepted values outside RFC3986

Classification: **configuration-dependent conformance/interoperability gap; not a demonstrated security exploit**.
At the original assessment the gap was confirmed by source and an isolated local diagnostic compiling the unchanged
OidcResourceIndicators helper with JDK25.0.4. No Maven/module test suite or live OP request was executed in that
initial pass; full verification of the later fix is recorded below.

RFC8707 section2 requires the parameter's value to be an absolute URI as defined by RFC3986. The supporting
[absolute-URI grammar](https://www.rfc-editor.org/rfc/rfc3986.html#section-4.3) and
[query grammar](https://www.rfc-editor.org/rfc/rfc3986.html#section-3.4) do not permit raw non-ASCII characters or unescaped
square brackets in a query. Java's URI API intentionally accepts a broader character set and follows its documented
RFC2396-based syntax/deviations; successful parsing and isAbsolute() are not full RFC3986 validation.
[JDK URI character/encoding contract](https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/net/URI.html).

Before the fix, the [resource indicator validation] helper checked blank/padded values, exact duplicates, URI.create(),
isAbsolute() and absence of a fragment. It did not validate the RFC3986 components or convert the identifier to a URI.
The [request factory] and [endpoint client] retain the original strings. [Request object processor] likewise places those
same strings in a signed Request Object. Correctly encoding the containing query/form/JSON does not repair the nested URI:
after decoding that container once, the AS receives the original invalid identifier.

The narrow diagnostic exercised the pre-fix helper, with these results:

| Input resource | Pre-fix helper result | Relevant distinction |
| --- | --- | --- |
| `https://api.example/items` | Accepted. | Ordinary absolute URI control. |
| `urn:example:contacts` | Accepted. | Abstract identifier control; no HTTPS-only restriction is warranted. |
| `https://api.example/items?currency=£` | Accepted. | Raw non-ASCII character; its URI form uses %C2%A3. |
| `https://api.example/items?currency=%C2%A3` | Accepted. | The explicitly percent-encoded URI form is valid. |
| `https://api.example/items?filter[x]=y` | Accepted. | Raw query brackets are outside the RFC3986 query grammar. |
| `https://api.example/items?filter%5Bx%5D=y` | Accepted. | The explicitly percent-encoded query form is valid. |
| `/api` | Rejected. | Existing relative-URI rejection works. |
| `https://api.example/items#fragment` | Rejected. | Existing fragment rejection works. |

The pre-fix [code exchange tests].authorizationRedirectFormEncodesParametersAndRetainsEndpointQuery deliberately used a
resource containing raw £, which was not an RFC3986 URI. It now uses `%C2%A3` inside the identifier and still verifies
that outer parameter encoding preserves the nested resource without parameter injection.

Impact: an explicitly configured value can pass local validation and be sent during login/redemption/refresh, then fail at
an AS enforcing RFC8707 with invalid_target or fail to match its registered URI spelling. Shared [outbound policy] callers
use the same validator. The issue does not bypass AS authorization, does not establish token disclosure/SSRF, and is not
caused by accepting a permitted query component. All-ASCII, correctly escaped ordinary resource identifiers avoid these
demonstrated cases. No live interoperability failure was measured.

**Remedy implemented and committed as `62fb4e161d`:** the existing package-private shared helper retains Java URI structural/absolute/
fragment checks and now validates opaque SSP or hierarchical path/query with [Common URI validation].validateQuery.
A private authority check uses Common validateHost, validates optional userinfo and ASCII-digit port syntax, and keeps
bracketed IPv6 hosts and percent-escaped registered names without relying on JDK parseServerAuthority (which rejects
otherwise valid escaped reg-names). Invalid resource values fail early with the existing configuration-key context;
valid values are passed through unchanged, not silently recoded by URI.toASCIIString(). No Common, legacy, public API or
additional module dependency changed. A pre-fix failing regression now passes; additional tests cover Unicode in the
authority/path/opaque SSP, raw brackets in path/query/URNs, nonnumeric ports and extra userinfo delimiters, and preserve
escaped URNs, queries, hostnames and bracketed IPv6. The module passes 1,612 tests plus static checks; synthetic
integration passes 42 and real-Keycloak passes 18. No strict OP invalid_target response was needed to establish this
configuration-boundary fix, and no live AS audience/registration policy has been certified.

### Practical support and configuration distinctions

| Capability | Current support | Boundary / reason |
| --- | --- | --- |
| One or several configured resources during OIDC login | Implemented. | Values must be chosen for the actual registered API; resolved F01 now validates URI component grammar before emission. |
| Repeated query/form fields; resource in JAR/PAR | Implemented. | Shared encoding/serialization is reused after resource URI validation; outer encoding is not itself nested-URI validation. |
| Resource on code redemption and refresh | Implemented with the same configured list. | No independent per-call selection or resource-keyed local token portfolio. |
| Full multi-resource grant with one API token at a time | Deliberately not exposed by static login configuration. | The application would need to specify which API/token it needs; no universal subset policy can be inferred. |
| Effective scope and invalid_target responses | Existing generic support. | Tailored end-user errors and exact OIDC invalid_target regression coverage are limited. |
| AS audience restriction, consent and target acceptability | External AS responsibility. | Helidon supplies the request but cannot certify an external issuer's policy. |
| Recipient/audience and destination matching | Existing validation/routing building blocks. | Configure the actual AS audience and trusted destination; do not assume resource text equality. |

These identifiers have different purposes and must not be conflated:

| Value | Meaning in this OIDC flow |
| --- | --- |
| authorization-code.resources / wire resource | API(s) for which the RP requests access. |
| Request Object aud | AS/OP receiving the authorization request, not the downstream API list. |
| ID Token aud | RP client identifier(s), not the API resource list. |
| Access-token aud | AS-issued recipient restriction, possibly mapped from the requested resource. |
| Configured access-token validation audience | Recipient identifier expected by the configured validation role. |
| Actual outbound/UserInfo URI | Destination receiving the token; it must be an appropriate recipient under the deployment's mapping. |

[Request factory], [request object processor], [ID Token validator], [token validation configuration], [endpoint client]
and [outbound orchestrator] establish these separate uses. This comparison is not an instruction to inspect arbitrary
opaque RP access tokens to infer their audience.

### Code quality, reuse and evidence improvements

- **Existing component validation reused with appropriate scope.** Resolved F01 remains in the package-private
  [resource indicator validation] class shared by OIDC login and outbound policy callers. [Common URI validation]
  handles raw component characters, supplemented by local authority syntax checks. No generic Common service was added;
  abstract URNs still work. URI.toASCIIString alone was not treated as an RFC3986 absolute-URI validator.
- **Keep the working container pipeline.** [Common parameters], [Common writable query] and [form media support] already
  handle repeated values and outer encoding. Use correctly escaped resource identifiers as data, preserving their percent
  escapes through the container encoding. Do not switch to concatenation, comma-joining or an extra URI-encoding wrapper
  that changes the resource's identity. This pass found no need to duplicate those components.
- **Minor allocation/clarity opportunity.** [Resource indicator validation] uses LinkedHashSet only for add/membership;
  the set is never iterated. HashSet would avoid ordered-entry bookkeeping without changing the input-list order used on
  the wire or the first duplicate encountered. This is configuration-time cleanup, not a measured runtime bottleneck or
  security fix; no benchmark was run and no throughput benefit is claimed.
- **Member order — Rule 2.1.** [Token response] declares its private static create helper before its non-private instance
  accessors. The permanent [Rule 2.1 order](https://github.com/helidon-io/helidon/blob/main/DEV-GUIDELINES.md#rule-2-1) places
  those accessors before private static helpers. This is a separate maintainability observation, not a protocol defect.
  Prior request-factory/request-object ordering observations are not promoted again as new findings.
- **API documentation accuracy.** [Authorization configuration].resources Javadoc mentions only the Authentication
  Request, while the endpoint client and current README deliberately apply the list to code and refresh token requests
  too. Align the generated API-facing description with that documented behavior and the lack of subset selection.
  The README now explains the corrected RFC3986 resource syntax and preservation of explicitly escaped identifiers.
- **Focused evidence additions, not a new framework.** Existing repeated-value/PAR/JAR tests were retained, the broad
  encoding regression now uses a valid escaped resource and the shared-validator regressions cover raw versus escaped
  non-ASCII/brackets, URN/query/IPv6 identifiers and existing fragment/relative rejection. Separate useful follow-up
  would explicitly test the single-resource JWT string shape and invalid_target on the OIDC callback/code/refresh paths,
  without relying solely on the shared outbound grant's error test. Unsupported per-resource token selection is not a
  failing test of an implemented
  feature. Use observable-behavior tests and existing JUnit5/Hamcrest conventions
  ([Rule 10.1](https://github.com/helidon-io/helidon/blob/main/DEV-GUIDELINES.md#rule-10-1),
  [Rule 10.4](https://github.com/helidon-io/helidon/blob/main/DEV-GUIDELINES.md#rule-10-4));
  no production visibility change or one-use public helper is needed for these checks.

| Evidence inspected or executed | What it establishes | Limit |
| --- | --- | --- |
| Initial isolated ResourceUriDiagnostic against the pre-fix helper | F01 acceptance of raw £/query brackets; escaped URI/URN controls; relative/fragment rejection. | Historical JDK25.0.4 helper-level evidence; the fixed helper is separately tested below. |
| [Configuration tests].authorizationCodeFlowRejectsInvalidResources and authorizationCodeFlowRejectsInvalidResourceUriGrammar | Existing blank/padded, relative, fragment and duplicate assertions plus the new raw-bracket rejection. | Both cases pass in the full module suite. AS-side registration is outside these tests. |
| [Provider tests] resource and signed Request Object cases | Repeated resources and the signed multi-resource array. | Exact singleton resource assertion needs focused coverage. Inspected, not run. |
| [Code exchange tests] query encoding, PAR/JAR and code/refresh resource cases | Correct outer encoding and repeated values across these paths, now with valid `%C2%A3` inside the nested resource URI. | Full module suite passes; no live AS audience/grant policy is certified. |
| [Outbound policy tests] raw/escaped URI matrix | Invalid raw Unicode, brackets, port and userinfo syntax fail early; valid URNs, escaped hosts, query and IPv6 remain unchanged. | Initial invalid case failed before the fix; both positive and negative regressions pass after it. |
| [Refresh tests] resource emission and scope/refresh-token preservation | Fixed-list refresh and existing stored-value behavior. | No different-subset/per-resource-token lifecycle. Inspected, not run. |
| [Token Exchange tests] invalid_target fixture | Shared error transport yields a failure without retry in that test. | Not an executed OIDC callback/refresh error test or a separate RFC8693 audit. |

### Section traceability and validation limits

| RFC8707 section | Entries / finding | Boundary retained |
| --- | --- | --- |
| 1–1.2 — purpose and terminology | 8707-01, 05, 21–22. | Resource, scope, issuer/RP audience and endpoint roles differ. |
| 2 — parameter/value/audience/error | 8707-01–05, 16–18, 24; 8707-F01. | Absolute URI grammar, query exception, optionality and AS mapping. |
| 2.1 — authorization | 8707-06–10, 13, 16. | Full grant, string/array JWT representation, defaults and AS rejection. |
| 2.2 — token request | 8707-11–15, 17, 25. | Same-list implementation versus subset example; effective scope and AS policy. |
| 3 — security | 8707-18–22. | Audience enforcement, tenant-specific bases, multi-resource trust and destination association. |
| 4 — privacy | 8707-14–15, 23. | AS observation and data minimization without invented mandatory encryption. |
| 5–5.2 — registrations | 8707-16–17, 25. | Parameter/error support is not AS issuance or every OAuth grant. |

Method: read all substantive local RFC8707 sections1–5, checked the official edition, complete current development
guidelines and relevant current configuration/request/token/consumer source. Consulted only the necessary official
RFC3986 grammar and JDK URI API text for F01, plus the current Common reuse catalog and component implementations.
Existing selected unit-test bodies were inspected. One narrow diagnostic was compiled and executed in an isolated /tmp
directory using the unchanged production helper and JDK25.0.4; it made no network requests. No project unit/integration
suite, live OP/resource/registration call, interception/replay test or benchmark was executed. No exhaustive errata review
or full-JDK compatibility claim is made. In the original pass no runtime/test/Common/legacy source was changed; the later
8707-F01 remediation is recorded above. The original eight-spec OIDC inventory, DPoP exclusion, 230 earlier RFC feature
entries and all earlier findings remain preserved. The baseline pass added one conformance/interoperability finding.

The last approved dedicated pass, **RFC 9396 — Rich Authorization Requests**, is recorded below, limited to OIDC combination.

## 12. RFC 9396 — Rich Authorization Requests alongside OIDC

Assessed: 2026-09-29. Source: the supplied local RFC9396 and the
[official May 2023 RFC Editor edition](https://www.rfc-editor.org/rfc/rfc9396.html). All substantive sections1–14 and
AppendixA.1–A.4 have been read in five bounded slices. This pass evaluates RAR when combined with OIDC authorization,
associated token requests/responses and the necessary consumer boundaries. It is not a new payment/signing/healthcare
profile, generic AS implementation or standalone resource-server inventory.

**Verdict: RAR is not implemented as an end-to-end feature.** The current
[module coverage boundary](README.md#provider-coverage-matrix) already lists it as unsupported/queued. Source tracing finds
no first-class authorization_details request input, token-response data path or lifecycle. Existing JSON, PAR/JAR, generic
errors and claim mapping are useful pieces, not RFC9396 support. This is a missing optional capability, not a new confirmed
security/protocol defect in an advertised RAR implementation. It could fit Helidon's RP/RS roles with application-specific
data/policy integration; unlike DPoP, the user has not decided to exclude it. No feature implementation is scheduled here.

### Detail objects, types and permission semantics

| Entry / feature | Specification requirement or boundary | Current implementation / evidence | Assessment / consequence |
| --- | --- | --- | --- |
| 9396-01 — Typed authorization-detail array | Section2 defines authorization_details as a JSON array of objects, each with a REQUIRED string type selecting that object's authorization-detail definition. Even one detail is represented within the array. | **No RAR request model.** [Authorization configuration] has scopes/prompts/resources but no detail-array option; [request factory] builds only its supported fixed parameters. [Authentication request state] stores ordinary transaction bindings, not requested RAR data. | This is a concrete optional capability gap, not a malformed implementation of a feature that is advertised as supported. Generic JSON availability does not supply the request/lifecycle contract. |
| 9396-02 — Repeated types and object boundaries | Section2 permits several entries with the same type; separate objects can describe different accesses in the same API. | **No dedicated handling.** There is no detail-array input or grouping/selection policy in [authorization configuration] or [request factory]. Current scope/resource lists do not express these objects. | A future model must not key details only by type or merge all same-type fields. Preserving each object can be necessary to preserve the requested authority; absence of such a model is not evidence that current code incorrectly merges RAR requests. |
| 9396-03 — Type naming and namespaces | Section2.1 leaves type interpretation to the AS/API definition. Easily copied, unambiguous identifiers and, for cross-server APIs, collision-resistant namespaces are RECOMMENDED. A URI is one option, not a requirement for every type. | **No built-in type catalog or type-URI resolver.** [Discovery metadata model] has no RAR type field; [authorization configuration] exposes no type negotiation. | Do not require all type values to be HTTP URLs, ASCII-only strings or automatically fetched schemas. Those would exceed the base requirements. Names/schema meanings are application/AS contracts; this is not inherently unsuitable for a general OIDC client. |
| 9396-04 — Common fields and extensibility | Section2.2 offers optional common fields: locations/actions/datatypes/privileges are string arrays and identifier is a string. Type definitions may include their own nested extension fields. The RFC does not require every API to use all common fields. | **No type-specific or common-field RAR implementation.** Existing [request factory] scope/resource fields are unrelated scalar/list parameters; the module has no policy interpreting these detail objects. | A generic client representation should preserve supported extension JSON rather than reducing everything to a fixed five-field class. locations values are only typically URIs under this base RFC; do not blindly apply RFC8707's mandatory absolute-resource-URI rule to every type's field. |
| 9396-05 — Product within an object, separate grants across objects | Section2.2's common-field combination requests the product of an object's actions/locations/datatypes. Separate objects can express, for example, read contacts and write photos without granting write contacts. Access across objects is their union. | **Not modeled or enforced.** [Subject mapper] has generic role/scope/claim handling, not a RAR interpretation that retains action/data/location associations. [Request factory] does not construct RAR objects. | Flattening objects into global roles or independent lists could broaden permissions in a future design. No such RAR flattening is performed by the default implementation today, and no bypass is inferred from a hypothetical implementation. |
| 9396-06 — Validate each type under its definition | Section5 requires the AS to reject unknown types, unknown fields within a known type, wrong field types/values and missing required fields with invalid_authorization_details. Meaning comes from the type definition. | **AS duty, not an implemented Helidon type validator.** This provider is the RP/client and can also authenticate protected-resource tokens; it does not run the external AS's type registry, consent UI or authorization issuance. Existing token/ID Token validation is not equivalent to this request-schema/policy validation. | Do not turn the AS's MUST into a requirement that this RP ship every payment or healthcare schema. A future client can provide structural/type-contract support while the appropriate AS/RS owns business authorization. Unknown-field handling at an AS must follow the selected type, not arbitrary generic JSON acceptance. |

Normative references: [detail-array/type definition](https://www.rfc-editor.org/rfc/rfc9396.html#section-2),
[type identifiers](https://www.rfc-editor.org/rfc/rfc9396.html#section-2.1),
[common fields and combinations](https://www.rfc-editor.org/rfc/rfc9396.html#section-2.2),
[AS rejection rules](https://www.rfc-editor.org/rfc/rfc9396.html#section-5).

### Authorization transport and OIDC composition

| Entry / feature | Specification requirement or boundary | Current implementation / evidence | Assessment / consequence |
| --- | --- | --- | --- |
| 9396-07 — Authorization request encoding and input | Section3 permits authorization_details in authorization-request contexts and defines ordinary OAuth request encoding as form-encoding the serialized JSON. Consent may cover less than requested. | **No first-class input/emission.** [Authorization configuration] and [request factory] do not accept or construct a details array; [authentication request state] retains no requested detail/transaction data. [Common parameters], [Common writable query] and [form media support] are existing transport pieces. | Hand-appending JSON to a configured authorization-endpoint URI is not a supported end-to-end, state-aware RAR integration. Adding an encoding helper alone would not implement requested/granted data handling. This pass does not require new Device Flow/CIBA grants merely because the RFC lists them as other contexts. |
| 9396-08 — JAR/PAR are reusable transports, not automatic RAR support | Sections3/11.4/12 discuss carrying details securely/reliably using PAR and Request Objects. The structured array/object meaning must survive the applicable representation. | **Useful transport stack, missing structured-parameter integration.** [Request object processor] currently turns Common Parameters values into a JSON string or list of strings. [Endpoint client] can copy/form-encode PAR parameters. Neither constructs the missing detail array. [Helidon JSON arrays] and [JWT claim conversion] can preserve native JSON values when explicitly used. | A form parameter holds serialized JSON text; that does not mean the JWT claim should become a string containing escaped JSON, nor an array of JSON strings. Supporting a structured extension needs deliberate JSON handling through signing/encryption/PAR, not a claim that the current string copier already implements it. No unsupported RAR payload is emitted by the default code today. |
| 9396-09 — Coexistence with scope and OIDC | Section3.1 allows independent scope and authorization_details requirements together; the AS MUST process/present their combined requirements. It is RECOMMENDED that a given API use one form. AppendixA.1 explicitly permits openid plus OIDC claims beside authorization_details. | **Ordinary OIDC scope support only.** [Request factory] includes configured scopes with openid, and existing OIDC processing remains independent of RAR. No details are emitted. | RAR need not replace OIDC authentication or remove its required ID Token/state/nonce checks. The AS's merged consent is not an RP UI requirement. The recommendation to use one form per API is not a ban on mixing an OIDC login with fine-grained authorization for another API. |
| 9396-10 — Resource does not filter authorization_details | Section3.2 says resource can further determine where requested scope applies but has no impact on the AS's processing of authorization_details. Type-specific locations inside a detail can identify its intended RSs. | **Resource support is separate.** [Request factory]/[endpoint client] implement configured resource parameters, while neither has a details input. [Resource indicator validation] applies to those RFC8707 parameters, not arbitrary nested RAR fields. | Do not credit resource indicators as RAR support, or assume a resource value would narrow every detail object. The type's locations/other semantics require their own treatment; broad flattening or blind reuse of URI rules would be a future design mistake, not current implemented behavior. |
| 9396-11 — Authorization response is unchanged | Section4 introduces no authorization-response extension. The ordinary response still needs its applicable protocol validation; authorized details are returned through token/RS channels instead. | **Existing response machinery reusable.** [Callback processor] validates ordinary code/error, state, redirect and issuer handling. [HTTP feature] performs code redemption; it does not expect a new front-channel RAR authorization_details response field. | Lack of such a callback field is correct and not a missing requirement. Reusing the callback does not supply token-response details, consent outcome processing or type policy. No new response_type or RAR callback endpoint is prescribed by this RFC. |
| 9396-12 — Authorization invalid_authorization_details | Section5 requires this AS error for the defined type/schema/value failures. A client needs to fail the authorization attempt rather than treating rejected requirements as consented. | **Generic safe error branch, no tailored RAR UX.** [Callback processor] accepts syntax-valid error codes without a fixed enum. invalid_authorization_details therefore fits its generic authorization-error path; [HTTP feature] terminates with a generic400 page before code exchange. [Callback tests] exercise that branch using access_denied. | A dedicated enum is not required just to reject safely. The exact RAR error was not executed or found in the inspected tests. No client-side business-schema validator, consent downgrade retry or successful RAR grant is implied. |

Normative references: [request/encoding](https://www.rfc-editor.org/rfc/rfc9396.html#section-3),
[scope coexistence](https://www.rfc-editor.org/rfc/rfc9396.html#section-3.1),
[resource separation](https://www.rfc-editor.org/rfc/rfc9396.html#section-3.2),
[unchanged response](https://www.rfc-editor.org/rfc/rfc9396.html#section-4),
[error response](https://www.rfc-editor.org/rfc/rfc9396.html#section-5),
[large-request transports](https://www.rfc-editor.org/rfc/rfc9396.html#section-11.4).
Supporting representation context: [JAR Request Object claims](https://www.rfc-editor.org/rfc/rfc9101.html#section-4).

### Token requests, granted details and refresh

| Entry / feature | Specification requirement or boundary | Current implementation / evidence | Assessment / consequence |
| --- | --- | --- | --- |
| 9396-13 — Select details at token issuance | Section6 permits a token request to specify authorization_details for the new access token. The AS checks them against the underlying authorization/refresh grant or applicable client policy. | **Not exposed.** [Endpoint client]'s OIDC code/refresh methods submit the supported grant, credential, PKCE and configured resource fields, but take no details input. [Refresh manager] likewise supplies no per-operation detail selection. | Resource-aware refresh is not RAR downscoping. There is no supported request for a selected action/object subset of the original consent. The extension's applicability to other grants does not require adding all such grant implementations to an OIDC RP. |
| 9396-14 — Compare authority, not generic JSON subsets | Section6.1 explicitly provides no universal comparison algorithm: one API's write may subsume read, and omissions/privileges can have type-specific meaning. Reducing a token's permissions does not necessarily reduce the original grant. | **No RAR comparison/grant model.** [Authentication request state] and [local authentication result] have no requested/consented detail model. Existing JSON equality, string lists, scopes or role names are not used as a RAR subset validator. | Do not implement generic JSON containment, lexicographic ordering or action-name assumptions as authorization policy. API-specific comparison belongs with the responsible AS/RS/type contract; generic transport support could remain separate. No current false-comparison vulnerability is asserted. |
| 9396-15 — Return and retain effective granted details | Section7 requires the AS to return the authorization_details assigned to the access token. Without a token-request details parameter, the AS chooses them at its discretion; a client cannot assume requested details equal the result. | **Top-level Token Endpoint details are not retained.** [Token response] reads only its listed access/ID/refresh/type/lifetime/scope fields. [Local authentication result] and [refresh manager] therefore receive no granted-detail array from that response. | Sending RAR data alone would not give applications the effective rights returned by the AS. The missing data path is a support gap; ignoring an unrecognized response extension is not itself a proven security defect in the currently advertised ordinary OIDC flow. Do not recover this missing response field by decoding arbitrary opaque RP tokens. |
| 9396-16 — Enrichment, partial disclosure and JSON structure | Sections7/7.1 allow type-defined enrichment and omission of values when returning details to the client; user consent can also be narrower. Returned details remain structured data, not a textual copy of the request. | **No enrichment-aware response surface.** The [token response] parser omits the field entirely. [Helidon JSON arrays] and [JSON object access] can represent such values, but are not currently wired into this response/state path. | A future client must preserve appropriate returned values without unconditional request/response equality or rejecting permitted enrichment as an escalation. Type definitions determine what additions/omissions mean. RAR does not introduce a new token_type; Bearer-only OIDC token handling is not the reason this field is missing. |
| 9396-17 — Token invalid_authorization_details | Section8 applies the section5 type/schema/value rejection rules to token requests. Rejected requested details do not become newly granted rights. | **Generic token-error failure is available.** [OAuth error response] accepts a syntax-valid extension error and [endpoint client] returns an error result. [HTTP feature] fails initial token acquisition. [Refresh manager] treats it as a non-invalid_grant error, retaining a still-usable old session/token or removing expired authentication, without retrying after stripping requested details. | Generic handling is not type-aware RAR recovery. A previous unexpired credential is distinct from successful issuance for a failed request. Existing [code exchange tests] exercise error parsing with invalid_grant; exact RAR token/refresh cases were neither found nor run. |
| 9396-18 — Transaction and session lifecycle | RAR distinguishes request, consented grant and access-token rights; examples support transaction-specific permissions and later reduced tokens. A successful login alone does not prove a business action was authorized. | **Ordinary OIDC session lifecycle only.** [Authentication request state] binds the OIDC transaction, and [local authentication result] stores token/session values plus optional UserInfo. There is no RAR operation handle, response-details state or association between a particular business request and its granted authorization object. | Existing state/nonce/cookie handling can be reused, but no transaction authorization guarantee is added by this inventory. Retention, application continuation and selection of effective details need a feature design; neither a new generic token portfolio nor expanded cookie storage is mandated by the base RFC. |

Normative references: [token requests](https://www.rfc-editor.org/rfc/rfc9396.html#section-6),
[type-specific comparison](https://www.rfc-editor.org/rfc/rfc9396.html#section-6.1),
[effective token details](https://www.rfc-editor.org/rfc/rfc9396.html#section-7),
[enrichment](https://www.rfc-editor.org/rfc/rfc9396.html#section-7.1),
[token errors](https://www.rfc-editor.org/rfc/rfc9396.html#section-8).

### Resource evidence, metadata and deployment roles

| Entry / feature | Specification requirement or boundary | Current implementation / evidence | Assessment / consequence |
| --- | --- | --- | --- |
| 9396-19 — Details in JWT access tokens | Section9.1 RECOMMENDS top-level authorization_details in JWT access tokens, filtered for the audience. This carries rights for the RS, not a new ID Token authentication rule. | **Generic claim exposure, no RAR validator/policy.** [JWT access-token validator] applies its supported token checks. [Subject mapper] attaches the parsed JWT/SignedJwt to TokenCredential, preserving the raw JSON claim if present. It also exposes attributes via [JWT claim conversion], which serializes arrays/objects to JSON text. | Applications can reach authenticated issuer data, but a principal attribute is not a typed array of validated RAR objects. No required type/schema/permission interpretation is performed. Basic token authentication does not by itself authorize a payment, file operation or other type-specific action. |
| 9396-20 — Details through introspection | Section9.2 says that, when the AS includes these details in an introspection response, they MUST be in top-level authorization_details with the section2 structure, potentially filtered/extended for that RS. | **Raw JSON retained, RAR semantics absent.** [Validated introspection] keeps the full response JsonObject. [Subject mapper] attaches it to TokenCredential and stringifies structured principal attributes. Its internal ordinary-claim JWT adapter does not map this extension; the original response remains available. | Opaque access tokens can carry RAR evidence through this channel, but retaining arbitrary JSON is not validating a detail array or enforcing its rights. No standalone introspection-profile review or automatic role conversion is implied. |
| 9396-21 — Make granted rights available to the right RS | Section9 requires the AS to make approved details available to RSs; JWT/introspection are offered mechanisms. Section13 calls for need-to-know disclosure. Recipient/audience restrictions are not interchangeable with checking individual detail permissions. | **Existing recipient checks only.** [Token validation configuration] and the JWT/introspection validators support their configured audience validation. There is no RAR-type/locations policy that determines which detail objects authorize a particular operation. | The RFC does not require every access token to contain the literal claim regardless of its encoding/other AS-to-RS mechanism. An RS still needs the relevant effective authorization information and application policy. No new default bypass is inferred solely from absent RAR enforcement. |
| 9396-22 — AS-supported type advertisement | Section10 defines authorization_details_types_supported in AS metadata as a JSON array of supported types. Advertising capability does not construct a client request. | **Not consumed/negotiated.** [Discovery metadata model] does not retain this field, and [tenant metadata validation] has no RAR preflight or configuration branch. Existing PAR/JAR metadata covers transport capabilities, not supported detail types. | Ignoring a presently unsupported extension is not a base-discovery defect. Future support should distinguish AS capability, client intent and any deployment-specific type agreement rather than enabling requests merely because metadata lists a type. |
| 9396-23 — Client registration metadata and type registration | Section10 permits clients to advertise authorization_details_types as a JSON array. Registering type definitions with the AS is outside this RFC's scope. | **External setup, not implemented registration automation.** This provider has no dynamic client-registration/type-provisioning service or corresponding request configuration. Static client/OP deployment configuration remains external to the RAR flow. | Client type advertisement is MAY, not an unconditional registration request this RP must send. A client library need not operate the AS's type registry to transport agreed details. No registration calls or changes are made by this inventory. |
| 9396-24 — Minimal AS support and machine-readable schemas | Sections11.1/11.2 discuss AS advertisement, consent storage, type-specific presentation/enrichment and delivery to RSs. Section11.3 permits schema tooling but does not assume a type identifier resolves to a schema or requires dereferencing. | **AS functions out of this provider's role; client/RS integration still possible.** Helidon JSON/request transport could support agreed data types, but this module has no RAR integration. It does not host the consent UI, type schema registry or token issuer described by the AS guidance. | Do not cite the AS's minimal implementation list as mandatory RP UI/server work. Conversely, RAR is not unsuitable for Helidon just because business semantics are external. No automatic type-URL fetching, mandatory JSON Schema engine or public class per domain type is required by the base protocol. |

Normative references: [RS availability](https://www.rfc-editor.org/rfc/rfc9396.html#section-9),
[JWT carrier](https://www.rfc-editor.org/rfc/rfc9396.html#section-9.1),
[introspection carrier](https://www.rfc-editor.org/rfc/rfc9396.html#section-9.2),
[AS/client metadata](https://www.rfc-editor.org/rfc/rfc9396.html#section-10),
[AS implementation guidance](https://www.rfc-editor.org/rfc/rfc9396.html#section-11.2),
[optional schemas](https://www.rfc-editor.org/rfc/rfc9396.html#section-11.3).

### Security, privacy and the OIDC/domain examples

| Entry / feature | Specification requirement or boundary | Current implementation / evidence | Assessment / consequence |
| --- | --- | --- | --- |
| 9396-25 — Large requests and reliable transport | Section11.4 notes that rich JSON can produce very long authorization URIs and advises considering request_uri with PAR. Section3 permits the related transport choice; the RFC does not mandate PAR for every request merely because it uses RAR. | **Transport pieces available, no RAR size/transport policy.** [Request factory] and [endpoint client] already support configured PAR and signed/encrypted Request Objects for existing parameters. There is no details input, size budget or automatic RAR-specific transport decision. | Existing PAR could avoid putting a large payload directly into a redirect, but does not create the missing feature. No universal RFC byte limit, mandatory new cookie capacity or observed performance failure is inferred. Sensitive returned/enriched details also need deliberate retention decisions if support is added. |
| 9396-26 — Integrity against tampering and swapping | Section12 says that, if integrity of the details is a concern, the client MUST protect them against tampering/swapping, giving signed Request Objects or request_uri with PAR as approaches. It also requires AS handling/sanitization against injection. | **Generic protection available, not attached to absent RAR data.** [Request object processor] signs and optionally encrypts supported request data; [request factory] has PAR and ordinary state/nonce/PKCE bindings. It never adds a details array to those protected parameters. | Do not credit nonce/PKCE alone as proof that arbitrary business fields were integrity-protected. AS consent/rendering sanitization is outside this RP's role. The conditional MUST is preserved; no current RAR modification attack is claimed for a flow that does not exist. |
| 9396-27 — String comparison without extra normalization | Section12 requires JSON string comparison under RFC8259 with no additional transformation or normalization when evaluating equivalence. Section6.1 separately leaves permission comparison to the type's semantics. | **No RAR string/permission comparator.** Existing [JWT claim conversion] and Helidon JSON types are data tools, not an authorization equivalence policy. The module does not compare requested versus granted RAR values. | Future code should compare decoded string values as specified, not lowercase types, normalize Unicode/URI spellings or compare form-encoded text. JSON-object equality is still not a generic authority-subset test. No current comparison bypass is inferred. |
| 9396-28 — Sensitive data and consent-screen disclosure | Section13 discusses preventing sensitive-data leakage (including referrers), encrypted Request Objects or protected back-channel transport, need-to-know sharing, and the risk of an attacker replaying encrypted request data to reveal it through an AS consent screen. | **No RAR-specific privacy integration.** The existing JAR/PAR stack could protect transport; generic JWT/introspection claim exposure can still carry such data when an AS supplies it. The provider does not control the external AS's consent display, user-context check or audience-specific data minimization. | Signing alone is not confidentiality, and encryption alone does not solve the described consent-screen attack. No new leak was demonstrated in this pass. Future request/response storage, logging and application display must account for sensitivity and enrichment rather than assuming generic claim handling provides redaction or business-context binding. |
| 9396-29 — AppendixA.1 OpenID Connect example | AppendixA.1 permits normal openid/claims beside RAR. Its alternative type=openid with claim_sets, max_age, acr_values and claims is explicitly hypothetical; defining that type is outside RFC9396. | **Ordinary OIDC support, no hypothetical type implementation.** [Request factory] uses the openid scope and normal OIDC flow; it has neither an authorization_details openid object nor a general claims/max_age/acr_values request model. Existing UserInfo/ID Token processing does not imply support for that alternative type. | Do not replace scope=openid or claim that an OP must recognize this example type. It could only be used under an explicit external type agreement. Missing the illustrative type is not a Core/RAR conformance bug; the original OIDC inventory is unchanged. |
| 9396-30 — AppendixA.2–A.4 domain examples | Remote signing, tax access and eHealth illustrate domain-specific requests, nested identifiers and requester/context data. They do not define a universal Helidon business-policy implementation or replace the normative detail-array/type rules. | **No domain-specific RAR types supplied.** The module neither models these objects nor runs their AS/RS business policies. Generic [Helidon JSON arrays] and [JSON object access] could represent nested data if a future agreed profile is integrated. | Do not introduce a class/validator per example, treat illustrative shapes as overrides of section2, or import the cited domain standards into this OIDC pass. A healthcare requester need not be the subject of the record being accessed; authentication identity and domain-object authorization remain distinct. |

Normative/context references: [large requests](https://www.rfc-editor.org/rfc/rfc9396.html#section-11.4),
[integrity/comparisons](https://www.rfc-editor.org/rfc/rfc9396.html#section-12),
[privacy](https://www.rfc-editor.org/rfc/rfc9396.html#section-13),
[hypothetical OIDC type](https://www.rfc-editor.org/rfc/rfc9396.html#appendix-A.1),
[signing example](https://www.rfc-editor.org/rfc/rfc9396.html#appendix-A.2),
[tax example](https://www.rfc-editor.org/rfc/rfc9396.html#appendix-A.3),
[eHealth examples](https://www.rfc-editor.org/rfc/rfc9396.html#appendix-A.4).

### Practical support and representation boundaries

| Capability | Current status | Reason / ownership |
| --- | --- | --- |
| Supply authorization_details during OIDC authorization | Not supported as a first-class feature. | No configuration/per-request data model, parameter generation or requested-detail state. |
| Preserve RAR through query/form/JAR/PAR representations | Not implemented for RAR. | Reusable transports exist, but structured detail-object integration is missing. |
| Select details on code redemption/refresh | Not supported. | No token-request selector or type-specific grant comparison. |
| Expose effective/enriched Token Endpoint details to the RP | Not supported. | Fixed-field token response/local-session model drops the top-level field. |
| Access details inside a validated JWT/introspection response | Generic raw claim exposure exists. | Native data is available via credentials; no RAR shape/type/action enforcement. |
| Negotiate supported types / advertise client types | Not implemented. | AS metadata is ignored; client registration/type provisioning remains external. |
| Type definition, consent, AS enrichment and RS business enforcement | Deployment/type responsibilities. | Helidon need not become an AS or ship every domain schema to support a future client data path. |
| Generic error handling and request security mechanisms | Related support exists. | Not proof of RAR conformance or business-operation authorization. |

The same logical data has different representations at different boundaries:

| Boundary | Needed / available representation | Current limitation |
| --- | --- | --- |
| HTTP authorization/token/PAR field | Serialized JSON array, encoded once as the parameter value. | No details parameter constructed. |
| Structured Request Object | JSON structure preserved as claims before signing/encryption. | Current parameter bridge handles strings/string lists, not the RAR object array. |
| Token Endpoint JSON response | Native authorization_details array of objects. | Field not parsed/exposed/persisted. |
| JWT access-token claim | Native JSON claim in the parsed, validated token. | Generic retention, not RAR validation/policy. |
| Introspection JSON response | Native top-level array when supplied by the AS. | Raw JSON retained, not RAR validation/policy. |
| Helidon principal attribute | Generic array/object values are currently JSON text. | Not an RFC wire representation or typed RAR authorization API. |

[Request factory], [request object processor], [token response], [subject mapper], [validated introspection] and
[JWT claim conversion] establish these boundaries. Granting a business operation requires the appropriate effective
authorization policy, not just conversion between these representations.

### Code quality, reuse and evidence improvements

- **Reuse JSON and encoding components, not a new parser.** [Helidon JSON arrays], [JSON object access] and the existing
  JsonValue-aware [JWT claim conversion] can preserve nested objects, numbers, booleans and strings. Use [Common parameters],
  [Common writable query] and [form media support] only at the outer string-parameter boundary. Avoid double serialization
  or treating a list of JSON strings as a list of detail objects. These are future composition requirements, not a demand
  to add an unused RAR helper now.
- **Use the native validated data that already exists.** For an application-side policy consuming a JWT/introspection
  claim, the raw JSON in TokenCredential avoids reconstructing it from stringified principal attributes. Do not change the
  shared principal/JwtUtil attribute contract or legacy provider just to implement a new optional feature. This is a reuse
  and avoidable-conversion observation; no current RAR hot path or measured performance regression is claimed.
- **Keep transport and type policy separate.** Preserve object boundaries, repeated types and extensions; do not flatten
  them into global roles, infer subset rights by generic JSON equality or fetch a schema just because type resembles a
  URL. The current RAR absence is not an excuse to impose a closed set of payment/healthcare classes on future client use.
- **Make an eventual configuration/data API deliberate.** A future feature would need coherent builder/config support
  and explicit defaults/absence behavior; follow existing Blueprint patterns under
  [Rule 5.1](https://github.com/helidon-io/helidon/blob/main/DEV-GUIDELINES.md#rule-5-1),
  [Rule 5.2](https://github.com/helidon-io/helidon/blob/main/DEV-GUIDELINES.md#rule-5-2) and
  [Rule 8.1](https://github.com/helidon-io/helidon/blob/main/DEV-GUIDELINES.md#rule-8-1) if it is selected. This is design
  guidance, not a new guideline violation in a feature that is absent, and no public API is proposed/added here.
- **Preserve the requested/granted and privacy boundaries.** Returning effective details, permitted enrichment/omission,
  transaction association and sensitive-value retention need explicit behavior. Existing cookie protection/capacity is
  not evidence of a RAR data model. Do not automatically store/log the full requested or enriched object or infer consent
  from a successful login. The AS consent-screen attack needs AS-side countermeasures, not a claim that RP encryption
  alone fixes it.
- **Test the chosen feature, not just its ingredients.** If support is introduced, use observable behavior and existing
  JUnit5/Hamcrest conventions ([Rule 10.1](https://github.com/helidon-io/helidon/blob/main/DEV-GUIDELINES.md#rule-10-1),
  [Rule 10.4](https://github.com/helidon-io/helidon/blob/main/DEV-GUIDELINES.md#rule-10-4)). Cover repeated same-type objects,
  exact parsed strings, structured JAR/PAR values, OIDC scope coexistence, independence from resource, returned/enriched
  arrays, unsupported-type errors and refresh selection. Type-specific semantic tests belong to their actual profile;
  no universal JSON-subset validator should be justified by syntactic tests alone.

No new numbered security/protocol or newly confirmed guideline finding is promoted in this pass. Earlier scoped
member-order, API-contract and other quality notes remain as recorded, rather than being duplicated as RAR findings.

| Existing evidence inspected | Useful result | What it does not establish |
| --- | --- | --- |
| Scoped main/unit/integration symbol search and complete authorization configuration | No first-class RAR data/metadata/error implementation found; README lists unsupported/queued. | A test execution or a claim that hand-written application integration is impossible. |
| [Code exchange tests] signed Request Object plus PAR | Existing signing/PAR transport for ordinary parameters and resource string arrays. | Typed RAR object arrays or transaction-detail integrity. |
| [Callback tests] access_denied and [code exchange tests] invalid_grant | Generic syntax-checked error handling. | Executed invalid_authorization_details callback/token/refresh coverage. |
| [Token response], [local authentication result], [refresh manager] | Fixed-field response/storage path does not retain top-level RAR details. | Successful RAR downscoping, enrichment or granted-rights continuation. |
| [Subject mapper], [validated introspection], [JWT claim conversion] | Raw credential JSON exists; structured principal attributes are text. | Type/schema conformance or business permission checks. |

### Section traceability and validation limits

| RFC9396 section | Entries | Boundary retained |
| --- | --- | --- |
| 1–2 — purpose and data shape | 9396-01–02, 07, 15–16. | Array of objects with required type, not one object or a map keyed only by type. |
| 2.1–2.2 — names/common fields | 9396-03–05, 24, 27. | Extensible type contracts; product/union semantics; no unconditional URI/schema-fetch rule. |
| 3–3.2 — authorization/scope/resource | 9396-07–10. | OIDC can coexist; resource does not narrow authorization_details. |
| 4–5 — response/error | 9396-06, 11–12. | No new success-response field; AS validation and generic client failure roles differ. |
| 6–6.1 — token requests/comparison | 9396-13–14, 18. | Type-specific permission semantics; a narrowed token is not a rewritten original grant. |
| 7–7.1 — token responses/enrichment | 9396-15–16, 18. | Effective details, possible omissions/enrichment, not unconditional echo equality. |
| 8 — token errors | 9396-17. | Same rejection rules, no fabricated successful grant or stripping retry. |
| 9–9.2 — RS carriers | 9396-19–21. | Native data and AS duties; generic retention is not RAR enforcement. |
| 10 — metadata | 9396-22–23. | AS type advertisement, optional client metadata, external type registration. |
| 11–11.4 — implementation | 9396-24–25. | AS minimum functions are not RP UI duties; optional schemas and large-request transports. |
| 12 — security | 9396-10, 21, 26–27. | Conditional integrity MUST, exact string equivalence, type-specific recipients and AS sanitization. |
| 13 — privacy | 9396-16, 21, 28. | Need-to-know sharing and consent-screen replay risk despite encrypted request data. |
| 14–14.6 — registrations | 9396-01, 12–13, 15, 17, 19–20, 22–23. | Parameter/claim/metadata/error families do not mandate an AS or new business types. |
| AppendixA.1 | 9396-09, 29. | Normal OIDC alongside RAR versus explicitly hypothetical openid type. |
| AppendixA.2–A.4 | 9396-30. | Illustrative signing/tax/eHealth contracts, not mandatory Helidon profiles. |

Registration references: [OAuth parameter](https://www.rfc-editor.org/rfc/rfc9396.html#section-14.1),
[JWT claim](https://www.rfc-editor.org/rfc/rfc9396.html#section-14.2),
[introspection member](https://www.rfc-editor.org/rfc/rfc9396.html#section-14.3),
[AS metadata](https://www.rfc-editor.org/rfc/rfc9396.html#section-14.4),
[client metadata](https://www.rfc-editor.org/rfc/rfc9396.html#section-14.5),
[extension error](https://www.rfc-editor.org/rfc/rfc9396.html#section-14.6).

Method: read all substantive local RFC9396 sections1–14 and AppendixA.1–A.4 in bounded slices, checked the official edition
and complete current development guidelines, and traced current request/configuration/JAR/PAR/metadata/token/session/claim
paths plus selected existing test bodies. Consulted local JAR section4 only for representation context. The scoped search
included main, unit and both selected OIDC integration trees. No previous-review finding documents were consulted.
No tests, new diagnostics, live OP/resource/registration calls, consent/transaction/attack probes or benchmarks were run
in this pass. No exhaustive errata or domain-standard review is claimed. No runtime/test/Common/legacy source was changed.
The original eight-spec OIDC inventory, DPoP exclusion, 255 earlier RFC feature entries and nine earlier findings are
preserved. This was the last approved RFC pass; no further RFC or feature implementation is started by this inventory.

<!-- Implementation evidence links. -->

[request factory]: src/main/java/io/helidon/security/providers/oidc/next/OidcAuthenticationRequestFactory.java
[authorization configuration]: src/main/java/io/helidon/security/providers/oidc/next/OidcAuthorizationCodeConfigBlueprint.java
[tenant validation]: src/main/java/io/helidon/security/providers/oidc/next/OidcTenantConfigDecorator.java
[cookie state handler]: src/main/java/io/helidon/security/providers/oidc/next/OidcCookieStateHandler.java
[tenant metadata validation]: src/main/java/io/helidon/security/providers/oidc/next/OidcTenantContextFactory.java
[Discovery metadata model]: src/main/java/io/helidon/security/providers/oidc/next/OidcProviderMetadata.java
[callback processor]: src/main/java/io/helidon/security/providers/oidc/next/OidcAuthorizationResponseProcessor.java
[callback tests]: src/test/java/io/helidon/security/providers/oidc/next/OidcAuthorizationResponseProcessorTest.java
[HTTP feature]: src/main/java/io/helidon/security/providers/oidc/next/OidcFeature.java
[endpoint client]: src/main/java/io/helidon/security/providers/oidc/next/OidcEndpointClient.java
[ID Token validator]: src/main/java/io/helidon/security/providers/oidc/next/OidcIdTokenValidator.java
[mix-up policy]: src/main/java/io/helidon/security/providers/oidc/next/OidcMixUpProtection.java
[endpoint URI validation]: src/main/java/io/helidon/security/providers/oidc/next/OidcEndpointUris.java
[route tests]: src/test/java/io/helidon/security/providers/oidc/next/OidcFeatureRouteTest.java
[URI handling]: src/main/java/io/helidon/security/providers/oidc/next/OidcUri.java
[logout handler]: src/main/java/io/helidon/security/providers/oidc/next/OidcLogoutHandler.java
[provider tests]: src/test/java/io/helidon/security/providers/oidc/next/OidcProviderTest.java
[endpoint configuration]: src/main/java/io/helidon/security/providers/oidc/next/OidcEndpointConfigBlueprint.java
[client authentication]: src/main/java/io/helidon/security/providers/oidc/next/OidcClientAuthenticationSupport.java
[client authentication validation]: src/main/java/io/helidon/security/providers/oidc/next/OidcClientAuthenticationConfigValidator.java
[metadata loader]: src/main/java/io/helidon/security/providers/oidc/next/OidcProviderMetadataLoader.java
[webserver security integration]: ../../../webserver/security/src/main/java/io/helidon/webserver/security/HttpSecurityInterceptor.java
[cookie keys]: src/main/java/io/helidon/security/providers/oidc/next/OidcCookieKeys.java
[refresh manager]: src/main/java/io/helidon/security/providers/oidc/next/OidcRefreshTokenManager.java
[refresh coordinator]: src/main/java/io/helidon/security/providers/oidc/next/OidcRefreshCoordinator.java
[refresh tests]: src/test/java/io/helidon/security/providers/oidc/next/OidcRefreshTokenManagerTest.java
[token response]: src/main/java/io/helidon/security/providers/oidc/next/OidcTokenResponse.java
[request object processor]: src/main/java/io/helidon/security/providers/oidc/next/OidcRequestObjectProcessor.java
[request object configuration]: src/main/java/io/helidon/security/providers/oidc/next/OidcRequestObjectConfigBlueprint.java
[UserInfo support]: src/main/java/io/helidon/security/providers/oidc/next/OidcUserInfoSupport.java
[PKCE methods]: src/main/java/io/helidon/security/providers/oidc/next/OidcPkceMethod.java
[configuration tests]: src/test/java/io/helidon/security/providers/oidc/next/OidcProviderConfigTest.java
[metadata tests]: src/test/java/io/helidon/security/providers/oidc/next/OidcWellKnownMetadataLoadingTest.java
[code exchange tests]: src/test/java/io/helidon/security/providers/oidc/next/OidcAuthorizationCodeTokenExchangeTest.java
[Keycloak TLS identity tests]: ../../../tests/integration/security/oidc-next-keycloak/src/test/java/io/helidon/tests/integration/security/oidcnext/keycloak/KeycloakTlsCertificateIdentityIT.java
[Common query parser]: ../../../common/uri/src/main/java/io/helidon/common/uri/UriQueryImpl.java
[Common URI encoding]: ../../../common/uri/src/main/java/io/helidon/common/uri/UriEncoding.java
[JSON Boolean access]: ../../../json/json/src/main/java/io/helidon/json/JsonObject.java
[JSON value types]: ../../../json/json/src/main/java/io/helidon/json/JsonValue.java
[tenant runtime registry]: src/main/java/io/helidon/security/providers/oidc/next/OidcTenantRuntimeRegistry.java
[provider configuration validation]: src/main/java/io/helidon/security/providers/oidc/next/OidcProviderConfigDecorator.java
[runtime metadata tests]: src/test/java/io/helidon/security/providers/oidc/next/OidcTenantRuntimeResourcesTest.java
[JWT serialization]: ../../jwt/src/main/java/io/helidon/security/jwt/Jwt.java
[JWT signing]: ../../jwt/src/main/java/io/helidon/security/jwt/SignedJwt.java
[PAR response]: src/main/java/io/helidon/security/providers/oidc/next/OidcPushedAuthorizationResponse.java
[JOSE key policy]: src/main/java/io/helidon/security/providers/oidc/next/OidcJoseKeyPolicy.java
[JWT encryption]: ../../jwt/src/main/java/io/helidon/security/jwt/EncryptedJwt.java
[Request Object key tests]: src/test/java/io/helidon/security/providers/oidc/next/OidcRequestObjectProcessorTest.java
[OAuth error fields]: src/main/java/io/helidon/security/providers/oidc/next/OidcOAuthErrorFields.java
[JWT headers]: ../../jwt/src/main/java/io/helidon/security/jwt/JwtHeaders.java
[OIDC HTTP client factory]: src/main/java/io/helidon/security/providers/oidc/next/OidcWebClientFactory.java
[Common TLS configuration]: ../../../common/tls/src/main/java/io/helidon/common/tls/TlsConfigBlueprint.java
[Common TLS parameters]: ../../../common/tls/src/main/java/io/helidon/common/tls/TlsConfigDecorator.java
[TCP client connection]: ../../../webclient/api/src/main/java/io/helidon/webclient/api/TcpClientConnection.java
[Common TLS sockets]: ../../../common/tls/src/main/java/io/helidon/common/tls/Tls.java
[Common TLS manager]: ../../../common/tls/src/main/java/io/helidon/common/tls/ConfiguredTlsManager.java
[Common TLS trust wrapper]: ../../../common/tls/src/main/java/io/helidon/common/tls/TlsReloadableX509TrustManager.java
[Request Object configuration support]: src/main/java/io/helidon/security/providers/oidc/next/OidcRequestObjectConfigSupport.java
[tenant context]: src/main/java/io/helidon/security/providers/oidc/next/OidcTenantContext.java
[form media support]: ../../../http/media/media/src/main/java/io/helidon/http/media/FormParamsSupport.java
[HTTP status values]: ../../../http/http/src/main/java/io/helidon/http/Status.java
[HTTP/1 status parser]: ../../../webclient/http1/src/main/java/io/helidon/webclient/http1/Http1StatusParser.java
[HTTP/1 call chain]: ../../../webclient/http1/src/main/java/io/helidon/webclient/http1/Http1CallChainBase.java
[HTTP/1 response]: ../../../webclient/http1/src/main/java/io/helidon/webclient/http1/Http1ClientResponseImpl.java
[HTTP/1 status tests]: ../../../webclient/http1/src/test/java/io/helidon/webclient/http1/Http1StatusParserTest.java
[OAuth error response]: src/main/java/io/helidon/security/providers/oidc/next/OidcTokenErrorResponse.java
[authentication orchestrator]: src/main/java/io/helidon/security/providers/oidc/next/OidcAuthenticationOrchestrator.java
[authentication responses]: src/main/java/io/helidon/security/providers/oidc/next/OidcResponseFactory.java
[PAR result]: src/main/java/io/helidon/security/providers/oidc/next/OidcPushedAuthorizationRequestResult.java
[PAR modes]: src/main/java/io/helidon/security/providers/oidc/next/OidcPushedAuthorizationRequestMode.java
[Common parameters]: ../../../common/parameters/src/main/java/io/helidon/common/parameters/Parameters.java
[JSON object access]: ../../../json/json/src/main/java/io/helidon/json/JsonObject.java
[JSON strings]: ../../../json/json/src/main/java/io/helidon/json/JsonString.java
[JSON decoding]: ../../../json/json/src/main/java/io/helidon/json/Parsers.java
[tenant options]: src/main/java/io/helidon/security/providers/oidc/next/OidcTenantConfigOptionsBlueprint.java
[JWK Set manager]: src/main/java/io/helidon/security/providers/oidc/next/OidcJwkSetManager.java
[client authentication methods]: src/main/java/io/helidon/security/providers/oidc/next/OidcClientAuthenticationMethod.java
[client assertion configuration]: src/main/java/io/helidon/security/providers/oidc/next/OidcClientAssertionConfigBlueprint.java
[client assertion configuration validation]: src/main/java/io/helidon/security/providers/oidc/next/OidcClientAssertionConfigDecorator.java
[client assertion reuse tests]: src/test/java/io/helidon/security/providers/oidc/next/OidcClientAssertionReuseTest.java
[JOSE key policy tests]: src/test/java/io/helidon/security/providers/oidc/next/OidcJoseKeyPolicyTest.java
[private key source tests]: src/test/java/io/helidon/security/providers/oidc/next/OidcPrivateKeySourceTest.java
[JWT asymmetric signing]: ../../jwt/src/main/java/io/helidon/security/jwt/jwk/JwkPki.java
[JWT HMAC signing]: ../../jwt/src/main/java/io/helidon/security/jwt/jwk/JwkOctet.java
[JWT cryptographic factories]: ../../jwt/src/main/java/io/helidon/security/jwt/JwtUtil.java
[JWT key-set loading]: ../../jwt/src/main/java/io/helidon/security/jwt/jwk/JwkKeys.java
[certificate-bound configuration]: src/main/java/io/helidon/security/providers/oidc/next/OidcCertificateBoundAccessTokenConfigBlueprint.java
[certificate-bound modes]: src/main/java/io/helidon/security/providers/oidc/next/OidcCertificateBoundAccessTokenMode.java
[certificate-bound validation]: src/main/java/io/helidon/security/providers/oidc/next/OidcCertificateBoundAccessTokenSupport.java
[token validation configuration]: src/main/java/io/helidon/security/providers/oidc/next/OidcTokenValidationConfigBlueprint.java
[access-token validation request]: src/main/java/io/helidon/security/providers/oidc/next/OidcAccessTokenValidationRequest.java
[JWT access-token validator]: src/main/java/io/helidon/security/providers/oidc/next/OidcJwtAccessTokenValidator.java
[introspection access-token validator]: src/main/java/io/helidon/security/providers/oidc/next/OidcIntrospectionAccessTokenValidator.java
[request context]: src/main/java/io/helidon/security/providers/oidc/next/OidcRequestContext.java
[JWT binding tests]: src/test/java/io/helidon/security/providers/oidc/next/OidcJwtAccessTokenValidationTest.java
[introspection binding tests]: src/test/java/io/helidon/security/providers/oidc/next/OidcIntrospectionAccessTokenValidationTest.java
[certificate test fixtures]: src/test/java/io/helidon/security/providers/oidc/next/OidcTestCertificates.java
[local authentication result]: src/main/java/io/helidon/security/providers/oidc/next/OidcLocalAuthenticationResult.java
[OIDC provider]: src/main/java/io/helidon/security/providers/oidc/next/OidcProvider.java
[outbound orchestrator]: src/main/java/io/helidon/security/providers/oidc/next/OidcOutboundOrchestrator.java
[protected-resource configuration]: src/main/java/io/helidon/security/providers/oidc/next/OidcProtectedResourceConfigBlueprint.java
[endpoint policy configuration]: src/main/java/io/helidon/security/providers/oidc/next/OidcEndpointPolicyConfigBlueprint.java
[WebClient security propagation]: ../../../webclient/security/src/main/java/io/helidon/webclient/security/WebClientSecurity.java
[authentication request state]: src/main/java/io/helidon/security/providers/oidc/next/OidcAuthenticationRequestState.java
[subject mapper]: src/main/java/io/helidon/security/providers/oidc/next/OidcSubjectMapper.java
[validated introspection]: src/main/java/io/helidon/security/providers/oidc/next/OidcValidatedIntrospection.java
[authentication SPI]: ../../security/src/main/java/io/helidon/security/spi/AuthenticationProvider.java
[outbound security SPI]: ../../security/src/main/java/io/helidon/security/spi/OutboundSecurityProvider.java
[Common writable query]: ../../../common/uri/src/main/java/io/helidon/common/uri/UriQueryWriteable.java
[Common query construction]: ../../../common/uri/src/main/java/io/helidon/common/uri/UriQueryWriteableImpl.java
[resource indicator validation]: src/main/java/io/helidon/security/providers/oidc/next/OidcResourceIndicators.java
[outbound policy]: src/main/java/io/helidon/security/providers/oidc/next/OidcOutboundPolicy.java
[Common URI validation]: ../../../common/uri/src/main/java/io/helidon/common/uri/UriValidator.java
[Token Exchange tests]: src/test/java/io/helidon/security/providers/oidc/next/OidcTokenExchangeGrantTest.java
[Helidon JSON arrays]: ../../../json/json/src/main/java/io/helidon/json/JsonArray.java
[JWT claim conversion]: ../../jwt/src/main/java/io/helidon/security/jwt/JwtUtil.java
