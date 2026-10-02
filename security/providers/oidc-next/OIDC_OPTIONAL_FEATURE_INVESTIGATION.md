# OIDC Next: next optional feature investigation

Date: 2026-10-02. Source baseline: `a28eb6b50d`. This is a scoped comparison of possible **new features**, not a
claim that any unimplemented option is a mandatory OIDC defect. The two findings expressly deferred in the independent
review, UX-02 and SPEC-03, remain deferred and are not candidates here. No feature is implemented by this document.

## 1. `form_post` authorization response mode

The [Form Post Response Mode specification](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html#FormPostResponseMode)
defines an authorization response delivered to the RP redirect URI in an auto-submitted, URL-encoded HTTP POST body;
the RP must process it independently of the browser's form-submission mechanism. This is optional for a code-flow RP;
it is not equivalent to POSTing an authorization request to the OP. It could add interoperability with OP/client
registrations that select this mode and keep authorization codes out of the RP callback URL, without adding implicit or
hybrid token reception.

Current code: [OidcFeature](src/main/java/io/helidon/security/providers/oidc/next/OidcFeature.java) registers only GET
callback routes and passes the URL query to
[OidcAuthorizationResponseProcessor](src/main/java/io/helidon/security/providers/oidc/next/OidcAuthorizationResponseProcessor.java).
[OidcAuthenticationRequestFactory](src/main/java/io/helidon/security/providers/oidc/next/OidcAuthenticationRequestFactory.java)
constructs `response_type=code` without a `response_mode` option. The metadata model does not consume
`response_modes_supported`. The state cookie is always emitted with `SameSite=Lax` by
[OidcCookieStateHandler](src/main/java/io/helidon/security/providers/oidc/next/OidcCookieStateHandler.java), and no
cookie SameSite option exists in [OidcCookieConfig](src/main/java/io/helidon/security/providers/oidc/next/OidcCookieConfigBlueprint.java).
Per the [current RFC6265bis draft on Lax cookies and cross-site POST](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis-22#section-8.8.6),
a Lax state cookie is withheld on an OP-to-RP cross-site top-level POST. Merely adding a POST callback route would
therefore fail to correlate the transaction in that common deployment. Same-site OP/RP deployments may behave
differently; this is a concrete protocol/browser integration condition, not a claim that all POST callbacks fail.

A coherent opt-in feature would need to:

1. Select `form_post` per OIDC code-flow configuration, include it in ordinary, Request Object and PAR authorization
   requests, and check loaded OP response-mode capability when appropriate. Keep the existing query mode as the default.
2. Register a POST callback only for tenants that enable the mode; parse an explicitly URL-encoded body with Helidon's
   existing [FormParamsSupport](../../../http/media/media/src/main/java/io/helidon/http/media/FormParamsSupport.java)
   and `Parameters`, with a sensible request-body limit. Do not merge response-body credentials with URL query values:
   retain callback-URI matching while rejecting query/body ambiguity and duplicate `state`, `code`, `iss` or `error`.
   Reuse the current state/issuer/PKCE/nonce/code-redemption checks for both transports.
3. Make the *short-lived, authenticated-encrypted authentication-request state cookie* available on a cross-site POST
   (for example, `SameSite=None; Secure` in this mode) without indiscriminately relaxing the local-session cookie.
   Preserve the random-state/issuer/redirect validation; test generation-cookie/session-chunk rotation when prior Lax
   cookies were withheld on the POST and reappear on the next same-site GET. Check compatibility with target browsers
   rather than assuming their treatment of third-party cookies.
4. Test successful/failed callbacks with an actual browser or realistic cookie-policy fixture, including an external-
   site OP, malformed media/body, duplicates, mix-up protection, JAR/PAR composition and no logging of form credentials.

Assessment: **medium implementation and integration effort, high conditional interoperability value** when an OP
requires or a deployment prefers `form_post`. It is not a one-route change and should not be enabled until the
cross-site cookie policy is addressed. A cross-site browser test, not only a direct POST unit test, is an essential
acceptance criterion.

## 2. Optional code-flow `at_hash` verification

[OIDC Core section 3.1.3.8](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowTokenValidation)
allows an RP to verify the Token Endpoint access token against `at_hash` **if the returned ID Token has that claim**.
It does not require the claim or this check for the authorization-code flow; mandatory checks for implicit/hybrid
front-channel tokens do not make those unsupported flows available here. This adds a signed token-pair consistency
check, not a replacement for TLS, issuer/nonce/signature validation, or access-token audience validation at a resource.

Current code: [OidcFeature](src/main/java/io/helidon/security/providers/oidc/next/OidcFeature.java) has both values but
passes only the ID Token to [OidcIdTokenValidator](src/main/java/io/helidon/security/providers/oidc/next/OidcIdTokenValidator.java)
before UserInfo/session creation. The shared [Jwt](../../jwt/src/main/java/io/helidon/security/jwt/Jwt.java) already
parses `at_hash` into `Optional<byte[]>`; no duplicate JWT claim parser is needed. The refresh path validates an
optional replacement ID Token separately in
[OidcRefreshTokenManager](src/main/java/io/helidon/security/providers/oidc/next/OidcRefreshTokenManager.java).

A focused implementation would compare, only when a **new validated ID Token contains `at_hash`**, the left half of
the digest of the ASCII access-token string with that claim's decoded bytes, using the ID Token's signing algorithm
to select the digest. Perform the comparison after ID Token signature/claims validation but before UserInfo or writing
a session. On refresh, compare the *replacement* access token only when the response contains a *new* ID Token with
this claim; do not compare the new access token against a stored old ID Token. Cover valid, absent and mismatched
hashes, the supported ID-Token algorithm families, encrypted ID Tokens and both initial and refresh responses.
Unrecognized hash-to-signature mappings need an explicit policy, not a silent SHA-256 default or the access token's
own `alg` field. A compatibility opt-out should be considered only if a real OP emits incorrect hashes; it is not
needed to validate responses without the optional claim.

Assessment: **low-to-medium effort, defense in depth, limited new interoperability**. It is a reasonable bounded
security-quality task, but there is no demonstrated attack or mandatory Core gap in the current back-channel code
flow. Prioritize it ahead of a broader protocol only if the goal is a small, independently testable improvement.

## 3. OP-initiated back-channel logout

[OIDC Back-Channel Logout 1.0, errata set 1](https://openid.net/specs/openid-connect-backchannel-1_0.html#Backchannel)
defines a server-to-server POST with a signed Logout Token. Its mandatory validation includes signature, issuer,
audience, time claims, an `events` claim and at least `sub` or `sid`, while prohibiting `nonce`; the `jti` claim is
required, but checking for a duplicate `jti` is optional. The RP then terminates the identified sessions. This can
provide useful enterprise single-logout behavior without relying on a browser tab or third-party iframe cookies.

Current code: [OidcFeature](src/main/java/io/helidon/security/providers/oidc/next/OidcFeature.java) registers an
application-origin POST logout route, **not** a back-channel notification endpoint. Its
[OidcLogoutHandler](src/main/java/io/helidon/security/providers/oidc/next/OidcLogoutHandler.java) requires same-origin
request context and clears cookies on a browser response; an OP-to-RP POST has neither that origin nor that browser's
cookies. [OidcAuthenticationOrchestrator](src/main/java/io/helidon/security/providers/oidc/next/OidcAuthenticationOrchestrator.java)
reads encrypted local-session cookies directly. The ID Token, which may contain the OP's `sid`, is stored inside the
cookie; there is no server-side `sid`/subject-to-session index or shared revocation check on later cookie reads.

Adding just a Logout Token receiver would be **incorrect**: returning HTTP success without invalidating previously
issued browser cookies would leave those users logged in. A real implementation needs a session-revocation strategy
checked on every local-cookie authentication, with bounded retention/expiry and a multi-node story (shared storage or
an explicit application-provided SPI). It also needs purpose-specific Logout Token validation and tenant/issuer routing,
safe `sub`/`sid` correlation, no ID-Token/Logout-Token confusion, plus sensible repeat-delivery handling. Existing JWT
verification, JWK loading and form-body parsing can be reused, but an ID Token validator cannot be reused wholesale:
Logout Tokens have different required/prohibited claims and do not authenticate a browser request. Acceptance tests
must present an *old* browser cookie after a genuine OP notification and observe rejection on all server instances;
tests limited to a 2xx POST response would miss the central requirement.

Assessment: **high value for deployments needing OP global logout, high architectural cost** because of revocation
state, expiry and clustering. Plan this as a separate feature with an explicit session-store/invalidator decision, not
as an incidental extension of the local logout handler. Its absence is not a defect in the currently supported
RP-initiated logout flow.

## 4. RFC 9470 step-up authentication

[RFC 9470 sections 3–5](https://www.rfc-editor.org/rfc/rfc9470.html#section-3) defines an
`insufficient_user_authentication` Bearer challenge with `acr_values` and/or `max_age`, followed by a new
authorization request asking the OP for stronger or fresher user authentication. It extends an OIDC use case but does
not require every ordinary OIDC code-flow client or protected resource to provide an automatic challenge/retry loop.

Current code: [OidcResponseFactory](src/main/java/io/helidon/security/providers/oidc/next/OidcResponseFactory.java)
produces the existing standard Bearer challenges; the authorization factory has no `acr_values`/`max_age` request
parameters or per-request step-up options. [OidcIdTokenValidator](src/main/java/io/helidon/security/providers/oidc/next/OidcIdTokenValidator.java)
retains `auth_time` for refresh consistency, but that alone does not implement the requested assurance policy or
check an API access token's assurance.

End-to-end support needs application policy for which API challenges are trusted, per-transaction authentication
requirements, correct authorization parameters (including JAR/PAR), and a bounded continuation after success.
The requesting resource must assess assurance from the *new access token* or introspection evidence; accepting an
ID Token `acr` alone as authorization for an unrelated API would confuse token roles. The OP is permitted to return
an unmet-requirements error instead of a satisfactory token, so there must be a stop condition rather than an
unbounded login loop. A small static `acr_values` option may be useful independently but is not the full RFC9470
challenge protocol.

Assessment: **medium-to-high effort, valuable with a concrete step-up scenario**, not a default-flow defect or a
quick variation on the existing Bearer challenge.

## Recommendation

| Candidate | Main gain | Relative effort and critical dependency | Priority condition |
| --- | --- | --- | --- |
| `form_post` | New OP response-mode interoperability, less callback-URL exposure. | Medium; state cookie SameSite policy and actual cross-site browser test are mandatory design work. | **First user-visible protocol extension when an OP/client registration needs it.** |
| Code-flow `at_hash` when present | Signed access-token/ID-Token pair consistency. | Low–medium; reuse parsed JWT claim, handle signing-algorithm digest mapping and refresh correctly. | **First bounded hardening task if no missing OP feature is driving priorities.** |
| Back-channel logout | OP-triggered single logout without browser participation. | High; shared revocation/session-index design and JWT event validation before a receiver is meaningful. | Choose for a real single-logout requirement with a distributed-state design. |
| RFC 9470 step-up | Resource-driven fresh/strong authentication. | Medium–high; application trust policy, assurance evidence, per-request login and bounded recovery. | Choose for a defined API assurance/step-up workflow. |

Without a concrete interoperability requirement, I would **not** add a new response mode or logout endpoint just to
increase the spec count. The next contained improvement is conditional code-flow `at_hash` checking; if a target OP
actually requires `form_post`, prioritize that feature instead and include the cross-site cookie/browser acceptance
test from the outset. Neither task is a currently mandatory OIDC correctness fix. DPoP remains explicitly unsupported
by project choice and is not proposed here. This is not an exhaustive ranking of every optional claim/flow/extension in
the broader OIDC inventories; it compares candidates with distinct cost and utility profiles.

Method and limits: checked the current Java source and the linked official protocol specifications; the cookie
interaction is an inference from the explicit `SameSite=Lax` code and the cited cookie draft. No new browser, OP,
load or exploit test was run for this investigation. Relative value/effort rankings are engineering judgments, not
measured adoption or implementation estimates.
