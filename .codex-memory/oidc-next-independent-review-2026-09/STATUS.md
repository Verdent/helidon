# OIDC-next independent review status

- Review started: 2026-09-16
- Branch: `oidc-next`
- Source revision at start: `db97b63ceb56afce03cc0c6b42d3a8c5cf0f4536`
- Phase: complete
- Final report: `OIDC_NEXT_INDEPENDENT_REVIEW_2026-09.md`
- Original audit findings: 29 (SPEC-06 subsequently withdrawn after normative recheck)
- Remediated findings: 25 (`SEC-01`, `SPEC-01`, `CONC-01`, `CONC-02`, `SPEC-02`, `SEC-03`, `SEC-02`, `CORR-01`, `CFG-01`, `AVAIL-01`, `CFG-02`, `CFG-03`, `CFG-04`, `CFG-05`, `SPEC-05`, `ROBUST-01`, `UX-01`, `DESIGN-02`, `DESIGN-01`, `LIFE-01`, `SEC-04`, `CONC-03`, `CFG-06`, `SPEC-04`, `BUILD-01`)
- Clarified/closed findings: 1 (`CORR-02`: documented transport contract and regression coverage; no runtime defect established)
- Withdrawn findings: 1 (`SPEC-06`: mandatory raw-duplicate rejection was not substantiated by the cross-referenced JOSE rules)
- Open active findings: 0
- Deferred findings: 2 (`UX-02`, medium, on 2026-09-18; `SPEC-03`, low, on 2026-09-23; both by explicit user decision)
- Candidate findings awaiting proof: 0

## Current follow-up status (2026-10-02)

The separate OIDC-related RFC pass has nine numbered findings: eight remediated, one explicitly accepted PKCE `plain`
compatibility exception, and none awaiting an active fix. The former final conditional finding, 9101-F01, was reproduced
with signed JAR over PAR and fixed for that scoped path by the pre-request DNS-SAN check in `9a9873498f`; PAR HTTPS
enforcement followed in `fdd089914d`. The PKCE plain option was restored in `d0ab537df8` with S256 still the default,
and CUSTOM JWT access-token audience validation can explicitly be disabled as of `a28eb6b50d`, with the default still
enabled. The full OIDC Next provider verification passed after the latter adjustment. These are not new numbered
findings. UX-02 and SPEC-03 remain deferred at the user's request.

`security/providers/oidc-next/OIDC_RFC_COVERAGE.md` now has a current disposition table and corrected post-fix feature
rows, while preserving its original baseline evidence. The separate
`security/providers/oidc-next/OIDC_OPTIONAL_FEATURE_INVESTIGATION.md` compares form_post, optional code-flow at_hash,
OP back-channel logout and RFC 9470 step-up. No optional feature was implemented in this documentation pass. Dates and
"remaining" counts in the remediation chronology below refer to those historical checkpoints, not the current queue.

## RFC remediation chronology

On 2026-09-30 the user authorized the RFC 8707-F01 fix and asked to reuse Helidon Common URI validation. A pre-fix
regression confirmed an RFC3986-invalid resource with raw Unicode passed configuration validation. The shared
OidcResourceIndicators helper now uses Common component validators plus a private authority-syntax check, rejecting
invalid configured resource URIs without rewriting valid percent-escaped URNs, IPv6 hosts, reg-names or query values.
The prior authorization redirect encoding test now uses an escaped nested resource, and the README documents the
expected input. Final module verify passes 1,612 tests plus Checkstyle, maximum-effort SpotBugs/FindSecBugs, copyright
and dependency checks; all 42 synthetic and 18 real-Keycloak integration tests pass. The fix is committed as `62fb4e161d`.
9101-F01 is the only remaining conditional RFC finding. RFC 9101 section 8's certificate-name rule must be scoped to
the relevant HTTP-client role: OIDC-next sends Request Objects by value or PAR and uses only AS-issued `request_uri`
values, not an RP-hosted Request Object URI. PAR can still be a by-reference method, so do not dismiss the rule solely
because this RP does not host objects. On 2026-09-30, an isolated direct-HTTPS Keycloak test on the actual OIDC-next
PAR path accepted an explicitly trusted CN-only certificate without any SAN (303), whereas the matching-DNS-SAN control
also succeeded and a mismatched-DNS-SAN control failed as expected (503). All three cases ran; only the desired CN-only
rejection assertion fails intentionally. The original HTTP Keycloak PAR test and
integration-module style checks pass. This test uses plain PAR, not a signed JAR, so RFC 9101 section 8's exact scope
remains to be decided. No product TLS code changed. A correct rejection must happen before the request carries client
credentials; the existing WebClient connection listener runs before TLS, and no post-handshake/pre-request hook was found.
On 2026-10-01, the user requested a signed-JAR+PAR version. An isolated new Keycloak client now requires an RS256-signed
Request Object and registers the matching public JWK. OIDC-next sends its signed `request` through the same PAR TLS
transport. Three HTTPS tests ran with no skips: the correct DNS SAN passed, wrong DNS SAN failed, and explicitly trusted
CN-only/no-SAN still completed the signed PAR and produced a request URI (303), failing the expected 503 assertion.
The original Keycloak HTTP PAR test, integration module compilation and style checks pass; the intentional CN-only
regression stays red until a pre-request TLS identity fix is authorized and implemented. No product, Common or legacy
source changed in this test step; no commit requested.
See `rfc9101-f01-keycloak-test.md`, `rfc8707-f01-implementation.md` and
`security/providers/oidc-next/OIDC_RFC_COVERAGE.md`.

On 2026-09-30 the user authorized fixing 9126-F01. Real HTTP/1.1 201 responses with a custom reason phrase and an
empty reason phrase reproduced the PAR failure in two pre-fix loopback tests. A one-line numeric `Status.CREATED_201_CODE`
comparison now passes both, retaining the JSON field/media-type and non-201 error handling. A 202-with-success-body
rejection test was added to keep the status requirement exact; the first complete OIDC-next module/quality run passed
before that final test addition. Final module verify passed with all 1,609 tests plus Checkstyle, maximum-effort
SpotBugs/FindSecBugs, copyright and dependency checks; all 42 synthetic integration tests and 18 real-Keycloak
integration tests passed. At that checkpoint two RFC-phase findings remained actionable: 9101-F01 was conditional on a
TLS-profile audit, and 8707-F01 concerned resource-indicator URI grammar. The PAR fix was committed as `72bf55a21a`;
8707-F01 was the historical next focused candidate (now addressed above), while 9101-F01 needs its applicability audit.
See `rfc9126-f01-implementation.md` and `security/providers/oidc-next/OIDC_RFC_COVERAGE.md`.

On 2026-09-30 the user authorized fixing 8414-F01 (valid HTTP 200 metadata rejected for its reason phrase). Both
custom-phrase and truly empty-phrase HTTP/1.1 responses reproduced retryable failure before the fix; both now pass
after the loader changed its comparison to numeric `Status.OK_200_CODE`. Non-200 rejection, JSON-media-type and issuer
checks remain intact. All 1,606 module tests, 42 synthetic integrations, Checkstyle, maximum-effort
SpotBugs/FindSecBugs, copyright and dependency analysis pass. The 18-test real-Keycloak replay also passed. The fix is
committed as `0170fa3bae`; three RFC-phase findings remain actionable. See
`rfc8414-f01-implementation.md` and `security/providers/oidc-next/OIDC_RFC_COVERAGE.md`.

Historical next recommendation at `0170fa3bae`: `9126-F01`. PAR compared a `Status` object by identity with
`Status.CREATED_201`; an otherwise valid HTTP/1.1 201 with a custom/absent reason phrase takes the OAuth error path,
so PAR-enabled OIDC login becomes unavailable. RFC 9126 section 2.2 specifies numeric 201 and RFC 9112 section 4
defines the reason phrase as optional. A focused follow-up should compare `response.status().code()` with Helidon's
`Status.CREATED_201_CODE`, preserving JSON/body validation and rejecting non-201 success codes. This is a concrete
interoperability finding, not a demonstrated authentication bypass. No 9126-F01 fix had been started at that point;
`9101-F01` remains
conditional and needs a separate applicability audit before changing TLS identity policy.

On 2026-09-30 the user chose to retain RFC 7636-F01 as a deliberate, explicitly selected confidential-client
compatibility exception, not a mandatory runtime fix. The documentation/Javadoc clarification was committed as
`1940827324`. OIDC-next defaults to S256, public clients cannot choose PLAIN,
and there is no automatic downgrade. README, the PKCE option and enum Javadocs, and the guard comment now explain that
PLAIN with this S256-capable RP deviates from RFC 7636 section 4.2 and loses protection if the Authorization Request
is observed. No second opt-in or protocol behavior change was added. The finding is closed as an accepted exception,
not counted as RFC-conformant; four other RFC-phase findings were actionable at that checkpoint, before 8414-F01 was
fixed above. See the updated 7636-F01 disposition
in `security/providers/oidc-next/OIDC_RFC_COVERAGE.md`.

Historical next recommendation at `1940827324` was `8414-F01`; it is now fixed in `0170fa3bae` as described above.

On 2026-09-30 the user authorized a focused RFC 8705 mTLS alias fix (`8705-F01` and its OP UserInfo companion `8705-F02`).
Both were fixed, verified and committed as `282a094dee`. One `outbound-mutual-tls` tenant option, also usable
at provider root, expresses mTLS intent with a non-mTLS OAuth client-authentication method; existing TLS methods imply
it. The selected Token/PAR and OP UserInfo aliases are HTTPS-validated, alias-only PAR/UserInfo can be used where
advertised, absent aliases use the conventional HTTPS endpoint, and an advertised alias failure is not retried at the
conventional endpoint. Initial and deferred metadata fetches require HTTPS for mTLS-intending tenants. Resource-server
token validation and introspection authentication remain separate. All 1,604 module tests, 42 synthetic integrations,
Checkstyle, maximum-effort SpotBugs/FindSecBugs and dependency analysis passed. All 18 real-Keycloak integrations
passed against the integration-installed JAR; the final installed snapshot has byte-identical compiled production
classes after a test-only cleanup. At that checkpoint five RFC-phase findings remained unresolved; 7636-F01 is now
accepted as described above. Alias selection is not a
guarantee that the AS issued a bound access token; see `rfc8705-alias-remediation.md` and the remediation notes in
`security/providers/oidc-next/OIDC_RFC_COVERAGE.md`. No legacy provider or Common source was changed.

## Prior RFC remediation

On 2026-09-30 the user authorized fixing 9207-F01 (colliding issuer across independent OPs). It was fixed, verified and
committed as `f4d178e813`. A baseline mock callback with valid `iss` posted an honest code to the wrong Token
Endpoint once and returned 303; metadata-only discovery also accepted the unrelated OP's issuer. The fix binds actually
fetched metadata to its OIDC/RFC 8414 issuer-derived well-known URI, rejecting known pinned-source errors before GET,
and rejects conflicting/ambiguous same-issuer Authorization/Token Endpoint bindings at provider configuration time.
Valid shared-OP client registrations, canonical discovery profiles, actual trusted HTTPS, dev HTTP opt-out and static
no-fetch cases are covered. Both lazy initialization orders and concurrent virtual threads fail closed with zero wrong
Token Endpoint requests. All 1,586 module tests and 42 synthetic integrations pass; Checkstyle, maximum-effort
SpotBugs/FindSecBugs and dependency analysis pass. Seven RFC-phase findings remain unimplemented. The separate
provider-root WebClient builder fix was committed first as `ab46fd0a6b`. See
`rfc9207-f01-implementation.md` and `/tmp/oidc-issuer-binding.lHdm9b/`. All 18 real-Keycloak integration tests passed
against the installed snapshot. No other finding was implemented as part of these commits.

Historical next recommendation at this 9207-F01 checkpoint was `8705-F01`; it is now fixed as described above.

On 2026-09-29 the user authorized fixing 8414-F02 (Discovery TLS-policy bypass). It was fixed and verified, then
committed on 2026-09-30 as `dacfb25e88` on the user's explicit request; exactly six reviewed files were included.
The baseline default-TLS missing-JWKS/required-PAR cases reproduced HTTP metadata retrieval and READY tenants; the
deferred-loader refusal regression also failed, while HTTPS/explicit-HTTP-opt-out/unused-static controls passed.
The existing URI validator is now called before metadata I/O and outside the retryable-I/O catch; both loader callers
pass the tenant TLS flag. All six new focused tests, all 1,564 module tests and 42 synthetic integrations pass without
failures/errors/skips; Checkstyle, maximum-effort SpotBugs/FindSecBugs and dependency analysis pass. HTTPS, explicit HTTP
opt-out and unused-static controls are preserved. No public API, dependency, new class, Common or legacy change.
Eight other RFC-phase findings remain unimplemented; Core/spec inventories retain their baseline feature assessments.
See `rfc8414-f02-implementation.md` and `/tmp/oidc-8414-f02.Zy1RKs/`. The next proposed issue is 9207-F01;
that was the next issue at this historical checkpoint and is now fixed as described above.

## Current slice

BUILD-01 is implemented, verified, and committed as `e015f55ebe` on explicit request on 2026-09-23 (baseline `d4f0a5e66b`).
The user deferred SPEC-03
and requested moving to the next item. Two product files only: OIDC-next's POM and module-info.java. HTTP/Common Socket
are direct compile dependencies; HTTP has a direct requires. The test-only Hamcrest declaration now names the already
used full library instead of redundant core. The parent-managed dependency check runs at verify with exact documented
exceptions for re-exported APIs/service-loaded providers, retaining inherited static-annotation handling.
The baseline analyzer failed, and the new verify execution still failed on exactly HTTP/Common Socket/full Hamcrest
before their declarations were corrected. Final verification: 1,558 module tests and 42 synthetic integrations pass;
Checkstyle and 284-class maximum-effort SpotBugs/FindSecBugs report zero problems. The dependency analyzer passes.
An isolated single-dependency modular consumer discovers, creates, and closes the provider without WebServer; HTTP/1
and JSON providers remain resolved. Runtime artifacts/versions/scopes are unchanged; only redundant test-only
hamcrest-core leaves the resolved graph. Validated source and built/installed POM/JAR identities remain unchanged.
No protocol/runtime algorithm, public API, application configuration, third-party upgrade, Common, legacy, or shared
Security change. Keycloak not rerun for this build-only change. Final in-scope review: no findings. Details, exact
artifact hashes, and verification commands are in `build-01-implementation.md`; logs:
`/tmp/oidc-build01-dependencies.gIvht9/`. No active findings remain; SPEC-03 and UX-02 stay deferred.

SPEC-03 is now deferred by explicit user request on 2026-09-23. No implementation or shared integration change was made.
Retain its evidence and do not return it to the active fix queue unless the user reopens it. Historical investigation:
SPEC-03 implementation investigation, 2026-09-23, baseline `d4f0a5e66b`: normative scope confirmed, but no product
edits or tests yet. RFC 6750 section 2.3 recommends private on successful 2xx query-token responses (SHOULD).
Application no-store and other stricter directives must not be overwritten. RFC 9700 section 4.3.2 prohibits clients
from sending query tokens; hardening the existing opt-in resource-server compatibility mode does not make that client
behavior current-BCP compliant. Keep the default disabled and distinguish these roles in documentation.
Provider-only responseHeaders cannot meet the intended HTTP behavior: SecurityHandler:581-583 replaces earlier
application headers before final status is known; HttpSecurityInterceptor:553-556 reads requestHeaders on success.
The existing beforeSend callback is suitable for final-response policy, but ProviderRequest has no supported response
handle. OidcFeature is currently optional for protected-resource-only applications; requiring it would change setup.
Request user direction before expanding the fix into shared WebServer Security integration. No legacy/Common/shared
code changed, no feature requirement added, no new API/config/dependency, and no commit. The finding was pending scope
direction at that point; the subsequent user decision deferred it. Detailed evidence: `spec-03-investigation.md`.

SPEC-04 is implemented, verified, and committed as `d4f0a5e66b` on explicit request on 2026-09-23 (baseline `c5d611c395`).
RFC 8414 section 2 and OpenID
Connect Discovery section 3 define the omitted grant list as authorization_code/implicit, not unrestricted support.
Both configured-target and deferred-endpoint omission cases were reproduced before production edits. The shared Token
Exchange validator now uses the existing DEFAULT_GRANT_TYPES_SUPPORTED constant, retaining the discovery-loaded guard
and existing failure handling. Wholly static configuration, valid-token caching, admission, and other grants are unchanged.
README now distinguishes an omitted member in loaded discovery from not using discovery at all. No new API, option,
helper class, dependency, Common/legacy change, or automatic fallback. Three tracked files only.
Tests cover six grant lists on both paths, repeat calls, controlled failures before Token Endpoint I/O, no generated
Authorization on rejection, metadata/token caching, tenant readiness, and static controls with unavailable discovery.
Final validation: 222 focused tests; all 1,558 module tests; all 42 synthetic integrations; two focused real-Keycloak
Token Exchange/Client Credentials tests; production Checkstyle and 284-class maximum-effort static checks pass with
zero failures/errors/skips. Other 16 Keycloak cases were not rerun in this focused change. Final source review has no
in-scope findings. Source and built/installed artifact identities stayed unchanged through integrations.
Logs and fixture-preparation correction: `/tmp/oidc-spec04-grants.wgjmpC/`, detailed in SPEC-04 in confirmed-findings.md.
Commit recheck confirmed the exact reviewed/validated diff, successful logs, unchanged built/installed artifact identities,
and clean whitespace. No product edits or test reruns in the commit turn. Tracked tree/index clean; audit and unrelated
untracked artifacts are excluded. At that commit, two low-priority active items remained (SPEC-03, BUILD-01), plus deferred UX-02. SPEC-06
remains withdrawn and CORR-02 remains clarified/closed. No external reporting issue or external worklog.

Historical recommendation: SPEC-03, rechecked read-only at `d4f0a5e66b`. Query transport is explicitly opt-in/default false.
Extraction still collapses header/query credentials into a bare token and success uses AuthenticationResponse.success
without cache headers. RFC 6750 section 2.3 recommends Cache-Control: private on successful 2xx query-token responses
(SHOULD, not MUST). Preserve source information and verify final HTTP cache policy without weakening application no-store
or equivalent stricter protection. Ordinary header transport and failed authentication should retain their behavior.
The existing SecurityHandler copies responseHeaders before continuing; HttpSecurityInterceptor's SUCCESS path uses
requestHeaders instead, so a provider-only assertion would not prove coverage of every HTTP integration. Account for
that boundary without silently changing shared/legacy behavior. No new runtime reproduction or implementation here.
BUILD-01 remains the other low-priority item: direct HTTP/Common Socket dependency declarations, not a protocol issue.

CFG-06 is implemented, verified, and committed as `c5d611c395` on explicit request on 2026-09-22 (baseline `a253646a0c`).
Only the existing discovery
capability guard changes: REQUIRED still requires an advertised issuance capability; IF_PRESENT accepts false/omitted
metadata. The RFC 8705 false default, static configuration, DISABLED policy, and per-token certificate-proof checks are
unchanged. No new API, configuration, type, dependency, Common/legacy change, or automatic exchange.
Verified baseline reproduced four IF_PRESENT matrix failures and eight corresponding authentication failures before
the production edit. The updated tests cover 18 mode/metadata/method combinations, plus 16 static/discovery TLS
scenarios and 96 actual downstream requests with matching/different/absent certificates and unbound controls. Reused
existing test fixtures. ServerTest does not support the original dynamic matrix shape; an ordinary test with assertAll
preserves all cases without framework changes. This harness correction is not a provider defect.
Final validation: 279 focused tests; all 1,558 module tests; all 42 synthetic integrations; six focused real-Keycloak
JWT/introspection tests; production Checkstyle and 284-class maximum-effort static checks pass. All test runs have zero
failures/errors/skips after the fix. Other 12 Keycloak cases were not rerun in this focused change. Final source review
has no in-scope findings; source and built/installed artifact identities remained unchanged through integrations.
Logs: `/tmp/oidc-cfg06-metadata.aH1tMs/`. Details and validation history are in CFG-06 in confirmed-findings.md.
The commit contains only the four reviewed files (factory, README, two existing tests). Commit recheck confirmed the exact
validated diff, successful logs, unchanged built/installed artifact identities, and clean whitespace. No extra product
edit or test rerun in the commit turn. Tracked worktree/index clean; audit and unrelated untracked artifacts excluded.
No external reporting issue or external worklog.

Historical recommendation: SPEC-04, rechecked read-only at `c5d611c395`. Token Exchange capability validation skipped an omitted
grant_types_supported list (OidcTenantContextFactory:658-679), unlike Client Credentials, which uses the existing
authorization_code/implicit default (:604-619). RFC 8414 section 2 and OIDC Discovery section 3 give that default, which
does not include Token Exchange. The same helper serves configured targets and deferred endpoint policies. Propose
using the existing default consistently only when discovery was actually loaded, keeping static configuration unchanged,
updating the two README statements, and testing missing/default/empty/explicit lists on both paths. This is metadata
consistency/fail-early behavior, not a demonstrated authentication bypass. No next-item implementation or fresh runtime
probe in this turn.

SPEC-06 is withdrawn from the confirmed fix list after the same-turn normative/source recheck. RFC 7516 section 4 refers
to RFC 7515 section 4, which permits last-value duplicate handling. Both specifications use the same resulting-header
uniqueness wording in section 5.2 step 4, so that wording alone does not establish mandatory raw duplicate rejection for
compact JWE. Current parsing consistently keeps the last value; original protected-header bytes remain authenticated.
No internal parser differential/exploit was established. Do not introduce a JSON/JWE parser change on this finding's
former rationale. Details are in the findings annex. At that point, three low-priority items remained, plus deferred UX-02.

CORR-02 is clarified/closed on 2026-09-22 at baseline `8ec3b34d9f`; the four-file documentation/test change is committed
as `a253646a0c` on explicit request.
Real downstream mTLS proves matching proof succeeds and absent/different proof rejects bound tokens with 401 invalid_token;
JWT/introspection, unbound controls, and target/endpoint selection are covered. A universal propagation incompatibility
or library-level rejection requirement was not established. This is not a claimed runtime/security fix. README and
existing policy/configuration Javadoc now distinguish header preparation, OP/AS TLS, and application transport proof,
including the RFC 8705 section 6.5 integration qualification. No blanket ban, implicit exchange, or proof-key API.
Reused Common Keys/Tls and existing certificate/JWK/test helpers. No new production behavior, type, configuration,
dependency, Common, legacy OIDC, or shared Security/WebClient change. Final focused review has no in-scope findings.
Validation: 1,547 module tests; after final direct-resource Javadoc wording, 25 propagation tests and static checks
rerun; all 42 synthetic integrations and one focused real-Keycloak propagation integration pass on the final artifact.
Checkstyle and 284-class maximum-effort static analysis pass. Other 17 Keycloak cases were not rerun for this
documentation/test-only change. Sources and built/installed artifact identities remained stable through integrations.
Details, fixture preparation corrections, limitations, and logs are in the CORR-02 section of confirmed-findings.md.
Logs: `/tmp/oidc-corr02-propagation.fe7DoB/`. Commit recheck confirmed the exact previously reviewed/validated diff,
successful logs, unchanged built/installed artifact identities, and clean whitespace. No product edits or test reruns
in the commit turn. Tracked worktree/index are clean; audit notes and unrelated untracked artifacts remain excluded.
At that commit, five low-priority items remained; UX-02 remains deferred.

Historical recommendation: CFG-06, rechecked read-only at `a253646a0c`. Discovery initialization required the certificate-bound
issuance capability for every mode except DISABLED (OidcTenantContextFactory:978-1003), including IF_PRESENT. That mode
accepts unbound tokens at runtime (OidcCertificateBoundAccessTokenSupport:63-66), so a conforming issuer omitting the
optional flag or advertising false cannot initialize under that otherwise compatible validation policy. The existing
well-known metadata test explicitly expects this failure. RFC 8705 section 3.3 defines the flag as issuance capability
and omission as false, not a requirement to block a local conditional validator. Propose restricting this initialization
check to REQUIRED, retaining actual per-request proof validation in IF_PRESENT, and covering all mode/flag combinations.
This is configuration/interoperability correctness, not an authentication bypass or an RFC-defined IF_PRESENT mode.
No CFG-06 implementation or new runtime reproduction in this commit/recommendation turn.

CONC-03 Client Credentials admission is implemented, verified, and committed as `8ec3b34d9f` on 2026-09-22
(baseline `f8f1ad493f`), completing the finding with the earlier committed JWKS/tenant slices. The existing
bounded single-flight path now receives a per-tenant client-credentials-remote-work limiter (32 active/128 queued/PT1S
active admission); admitted same-key followers have no added deadline. Root/named parity, caching, cancellation, overflow,
expiry, and failure recovery are verified. Mixed grants and a controlled retry prove deferred discovery is already bounded
by grant admission, so no separate resolver limiter is added. All 1,543 module tests, 42 synthetic integrations, 18 Keycloak
tests, Checkstyle, and 284-class static checks pass. Final focused review has no in-scope findings; built/installed hashes
match before and after integration validation. The commit review corrected one unused exception binding to `_` for
Rule 1.5; Checkstyle and all 170 focused grant/cache/refresh/configuration tests pass after that naming-only cleanup.
The full suites/static analysis precede that cleanup and were not rerun in the commit turn. Tracked worktree/index
are clean; audit and unrelated untracked artifacts are excluded. See `conc-03-client-credentials.md`.
Shared WebClientSecurity's existing
proceed-on-provider-failure behavior is documented but unchanged; do not promise automatic HTTP suppression/503.

Historical pre-change CORR-02 recheck at `8ec3b34d9f`: the mismatched-identity two-hop case fails by RFC 8705 section 3, but the
RFC does not prescribe a blanket propagation ban. Inbound binding verification already exists. Outbound propagation
checks audience/transport but does not establish the actual outgoing TLS certificate; tenant webclient configuration is
for OP/AS calls, not the application's downstream client. A matching configured outbound identity can be valid, and
section 6.5 permits securely integrated TLS termination. Treat this as a deployment-dependent compatibility/diagnostics
finding, not an unconditional RFC violation or authentication bypass. A guard must preserve valid proof-bearing cases;
Token Exchange is a possible configured alternative only when issuer policy permits it. No CORR-02 implementation or
new runtime probe in this commit/explanation turn; the detailed finding records the qualification.

CONC-03 tenant initialization is implemented, verified, and committed as `f8f1ad493f` (baseline `b1321559bf`). The user
chose explicit retry/lifecycle coordination with existing admission support, not a blanket LazyValue conversion.
The new flat initialization-max-queued option defaults to 128; waiting is interruptible with no separate admission
deadline. Context reuse, backoff, shutdown ownership, and prior timed limiter callers are preserved. All 1,524 module
tests, 41 synthetic integrations, 18 real-Keycloak tests, production Checkstyle, and 284-class maximum-effort static
analysis pass. Final focused review has no in-scope findings; built/installed artifact hashes match before and after
integrations. Deferred metadata and Client Credentials were still open at that commit; the final slice is recorded above.
See `conc-03-tenant-initialization.md`. No Common/legacy changes; the tracked worktree was clean after that commit.

Historical next recommendation, rechecked read-only at `f8f1ad493f`: outbound Client Credentials admission. Its single-flight call
still has no limiter, so cache misses/expiry can retain uncapped same-key followers and run uncapped distinct-key loads.
Waiting is already interruptible. Reuse the bounded overload already used by Token Exchange, preserving cache/error
semantics and normal shared-result waiting. Before adding a separate deferred-metadata limiter, verify its production
entry paths: only elected Client Credentials/Token Exchange loaders invoke it, so bounding Client Credentials can also
bound the remaining discovery callers. That is a source-based inference to verify in the next implementation slice,
not a claim of completed remediation. No next-item code changes in this commit/recheck turn.

CONC-03 JWKS slice is implemented, verified, and committed as `b1321559bf` on 2026-09-21 (baseline `aa929b2df8`).
Reproduced the missing wait bounds and
cancellation; the implementation reuses the existing admission limiter for one coordinated key load plus bounded,
interruptible waiting. Flat jwk-set.max-queued (128) and admission-timeout (PT1S) preserve cache/rotation/retry/stale
policies. Overload propagates as unavailable, including safe post-refresh cookie removal. All 1,508 final module tests,
40 synthetic integrations, 18 real-Keycloak tests, production Checkstyle, and 283-class max-effort static analysis pass.
Final focused review has no in-scope findings; built/installed JAR hashes match before and after integrations. This is
only the JWKS slice at that commit; the subsequent tenant-initialization work is recorded above. See
`conc-03-jwks-implementation.md`. Common and legacy OIDC were untouched; the tracked tree was clean after that commit.

Historical next recommendation: tenant initialization, rechecked read-only at `b1321559bf`. First-use/retry requests can wait
behind discovery in TenantContextSlot.get's uninterruptible initializationLock, without a follower bound. Ready contexts
already bypass that lock. Reuse existing admission control with per-caller unavailable handling while preserving one
initializer, retry policy, tenant isolation, and close/late-initialization cleanup. This is availability hardening, not
an OIDC-prescribed queue limit or carrier-pinning claim. Deferred outbound metadata and Client Credentials remain later
CONC-03 slices. No next-slice implementation in this commit/recheck turn.

SEC-04 is implemented, verified, and committed as `aa929b2df8` on 2026-09-21 (baseline `98156899ea`). The baseline reproduced one
HTTP fetch during configuration for each of the three key inputs. Client assertion, ID Token, and UserInfo decryption
configuration now holds ResourceConfig descriptions and rejects URI/absent sources before key loading; runtime loaders
also guard sources. All local source forms, standalone/disabled/nested configuration, repeated/concurrent use, safe
diagnostics, and real signing/decryption are covered. Two small package-private Blueprint decorators use the existing
JOSE policy helper; no resource wrapper or new public helper/configuration key/dependency.

The deliberate programmatic type change is Resource to ResourceConfig. Local YAML syntax is unchanged. Consumers open
fresh local resources and retain parsed keys, rather than sharing a mutable stream; files must remain available when
new consumers initialize (including local logout). Supplied content provides an immutable snapshot and supports explicit
secure external-secret retrieval. This is a provisioning policy, not an OIDC requirement for filesystem-only storage.

Final validation: 1486 module tests, 39 synthetic integrations, 18 real-Keycloak tests, zero failures/errors/skips.
Production Checkstyle and configured max-effort static checks pass (281 classes, zero bugs/errors/missing classes).
Test-source style was reviewed manually; final focused review has no in-scope findings. Artifact hashes match before
and after integration validation. No Common, legacy, integration-source, or protocol-validation changes. See
`sec-04-implementation.md` for decisions, compatibility, test preparation corrections, and logs.

Pre-implementation recommendation (historical): CONC-03, rechecked read-only at `aa929b2df8`; begin with JWKS loading/refresh.
Coalescing already avoids duplicate upstream requests, but cold/refresh JWKS and tenant initialization use uninterruptible
locks with no follower cap. Deferred metadata waits are interruptible but uncapped. Client Credentials calls the
single-flight overload without a limiter, unlike Token Exchange. Existing limiter/coalescer helpers should be reused
where appropriate; do not redesign Common or implement all paths as one oversized change.

Qualification: valid warm-cache lookups already have fast paths, and network timeouts exist; this is not a claim that
every request blocks indefinitely or that virtual threads pin carriers. The missing component-level pending-call bound
allows traffic to accumulate request state during a slow load; impact depends on outer admission limits and traffic.
Make waiting bounded/interruptible while preserving cache, key-rotation, retry/backoff, stale-key policy, and shared-load
semantics. This is availability/resilience work, not an OIDC-prescribed numeric queue limit. No new runtime probe or
next-issue implementation occurred in that earlier commit/recheck turn; the current JWKS slice is recorded above.

LIFE-01 is implemented, verified, and committed as `98156899ea` (baseline `266eac658d`). A real private-pool
cleanup regression was reproduced before the fix. OidcProvider now has terminal, idempotent AutoCloseable ownership;
configuration-created features release their runtime on the last active registration's stop. Provider-bound features
borrow and do not close their owner. Late initialization cannot reactivate a closed runtime or leak its client.

All 1406 final module tests, 39 synthetic integrations, and 18 real-Keycloak tests pass, with zero failures/errors/skips.
Production Checkstyle and configured max-effort static analysis pass (279 classes, zero bugs/errors/missing classes).
Test-source style was reviewed manually; the integration parent skips Checkstyle. Final implementation review has no
in-scope finding. Built/installed JAR checksums match, and neither artifact nor code changed during integrations.
Tests cover real private-connection closure, shared-provider ownership, default shared-pool preservation, copied/reused
routing builders, named sockets, startup rollback, and virtual-thread close/init races. No Common/legacy changes, new
configuration/dependency, or protocol-validation change. See `life-01-implementation.md` for evidence and scope boundaries.

The read-only SEC-04 recommendation at `98156899ea` is addressed by the work above. Its scope remains configuration-
dependent private-key confidentiality/availability hardening, not a demonstrated unauthenticated SSRF or login bypass.
The earlier CORR-01 stream-reuse fix remains satisfied through fresh resources per consumer; its original buffering
mechanism has been superseded by the explicitly documented ResourceConfig source contract.

DESIGN-01 is implemented, verified, and committed as `266eac658d` (baseline `2ddded7a96`). The provider retains its tenant
registry and one new `OidcFeature.create(OidcProvider)` overload reuses it. This is the only public API addition;
the registry accessor is package-private. Existing configuration factories remain available for independent features.
No new classes/options/dependencies, global cache, configuration-owned runtime, or lifecycle work.

Validation: reproduced two discovery requests in one full login before the fix; the shared path now makes one.
All 1386 module tests, 39 synthetic integrations, and 18 real-Keycloak tests pass, along with Checkstyle and configured
maximum-effort static/security analysis (278 classes, zero bugs/errors/missing classes). Coverage includes config-loaded
providers, lazy initialization, virtual-thread traffic, shared JWKS use, provider isolation with identical configs, and
the shared-runtime logout/refresh race. Packaged/installed JAR payloads are byte-identical. Final review has no findings.
See `design-01-implementation.md` for scope, reasoning, intermediate results, and logs.

DESIGN-02 is implemented, verified, and committed as `2ddded7a96` on 2026-09-18 (baseline `7024326c0e`). Callback handoff uses
enabled GET endpoint configuration, origin/decoded-path matching, and the original query parameters. Normal application
queries no longer suppress session authentication or login. Bearer precedence and callback protocol validation remain
intact. Protected state still requires an absolute callback URI; local configuration shorthand is resolved separately.

Validation: four pre-fix failures reproduced; all 1382 module tests, 38 synthetic integrations, and 18 real-Keycloak
tests pass, as do Checkstyle and configured maximum-effort static checks (278 classes, zero bugs/errors/missing classes).
Literal/encoded callback paths, fixed repeated/encoded query values, unknown response fields, malformed callbacks,
multi-tenant/disabled-flow boundaries, and actual provider composition are covered. Final review has no additional
finding in this change. See `design-02-implementation.md` for decisions, intermediate failures, commands/logs, and scope.

Nine tracked files committed: five existing production classes, README, two module tests, and one synthetic integration
test. No new public API, configuration, class, cookie format, blocking mechanism, Common change, or legacy-provider
change. The Common reuse catalog now records why UriInfo.toUri() must not be reparsed for protocol query validation.
Unrelated untracked artifacts remain preserved. The previous UX-01 fix is committed as `7024326c0e`; IDCS validation
remains with the user, and this routing fix adds no migration requirement.

UX-02 is deferred by explicit user decision on 2026-09-18: parallel-login behavior is considered too obscure to prioritize.
Its evidence remains recorded, but it is removed from the active fix queue. Do not implement or re-propose it unless the
user reopens it.

The earlier DESIGN-01 exploration/proposals remain in the finding as history. The implemented minimal version preserves
existing factories and adds only the provider-taking overload; config-loaded code reuses Security's existing named lookup.
Nine tracked files were committed, only two of them production classes. Common and the legacy provider are unchanged.
LIFE-01 was separate from the runtime-sharing commit and is now addressed by `98156899ea`. Its impact
qualification still matters: HTTP pools are intentionally JVM-shared by default. This fix releases owned resources,
including private pools, without evicting shared pools or letting one borrowing feature close another consumer's runtime.
Lifecycle-hook dispatch failures in unrelated WebServer features are outside this change; explicit provider close is
available independently of hook delivery. UX-02 remains deferred.

## Completed

- Located 25 unit-test classes plus one helper, 8 synthetic integration-test classes plus one helper, 12 Keycloak
  integration-test classes plus two helpers, 121 production Java files (18,015 lines), the module
  POM/descriptor/README, and 41 locally downloaded specification documents.
- Created an isolated workspace for this review.
- Locked prior-review exclusions before reading implementation content for this audit.
- Ran the complete Java 27 unit suite outside the socket-restricted sandbox: 740 tests, 0 failures, 0 errors, 0 skipped.
- Mapped all 25 generated configuration types and their root/tenant translation path.
- Reviewed provider/service/feature entry points, tenant resolution, runtime slots, initialization retry coordination,
  failed-client cleanup, endpoint policy resolution, and the tenant WebClient isolation path.
- Reviewed Authorization Code request/callback processing, protected browser state, local authentication cookies,
  refresh, logout, request objects, PAR, Token Endpoint operations, ID Token/JWT access-token validation,
  certificate-bound access tokens, introspection, UserInfo JSON/JWS/JWE, client authentication, JOSE key policy, and
  remote JWKS refresh behavior.
- Independently reproduced the single-use client-assertion resource failure and the static-introspection metadata
  failure with focused runtime probes.
- Reviewed outbound target matching, Token Propagation, Client Credentials, Token Exchange, deferred discovery,
  per-key token caches, single-flight behavior, admission control, and subject/principal mapping. Reproduced the remote
  work queue-bound violation under concurrent virtual-thread callers.
- Completed the Java 27 module `verify` lifecycle: 740 unit tests passed and the JAR was built.
- Completed all local synthetic integration tests: 28 passed, 0 failed/errored/skipped.
- Completed all Keycloak/Testcontainers integration tests: 18 passed, 0 failed/errored/skipped.
- Ran repository Checkstyle: zero violations. Ran SpotBugs with FindSecBugs: zero reported bugs across 265 analyzed
  production/generated classes and no missing analysis classes.
- Ran Maven dependency analysis and separated true direct-dependency drift from expected umbrella/service-provider
  dependencies.
- Verified generated `toString` redaction for every `@Option.Confidential` config/state property. Reviewed supported JWE
  configuration against the actual shared JWT encryption/decryption primitive.
- Cross-checked OpenID Provider JWKS rules, certificate-bound token metadata/propagation, token lifetime boundaries,
  concurrent browser login state, and callback-route discrimination against reachable code paths.
- Completed the advertised-standard traceability matrix, explicit unsupported boundary, quality/Common reuse appendix,
  final severity calibration (6 high, 18 medium, 5 low), and root executive report.
- Implemented and verified the post-review remediation for `SEC-01`; recorded current-working-tree evidence in
  `remediation-log.md`.
- Committed `SEC-01` as `917843c455`.
- Implemented and verified `SPEC-01`: authorization and PAR redirects now use Common's form-safe, multi-value query
  writer path. The complete module suite passes 753 tests; Checkstyle and SpotBugs/FindSecBugs are clean.
- Committed `SPEC-01` as `667960ec08`.
- Implemented and verified tenant-scoped refresh single-flight with a short bounded late-arrival grace cache, exact
  source-session fingerprints, per-tenant admission, interruption-safe virtual-thread waits, and non-mutating 503
  overload behavior for expired sessions (`CONC-01`).
- Changed remote-work queue admission to immediate exact slot reservation, closing unbounded overflow outside
  `max-queued` for refresh, introspection, and Token Exchange (`CONC-02`).
- Verified the concurrency slice with 767 module tests, 28 synthetic integration tests, 4 focused Keycloak
  refresh/logout tests, Checkstyle, and SpotBugs/FindSecBugs.
- Committed `CONC-01` and `CONC-02` as `962d3114ab` on 2026-09-17; unrelated review and migration documents remained unstaged.
- Implemented `SPEC-02` in the shared JWE decryptor and removed UserInfo's weaker duplicate check. Authentic ciphertext
  reproduced the pre-fix defect; regression coverage includes four validation paths, cookie restoration, and HTTP callbacks.
- Verified `SPEC-02` with 828 module tests, 28 synthetic integration tests, Checkstyle, and SpotBugs/FindSecBugs.
- Committed the six SPEC-02 product/test/documentation files as `103fe50998`; unrelated review and migration files remained unstaged.
- Implemented SEC-03 using the existing per-request WebClient redirect setting. Both initial and refreshed JWKS stay at
  their configured/discovered endpoint. Rechecked the actual standards and documented no-redirect as the selected policy,
  not a standards prohibition on every redirect.
- Verified SEC-03 with 101 focused TLS cases, 929 module tests, 28 synthetic integration tests, and clean static analysis.
- Committed the four SEC-03 product/test/documentation files as `53be9c06ea`; unrelated review and migration files remained unstaged.
- Implemented SEC-02: default issuer-subject identity across browser/JWT/introspection, explicit authority-qualified
  resource claim mapping, safe issuer-less introspection namespaces, and ID Token identity preservation during refresh.
- Reproduced conditional cross-issuer record access before the change (200 instead of 403) and verified owner/non-owner
  isolation afterward with legitimate JWT and introspected tokens.
- Verified SEC-02 with 960 module tests, 31 synthetic tests, all 18 Keycloak scenarios, Checkstyle, and configured static
  analysis. The full Keycloak run exposed one old raw-ID assertion; all 10 affected identity-flow cases passed on rerun.
- Updated user documentation and reviewed the changed code against the applicable current Helidon guideline rules.
- Committed SEC-02 as `04fd93333f` on explicit user request; the tracked worktree is clean.
- Implemented CORR-01 with Common Resource buffering before configuration publication. On user request, removed the
  unnecessary Resource wrapper, defensive snapshots, and shared parsed-key cache; restored normal key loading unchanged.
- Verified simplified CORR-01 using 13 added tests, including stream preparation/failure/closure, 128-way virtual-thread
  assertion generation, independent Nimbus signature verification, deferred discovery, inherited introspection, and
  provider/feature callbacks. Client identity, audience, key selection, algorithm, lifetime, and assertion freshness
  remain independent.
- Final simplified CORR-01 checks: 973 module tests, 31 synthetic tests, Checkstyle, and 274-class configured static
  analysis all passed. Keycloak was not rerun for this simplification; earlier wrapper-version results are historical.
  Documentation, progress, and the user's preference for avoiding unnecessary functionality were saved.
- Committed simplified CORR-01 as `53f9e88d7f` on explicit user request. No unrelated documents were included.
- Reproduced CFG-01 with eight HTTP tests: the four static JWT configurations failed and the four discovered controls
  passed. Fixed only the discovery capability validation guard, reusing the existing factory flag.
- Verified CFG-01 with inherited and separate assertion settings, independent HMAC/RSA signatures, fresh assertion IDs,
  discovery rejection cases, issuer-less static initialization with an identity namespace, and retained TLS/key checks.
- Final CFG-01 results: 989 module tests, 31 synthetic tests, Checkstyle, and 274-class configured static analysis passed.
  README and review progress were updated. Keycloak was not rerun for this slice.
- Committed CFG-01 as `2db9446dbe` on subsequent explicit user request; no unrelated documents were included.
- Implemented AVAIL-01 for Protected Resource introspection with the existing unavailable result/503 mapper and internal
  cause/status diagnostics. Preserved inactive-token and explicit local policy rejection; no acceptance fallback/retry.
- Verified 17 upstream HTTP status categories, unusable response handling, connection failure, timeout, ten interrupted
  virtual-thread reads, permit recovery, and same-token recovery through the real protected HTTP route.
- Final AVAIL-01 results: 1004 module tests, 32 synthetic integration tests, Checkstyle, and 274-class configured static
  analysis passed. Reused Common's bounded retry matcher for test cleanup. No production dependency or public API added.
- Removed tentative browser-refresh retention changes after checking RFC 6749 refresh-token rotation; existing refresh
  tests and production code remain unchanged. Documented that separate scope.
- Committed AVAIL-01 as `fb48a894ef` on subsequent explicit user request; no unrelated documents were included.
- Confirmed CFG-02 against the explicit shared-options API/README contract and reproduced seven failures in nine focused
  tests before changing production code; named-tenant/default-builder controls passed.
- Repaired both missing options in root-key detection, changed-option detection, and tenant copying. Reused generated
  defaults and existing config values; no new mapper, public API, or dependency.
- Verified root/config/builder parity, explicit defaults, root/named conflicts, custom tenant names, copy/reuse, interval
  validation, a real one-operation limiter, and retry at the configured two-second boundary.
- Final CFG-02 results: 1019 module tests, 32 synthetic integration tests, Checkstyle, and 274-class configured static
  analysis passed. README and review progress are updated.
- Committed CFG-02 as `3c9e15880e` on subsequent explicit user request; no unrelated documents were included.
- Confirmed CFG-03 against Discovery section 3, Client Registration section 2, and Core section 3.1.3.7; reproduced
  both signed-only false failures while the no-encryption-metadata control passed.
- Scoped encryption capability intersection to the existing required-encryption/key-configured settings, without
  changing actual token validation or adding registration/configuration APIs.
- Verified absent/empty/non-overlapping unused capabilities, configured optional/required encryption compatibility,
  malformed metadata rejection, mandatory signing support, and unchanged strict token/JWE checks.
- Final CFG-03 results: 1026 module tests, 33 synthetic integration tests, Checkstyle, and 274-class configured static
  analysis passed. Full browser discovery/login succeeds with unrelated advertised encryption. Notes and README updated;
  committed the five verified files as `21f8e9c3e6` on subsequent explicit user request.
- Rechecked CFG-04 against current tenant validation, shared `EncryptedJwt`, README, and RFC 8725 section 3.2.
  `RSA1_5` is accepted with a warning and documented as usable, but the shared primitive explicitly rejects it.
  Other unsupported nonblank ID Token `alg`/`enc` values also pass local configuration validation. This is a fail-fast
  correctness/documentation issue, not an established authentication bypass.

- Implemented and verified CFG-04 after reproducing 39 accepted-but-unusable configurations. Shared JWT support
  information now validates ID Token/UserInfo algorithms, and misleading legacy-algorithm documentation is corrected.
- Verified all advertised pairs with independent ciphertext and retained default/strict-registration behavior. Final
  results: 74 JWT tests, 1132 OIDC tests, 33 synthetic integrations, Checkstyle, and 340-class configured static analysis.
- Committed CFG-04 as `75f11da41e` on explicit request after explaining API and configuration compatibility. Exactly the
  eight verified product/test/README files were included; unrelated documents remain outside the commit.

- Implemented CFG-05 after reproducing all three configuration entry paths accepting a missing required decryption key.
  Existing enabled-tenant validation now rejects that combination; optional and disabled configuration remains valid.
- Corrected two invalid test fixtures without weakening their runtime/discovery checks; integration confirms no
  metadata/JWKS/token requests for rejected static/discovery configuration. Final verification: 1136 module tests,
  34 synthetic integrations, Checkstyle, and 274-class configured static analysis passed.

- Committed CFG-05 as `83e2555e1c`; only the seven verified product/test/README files were included.
- Rechecked SPEC-05 at the committed revision. The manager passes `jwkSetUriFromWellKnownMetadata()` as the public-only
  validation gate, while static URIs and explicit overrides retain false. Local and official Discovery section 3 require
  OP JWKS not to contain private/symmetric values. Keep this distinct from legitimate private RP keys and separately
  provisioned local OAuth validation secrets. No SPEC-05 implementation requested or made in the commit/status turn.

- Implemented SPEC-05 after proving static/override public-key policy gaps and existing local HMAC capability. All OP URI
  sources now validate public-only key material on initial load and refresh. Explicit local access-token resources preserve
  HMAC support without sharing keys with ID Token/UserInfo/Request Object consumers or adding a duplicate cache implementation.
- Corrected OP fixtures to public-only data while retaining a genuine two-public-key ID Token no-kid case. Verified
  confidentiality, local-source URI rejection, no fallback, mixed-flow discovery, empty-set revocation, and 64 virtual-thread
  callers. Final results: 1220 module tests, 34 synthetic integrations, all 18 Keycloak tests, and clean static checks.

- Committed SPEC-05 as `cecb927d18`; exactly the eighteen verified product/test/README files were included.
- Rechecked ROBUST-01 against current parsers, session expiry, refresh, outbound token managers, and RFC 6749 section 5.1.
  Zero-lifetime outbound tokens are still returned as successes and attached; extreme nonnegative lifetimes can overflow
  expiry arithmetic. Callback session creation lacks a local guard around that calculation. Refresh handling has changed
  since the base audit, so do not assume the original simple refresh-loop description without new runtime evidence.

- Implemented ROBUST-01 after reproducing all eight initial zero/huge-lifetime regressions. Shared expiry handling now
  rejects unusable responses before token use, saturates unrepresentable absolute deadlines conservatively, and avoids
  overflow in local session/skew comparisons. Missing/short-positive lifetime behavior is preserved and tested.
- Final ROBUST-01 verification passed 1304 module tests, 34 synthetic integrations, 18 real-Keycloak tests, Checkstyle,
  and 275-class configured static analysis. No new public API, configuration, threads, locks, or caches. Not committed.

- Committed ROBUST-01 as `18bce777f5` on the subsequent explicit request; the verified source and validation results
  are unchanged. Only its fourteen implementation/test/README files were staged and committed.
- Rechecked UX-01 at that revision: the cookie still combines complete tokens, optional UserInfo, and session metadata,
  with AES-GCM/Base64URL expansion and no final encoded-size guard. Neither Common HTTP SetCookie construction nor the
  OIDC callback/refresh send path supplies such a guard. Chromium's current cookie parser limits name plus value to
  4096 bytes; RFC 6265 section 6.1 describes minimum user-agent capacity, not a universal OIDC cookie-size MUST. This is
  an interoperability/login-availability issue, not a demonstrated authentication bypass. No new browser experiment
  or UX-01 regression tests were run in this source/spec recheck.

## Next

BUILD-01 is committed. The original implementation-fix queue is complete, with the recorded deferrals. The user requested
a separate OIDC specification feature-coverage
document, one specification at a time with incremental saves. Core is complete (44 source-backed feature/role/policy
entries), Discovery is complete (26 entries; all 35 metadata names), and Dynamic Client Registration is complete
(26 entries; all 30 client metadata/six response fields mapped, with no protocol client claimed). Session Management is
complete as of 2026-09-24 (14 entries; browser protocol missing, adjacent local session behavior distinguished).
RP-Initiated Logout is complete as of 2026-09-25 (22 entries; all six request parameters, both metadata fields,
URI/hint limits, local lifecycle and OP boundaries). All 132 feature rows, 90 source references and five-spec anchors
checked; the prior 110 feature rows are unchanged. Front-Channel Logout is complete as of 2026-09-25 (16 entries;
receiver missing, all four metadata fields and query/claim roles mapped, browser constraints and OP duties separated).
All 148 feature rows, 91 source references and six-spec anchors checked; the prior 132 feature rows are unchanged.
Back-Channel Logout is complete as of 2026-09-25 (30 entries; errata set 1, 15 December 2023): full field inventory and
all 11 validation steps, session/invalidation/refresh boundaries, responses and OP roles. All 178 feature rows, 91 source
references and seven-spec anchors checked; the prior 148 feature rows are unchanged. CIBA is complete as of 2026-09-25
(49 entries; Final, 1 September 2021): all modes/field inventories/errors and OP/application/privacy boundaries.
The full eight-spec document is complete: 227 entries, 93 source references, 136 eight-spec links checked. All 178
pre-CIBA feature rows are unchanged; added a concise overall implementation/reuse overview and removed stale progress
prose. No runtime edits, test reruns or new commit. The original eight-spec inventory is complete and uncommitted.
The user subsequently approved a separate, OIDC-only companion-RFC pass, one RFC at a time. RFC 9700 is complete for
the scoped OIDC authorization-code RP as of 2026-09-25: thirty entries plus section/role map for transaction/mix-up,
redirect/leakage, TLS/proxy, client authentication, metadata, token storage/refresh, sender constraints, request integrity
and OP/browser boundaries. All 30 evidence links and 29 RFC links checked. The original 1,295-line OIDC inventory is
unchanged against its initial snapshot. No new exploit was established, no runtime edits/tests/commit; tracked tree/index
remain clean at e015f55. RFC7636 is now complete (2026-09-25): twenty entries, section/role map and qualified errata notes.
All 50 RFC feature rows, 34 source references and 51 RFC URLs/anchors checked. Prior 30 RFC9700 rows and original eight-spec
inventory are unchanged; only RFC9700's next-pass routing sentence changed. Local RFC source unchanged; no runtime/test edits.
New companion-document finding 7636-F01: confidential clients can select plain although this RP supports S256, contrary to
RFC7636 section 4.2. Default/public S256 is unaffected; no default exploit or automatic downgrade retry claimed. No runtime
fix requested/performed; keep this separate from the prior implementation queue. Tests were inspected, not rerun. An
independent Appendix B known-answer regression is suggested separately, not as another defect.
The user-approved RFC9207 pass is now complete: twenty entries, section/role map and source-level finding 9207-F01 saved
(2026-09-25). Distinct OP configurations can accept one issuer without cross-AS identity enforcement; a configured
malicious OP with unpinned metadata can claim an
honest issuer, causing valid returned iss to pass before the code/verifier is sent to its wrong Token Endpoint. Preconditions
and no-live-exploit boundary are documented; genuine same-OP multi-client tenants must remain supported. No runtime fix.
Transport/alternative-response scope, policy limits and focused test follow-ups are recorded. All 70 RFC feature rows,
41 source references, 66 RFC URLs/anchors and 19 table structures checked. All 50 prior rows and 7636-F01 are unchanged;
only the prior next-pass routing sentence changed. The original OIDC inventory/local RFC9207 hashes are unchanged.
Tracked tree/index remain clean at e015f55; no runtime changes, tests or live exploit probes. The user approved continuing
on 2026-09-29; RFC9101 is complete with thirty entries, conditional conformance finding 9101-F01, a section/role map and
separate quality/reuse notes. All 100 RFC rows, 58 source references, 95 RFC URLs/anchors and 26 table structures checked.
All seventy prior rows/findings are unchanged; only RFC9207's next-pass routing sentence changed. Original OIDC inventory
and local RFC9101 hashes are unchanged; tracked tree/index still clean at e015f55.
The assessed Temurin 25.0.4+7 HTTPS verifier permits CN fallback without DNS SAN, contrary to RFC9101 section 8's identity
profile. This is source/bytecode evidence, not a TLS handshake/MITM test; trusted chain still required and mismatched DNS
SANs fail. Common and legacy code are untouched. No partial JAR work was present after the interrupted turns. No tests,
handshakes, OP probes or benchmarks were run. Quality notes identify Rules 8.2/2.1 and repeated signing-key resolution during
tenant initialization, separately from the conditional conformance gap. The user-approved RFC9126 pass is complete with
twenty-five entries and source-confirmed interoperability finding 9126-F01 saved (2026-09-29). The PAR success check compares Status
instances, so a valid HTTP/1.1 201 with custom/empty reason text is misread as failure and becomes authentication-unavailable
(503). This is not an authentication bypass or executed OP test. Numeric 201 comparison is the focused unimplemented remedy.
All feature roles, synthesis and separate quality/reuse notes are saved. All 125 rows, 70 evidence paths, 118 assessed-RFC
URLs/anchors and 32 tables are checked; the supporting HTTP status-line reference was verified separately. All 100 earlier
rows/findings and 58 earlier reference definitions are unchanged; only RFC9101's next-pass routing sentence changed.
Original OIDC inventory/local RFC9126 hashes are unchanged; tracked tree/index remain clean at e015f55. No runtime tests,
OP probes, benchmarks or code changes were performed in that PAR pass. Documents/progress
and prior findings remain uncommitted; no RFC-phase runtime fix is implemented. The user-approved RFC8414 pass is complete
with thirty entries saved (2026-09-29) and two confirmed source-level findings:
8414-F01 rejects valid custom/empty-reason HTTP200 metadata and causes retryable initialization failure. 8414-F02 can fetch
explicit HTTP metadata despite tls-required=true when static auth/token endpoints coexist with missing JWKS; an active HTTP
response attacker can redirect default AUTO PAR to its HTTPS endpoint and obtain Basic/post client secrets. Specific config
preconditions and no-executed-attack limits are documented. All feature roles, synthesis and quality/reuse notes are saved.
All 155 rows, 75 evidence paths, 143 assessed-RFC URLs/anchors and 40 tables are checked; supporting HTTP status-line text was
already verified during PAR and the current source trace rechecked. All 125 earlier rows/findings and 70 reference definitions
are unchanged; only RFC9126's routing sentence changed. Original OIDC inventory/local RFC8414 hashes are unchanged; tracked
tree/index remain clean at e015f55. No automatic RFC8414 prefix-style lookup or signed_metadata processing is implemented;
explicit well-known-uri is available and ignoring unsupported signed bundles is permitted. Do not mistake the correct OIDC
append algorithm for the RFC8414 transformation. That metadata pass made no runtime changes or tests/probes/commits; all six
RFC-phase findings remain unimplemented. The user-approved RFC7523 pass is complete with twenty-five entries (2026-09-29)
and no new confirmed security/mandatory-protocol finding. All substantive sections 1–8 were read; optional profile limits,
section map and quality/reuse notes are saved. Rules2.1/10.6, HMAC material work, duplicate initialization key loading,
lifetime precision and focused concurrency/error tests are separate improvements, not new protocol defects. All 180 rows,
85 evidence paths, 162 assessed-RFC links/anchors and 46 tables are checked; supporting Core/guideline anchors verified.
All 155 earlier rows/six findings and 75 earlier definitions are unchanged; only RFC8414's routing sentence changed. Original
OIDC inventory/local RFC7523 hashes are unchanged; tracked tree/index remain clean at e015f55. No runtime/test/Common/legacy
changes, test execution, probes, benchmarks or commit. This pass concerns OIDC client authentication, not the separate
JWT-bearer grant or standalone JWT/JOSE formats. The user clarified and approved RFC8705 as an OAuth extension relevant to
provider support; the pass is complete with thirty documentary entries (2026-09-29). Authentication and bound-token
mechanisms are assessed separately, keeping RP/OP/RS roles distinct. Two source-confirmed alias findings are saved:
8705-F01 gates aliases on TLS OAuth authentication methods, missing binding-only mTLS with Basic/JWT/NONE; a conventional
non-certificate listener can cause failure or permitted unbound-token fallback. 8705-F02 ignores an advertised OP UserInfo
mTLS alias, causing bound-token UserInfo/login/refresh failures even with the TLS authentication methods. Preconditions and
source-only/no-executed-attack limits are explicit. All binding/lifecycle/security roles, synthesis and quality/reuse notes
are saved. Pure RP refresh and optional browser AT validation limitations are distinguished. All 210 rows, 97 evidence
paths, 199 assessed-RFC links/anchors and 54 tables are checked; supporting Discovery/guideline anchors verified. All 180
earlier rows/six findings and 85 earlier definitions are unchanged; only RFC7523's routing sentence changed. Original OIDC
inventory/local RFC8705 hashes are unchanged; tracked tree/index remain clean at e015f55. No runtime/test/Common/legacy
changes, test execution, handshakes, probes, benchmarks or commit. Eight RFC-phase findings remain unimplemented.
On 2026-09-29 the user asked to verify DPoP non-support and mark it unsupported. The module README already explicitly records
that boundary; the Bearer-only Token Endpoint parser/UserInfo client and JWT/introspection rejection guards/tests agree.
RFC9449 is now marked intentionally unsupported in the sequence table and a short section 9 disposition, not a new finding
or ninth detailed RFC pass. Its full review is skipped at the user's direction; earlier plans to assess DPoP are superseded.
No runtime changes, tests or commit in that disposition turn. The subsequent RFC9470 step-up pass is complete with twenty
entries (2026-09-29). End-to-end support is not implemented: no resource challenge generation/consumption, first-class
acr_values/max_age request/metadata handling or challenged-resource continuation. Existing prompts, generic safe callback
errors, JWT/introspection claim exposure and conditional ID Token auth_time refresh comparison are reusable pieces, not
complete protocol support. Prompt=login/max_age=0 OP semantics and local-cookie acceptance are explicitly distinguished.
The feature could fit Helidon's RP/RS roles with application/OP coordination; unlike DPoP it is not intentionally excluded.
No new numbered security/protocol finding was promoted. Separate quality notes cite Rules1.2.1/1.2.2 (explicit public null
acceptance), 8.2 (Blueprint constant), 2.1 (member order), 3.1 (qualified type) and 1.5 (unused catch binding), with Rule0.1
for genuine exceptions.
Reuse and tests/UX boundaries are saved separately; no feature implementation is scheduled by this inventory.
All 230 feature rows, 61 tables and 109 evidence definitions/108 paths are checked; new RFC/Core/guideline anchors resolve.
All 210 earlier rows/eight findings and 97 earlier definitions remain unchanged; the first eight detailed RFC sections
are byte-identical, with only DPoP's routing sentence changed. Original OIDC inventory/local RFC9470 hashes are preserved;
tracked worktree/index remain clean at e015f55. No code changes, test execution, live OP/resource/MFA/attack/replay probes,
benchmark or commit in that pass. The subsequent RFC8707 Resource Indicators pass is complete with twenty-five entries
(2026-09-29), bringing the total to ten detailed RFC passes / 255 entries. Static configured resources are carried through
OIDC query/JAR/PAR/code redemption/refresh. Per-call subset selection/resource-specific token portfolios are a documented
intentional limit of the static-login model, not a new MUST violation. Resource/scope/AS audience/RP audience/destination
roles and deployment/privacy obligations are distinguished.
New 8707-F01: Java URI-based validation accepts raw non-ASCII and unescaped query brackets outside RFC3986; the unchanged
semantic values can be sent as resource. An isolated actual-helper diagnostic on JDK25.0.4 reproduced both invalid cases
and valid escaped/ordinary URI/URN plus relative/fragment controls. This is a configuration-dependent conformance/
interoperability gap, not a demonstrated security exploit or live OP failure. Common UriValidator query-component checks
are relevant reuse; URI.toASCIIString alone leaves raw brackets and is insufficient. No fix was made.
Separate quality notes cover the validation/encoding reuse boundary, membership-only LinkedHashSet overhead (unmeasured),
Rule2.1 ordering in OidcTokenResponse, resources Javadoc and focused tests. Existing test bodies were inspected, not run.
All 255 feature rows, 71 tables and 113 evidence definitions/112 paths are checked; new RFC/guideline/README anchors resolve
and supporting official RFC3986/JDK text was verified. All 230 earlier rows/eight findings and 109 earlier definitions are
unchanged; only RFC9470's final routing sentence changes. Original OIDC inventory/local RFC8707 hashes are preserved;
tracked tree/index remain clean at e015f55. No production/test/Common/legacy edits, project test suites, live OP/resource/
registration requests, attack/replay probes, benchmarks or commit. Only the isolated helper diagnostic ran. Nine RFC-phase
findings remain unimplemented. The final approved RFC9396 RAR pass is complete with thirty entries (2026-09-29): RAR is
not implemented end to end, matching README's unsupported/queued boundary. Request input/structured JAR integration,
token request selection, effective/enriched token response data/state and supported-types metadata are missing. Generic
errors and raw JWT/introspection JSON are usable pieces, not RAR semantics; structured principal attributes are JSON text.
Scope=openid can coexist with RAR; resource does not narrow authorization_details. Type-specific comparison/enrichment,
AS consent/policy, privacy/display risk and the explicitly hypothetical AppendixA.1 OpenID type are distinguished.
No new numbered security/protocol or newly confirmed guideline finding. Reuse/design/test notes are separate; no feature
implementation is scheduled. All 285 feature rows, 80 tables and 115 evidence definitions/113 paths are checked, along with
new RFC9396/JAR/guideline/README anchors. All 255 earlier rows/nine findings and 113 earlier definitions are unchanged;
only RFC8707's final routing sentence and the overall completion/scope header were updated outside the new section.
Original OIDC inventory/local RFC9396 hashes are unchanged and tracked worktree/index remain clean at e015f55. No source
changes, tests/new diagnostics, OP/resource/registration calls, consent/attack probes, benchmarks or commit in the RAR pass.
The agreed RFC sequence is complete: eleven detailed passes / 285 entries, plus DPoP intentionally unsupported with its
full pass skipped. Subsequently, the user authorized 8414-F02 and it is now fixed/verified in the working tree as recorded
above; eight RFC-phase findings remain unimplemented. No more RFCs are queued; do not broaden the inventory or begin the
next fix/feature without user direction. The original 227-entry/eight-spec OIDC inventory remains frozen.
New deliverable: `security/providers/oidc-next/OIDC_RFC_COVERAGE.md`; progress: `oidc-rfc-coverage-progress.md`.
Keep the original eight-spec document unchanged and do not expand into unrelated OAuth or standalone JWT/JOSE reviews.
Deliverable:
`security/providers/oidc-next/OIDC_SPEC_COVERAGE.md`, new and uncommitted.
See `oidc-spec-coverage-progress.md`; no runtime change or certification claim accompanies the capability inventory.
SPEC-03 and UX-02 remain deferred; do not reopen them without direction. Keep Common and the legacy provider unchanged;
IDCS validation remains with the user.

## Working rules

- Save status and evidence at every slice boundary and whenever a finding becomes confirmed.
- Do not open, search within, quote, or use any file listed in `scope.md` under prior-review exclusions.
- A real finding needs a reachable code path, concrete violated invariant/spec requirement, user/security impact, and
  source/spec evidence. Missing tests alone are not a product defect.
- Keep security/spec/design findings separate from optimization, Common reuse, code quality, tests, and documentation.
- Re-check cross-file assumptions before promotion from candidate to confirmed.

## Transparency

Before this review was requested, a broad memory-discovery command used during the Helidon Common task printed portions
of existing OIDC memory into the conversation. No prior review document will be consulted during this audit. To mitigate
the unavoidable prior exposure, every reported issue must be independently reproduced or proven from the current source,
tests, and local specifications; prior labels, priorities, and conclusions are not evidence.
