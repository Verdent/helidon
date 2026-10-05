# OIDC provider contract tests

`OidcProviderContract` runs the same 38 scenarios against real Docker identity providers.
`AutheliaOidcIT` and `KeycloakOidcIT` select adapters; the adapters configure native clients,
users, keys, callback registration, and interactive login. They do not change the shared
assertions or supply synthetic tokens.

## Shared coverage

| Area | Scenarios |
| --- | --- |
| Discovery | Configured issuer and HTTPS endpoints |
| Browser login | Authorization code with S256 PKCE; confidential and public clients |
| Client authentication | Basic, client secret POST, private key JWT, client secret JWT |
| Identity | UserInfo, username, email, roles, and scopes; JWT and introspection agree on the identity of the same native token |
| Authorization | A mapped reader role permits access and an absent admin role denies it; granted read scope permits access and absent write scope denies it |
| Sessions | Recorded native refresh preserves identity and scopes, updates access credentials, and renews the cookie; revoked refresh tokens clear the session; local logout clears it |
| Callback protection | Tampered state, missing state cookie, mismatched nonce, rejected client authentication, and replayed callbacks cannot create a session |
| Protected resources | Missing and unknown bearer tokens are rejected; introspection accepts user and service tokens and rejects the wrong audience and revoked tokens |
| JWT access tokens | User and client credentials layouts succeed; wrong audience, altered signatures, and ID Tokens used as access tokens are rejected |
| Signing keys | A warm JWKS cache reloads for a new native signing key and continues accepting the previous key |
| Authorization extensions | PAR, signed Request Objects, and their combination complete login |
| Response protection | Signed UserInfo and encrypted ID Tokens complete login |
| Provider logout | RP-initiated logout completes at the provider |
| Outbound security | Token propagation, client credentials with caching, and token exchange |

Core scenarios run for every adapter. Optional protocol features use explicit adapter
capabilities and a reason in the JUnit skip report. Failures of supported scenarios remain
failures. Docker availability is the only infrastructure skip; container or provider
startup failures fail the suite.

The existing `oidc-next-keycloak` module retains its specialized coverage. The synthetic
`oidc-next` integration module and provider unit tests remain responsible for controlled
malformed responses, time boundaries, concurrency, and other cases which cannot reliably
be induced in a real provider.

## Provider settings and exceptions

| Provider | Image | JWT access token profile | Exceptions |
| --- | --- | --- | --- |
| Keycloak | `quay.io/keycloak/keycloak:26.8.0` | `CUSTOM`, with the `typ: Bearer` payload marker and required `sub`, `iat`, `jti`, `azp` | All shared capabilities enabled |
| Authelia | `ghcr.io/authelia/authelia:4.39.28` | `RFC_9068`; JWT access tokens explicitly enabled for user and service clients | RP-initiated logout and token exchange are not implemented; signed UserInfo, PAR combined with JAR, and the error after refresh-token revocation have the known incompatibilities below |

Authelia's unimplemented features are listed in its
[OIDC support chart](https://www.authelia.com/integration/openid-connect/introduction/).
Its regular access tokens are opaque, so common bearer scenarios use introspection.
An Authelia-specific test verifies that the native access token is not a compact JOSE token.
The fixture configures scope claim paths `scope` and `scp`: Authelia's JWT client
credentials tokens encode their scopes in `scp`. This uses existing tenant claim mapping.

### Authelia signed UserInfo incompatibility

Authelia 4.39.28 produces an RS256 UserInfo response without `iss` or `aud`. This was
observed against the pinned image and is consistent with its
[UserInfo handler](https://github.com/authelia/authelia/blob/v4.39.28/internal/handlers/handler_oauth2_oidc_userinfo.go)
and [claim hydration](https://github.com/authelia/authelia/blob/v4.39.28/internal/oidc/claims.go).

[OIDC Core 5.3.2](https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse)
requires signed UserInfo to include the provider's issuer and an audience containing the
RP client ID. Helidon retains these checks. Normal JSON UserInfo works and is exercised
by the shared suite. A switch that permits missing signed claims would change the issuer
and client binding contract; this suite does not add one.

The successful signed UserInfo scenario is skipped for this specific, documented provider
defect, separately from the two unimplemented features. An additional Authelia regression
checks the missing claims, verifies that the callback is rejected with HTTP 502, and
verifies that no authenticated session is created. When a provider release fixes the
response, update the adapter capability and remove this regression; its claim assertions
will flag the change.

### Authelia PAR combined with JAR incompatibility

Authelia 4.39.28 accepts PAR and JAR independently, but rejects a signed Request Object
pushed through PAR because it also requires an outer `response_type` form parameter.
[RFC 9126 section 3](https://www.rfc-editor.org/rfc/rfc9126.html#section-3) requires
authorization parameters to be inside the JWT; the form may contain only `request` and
parameters required by the client authentication method. With Basic client authentication,
the shared flow correctly sends only `request` in the form.

The combined success scenario is skipped for this documented incompatibility. A separate
Authelia regression records the form, checks the native `invalid_request_object` response
and its `response_type` diagnostic, and verifies that no local session was created. When
the provider fixes this behavior, enable `PAR_WITH_JAR` and remove the rejection regression.

### Authelia error after refresh-token revocation

With the pinned image and SQLite storage, revoking a refresh token succeeds, but trying
to refresh afterward returns HTTP 500 with `server_error` and a "no rows affected"
storage error. A revoked refresh token should instead result in `invalid_grant` under
[RFC 6749 section 5.2](https://www.rfc-editor.org/rfc/rfc6749.html#section-5.2).

The shared terminal-error scenario is skipped for this specific incompatibility. An
Authelia regression verifies the actual native error and proves that the RP retains only
the original, unexpired local session: the access credential and cookie remain unchanged,
and the response sets no new authentication cookie. Helidon treats a server error as
potentially transient; it removes authentication if the existing access lifetime expires.
The controlled refresh unit tests cover that expiration boundary. No new session lifetime
or token is granted by this fallback. Enable `REFRESH_TOKEN_REVOCATION` and remove the
provider regression when the native endpoint returns the standard terminal error.

The suite therefore has five Authelia skips: two unsupported features and three specific
provider incompatibilities. All other shared scenarios run for both providers.

## Refresh, revocation, and key rotation

The Helidon `OidcEndpointRecorder` forwards requests and JSON replies to the actual native
endpoint, retaining Content-Type, cache control, and authentication response headers. It
records grant types and parameter names without substituting token responses. Refresh
tests prove that the RP uses the access token returned by a real refresh request, that the
refreshed token authenticates an API Bearer request (via introspection for Authelia), and that
native `invalid_grant` after refresh-token revocation removes the authentication cookie.
Each provider uses a dedicated refresh-test client whose native access tokens expire in
45 seconds, within the RP's one-minute renewal margin; protected-resource validation
clock skew does not control browser refresh.
The separate Authelia regression verifies its nonstandard server-error response.
Access-token revocation is tested through live introspection, not local JWT verification.

Key rotation tests keep the same RP running, count its actual JWKS requests, and configure
zero delay for refreshing an unknown `kid`. The adapter installs a new signing key while
retaining the old public key. Both tokens must validate; the JWKS request count must rise
once for the new key. Closing the rotation restores the original provider configuration.

## Running

Use the repository's required JDK and a Docker daemon. Install the current OIDC module
first so standalone integration builds use the workspace implementation:

```shell
mvn -pl security/providers/oidc-next install
mvn -f tests/integration/security/oidc-next-providers/pom.xml verify
```

Run one provider or a specific shared scenario with Failsafe:

```shell
mvn -f tests/integration/security/oidc-next-providers/pom.xml -Dit.test=AutheliaOidcIT verify
mvn -f tests/integration/security/oidc-next-providers/pom.xml \
    '-Dit.test=KeycloakOidcIT#publicCodeFlowAuthenticatesWithS256WithoutAClientSecret' verify
```

Image overrides are `helidon.tests.authelia.image` and `helidon.tests.keycloak.image`.
Keep defaults pinned and recheck the capability matrix when upgrading.

Each provider class owns one container. Relying parties and downstream Helidon servers
use ephemeral HTTPS ports. Keycloak updates redirect URIs through its admin API; Authelia
reloads its file configuration by restarting the process within the same container,
preserving its SQLite storage. Its file users, SQLite storage, and in-memory sessions
require no additional containers. Test DNS and certificate trust are local to the Helidon
clients; no hosts-file changes are needed. All credentials
and private keys in this module are test fixtures.
Authelia's external NTP startup check is disabled in this fixture; the containers and RP
use the Docker host clock. The rotated issuer key is generated independently of client
assertion and encryption keys.

To add a provider, implement `IdpAdapter`, configure the native client modes, declare
unsupported capabilities with precise reasons, and add a small `*OidcIT` subclass. Keep
provider setup and login in the adapter and protocol assertions in the shared contract.
