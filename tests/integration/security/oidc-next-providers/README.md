# OIDC provider contract tests

`OidcProviderContract` runs the same 26 scenarios against real Docker identity providers.
`AutheliaOidcIT` and `KeycloakOidcIT` select adapters; the adapters configure native clients,
users, keys, callback registration, and interactive login. They do not change the shared
assertions or supply synthetic tokens.

## Shared coverage

| Area | Scenarios |
| --- | --- |
| Discovery | Configured issuer and HTTPS endpoints |
| Browser login | Authorization code with S256 PKCE; confidential and public clients |
| Client authentication | Basic, client secret POST, private key JWT, client secret JWT |
| Identity | UserInfo, username, email, roles, and scopes |
| Sessions | Refresh preserves identity and renews the cookie; local logout clears it |
| Callback protection | Tampered state and replayed callbacks are rejected |
| Protected resources | Missing and unknown bearer tokens are rejected; introspection accepts user and service tokens and rejects the wrong audience |
| JWT access tokens | Provider layout succeeds; altered signatures and ID Tokens used as access tokens are rejected |
| Authorization extensions | PAR and signed Request Objects complete login |
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
| Authelia | `ghcr.io/authelia/authelia:4.39.28` | `RFC_9068`; JWT access tokens explicitly enabled for the JWT client | RP-initiated logout and token exchange are not implemented; signed UserInfo has the known incompatibility below |

Authelia's unimplemented features are listed in its
[OIDC support chart](https://www.authelia.com/integration/openid-connect/introduction/).
Its regular access tokens are opaque, so common bearer scenarios use introspection.

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

To add a provider, implement `IdpAdapter`, configure the native client modes, declare
unsupported capabilities with precise reasons, and add a small `*OidcIT` subclass. Keep
provider setup and login in the adapter and protocol assertions in the shared contract.
