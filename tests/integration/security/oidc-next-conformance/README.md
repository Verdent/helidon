# OpenID Foundation RP conformance for OIDC Next

This opt-in integration module runs the official [OpenID Foundation conformance suite](https://gitlab.com/openid/conformance-suite)
against a Helidon OIDC Next relying party. It uses the prebuilt suite and nginx images
pinned to `release-v5.3.3` (the latest published release when pinned on October 26, 2026),
plus an ephemeral MongoDB container. No OIDF account, externally hosted server, manual
plan IDs, suite source checkout, or credentials in Git are needed.

The fixture creates a temporary TLS certificate with a DNS SAN, trusts it only in its
own clients, starts a uniquely named Compose project, creates five fresh static-client
plans, runs their modules, and shuts the project down. Docker Compose must support
`host-gateway`, and ports 8443 (suite) and 39443 (local HTTPS RP) must be free.
On Linux, `host.docker.internal` lets the suite send Back-Channel Logout to the RP.
The test machine also needs `openssl`, a Docker daemon, Docker Compose v2, and the
repository's required JDK and Maven versions.

| RP plan | JUnit cases | Expected official results |
| --- | ---: | --- |
| Basic | 14 | 13 `PASSED`, 1 `SKIPPED` |
| Configuration | 6 | 5 `PASSED`, 1 `SKIPPED` |
| Refresh Token | 3 | 3 `PASSED` |
| Back-Channel Logout | 8 | 8 `PASSED` |
| RP-Initiated Logout | 3 | 3 `PASSED` |

The two official `SKIPPED` results are the `alg=none` ID Token checks: the RP
intentionally refuses unsigned ID Tokens; the tests also assert that no local
authentication cookie is issued. All 34 JUnit cases must execute and pass; suite
startup or plan-provisioning failures fail the module instead of skipping it.
Negative cases verify the RP's rejection response and the suite result.
The fixture enables S256 for the known test issuer, which does not advertise its
supported PKCE methods; the production default policy remains unchanged.
These five plans are an automated regression check, not an OIDF certification
or a claim to cover every optional RP profile.

With the repository dependencies installed (for example, after running
`mvn -Ptests -DskipTests install`), run from the repository root:

```shell
mvn -f tests/integration/security/pom.xml -Poidc-conformance \
    -pl oidc-next-conformance verify
```

The `oidc-conformance` profile adds this module to the security test reactor;
normal multi-module builds and the usual provider integration tests do not run
it. Running this module's POM directly also executes it. No CI job runs this
module; enable the profile explicitly to run it locally.
To update the pinned suite tag, update both image references in
`src/test/resources/oidf-compose.yml`, re-run all five plans, and inspect module
changes and expected outcomes rather than silently dropping cases.
