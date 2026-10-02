# OIDC Next adapter for Oracle IDCS

This optional module supplies Oracle IDCS tenant defaults to the existing `oidc-next` security provider. It does not
register another OIDC provider or duplicate authorization-code processing, signature validation, cookies, refresh,
UserInfo, or Helidon Security integration. Put `helidon-security-providers-oidc-next-idcs` on the classpath/module path
and select `adapter.idcs` for each IDCS tenant; ordinary tenants use the same `oidc-next` configuration as before.

```yaml
security:
  providers:
    - oidc-next:
        default-tenant: oracle
        tenants:
          oracle:
            adapter:
              idcs:
                domain-uri: "https://idcs-example.identity.oraclecloud.com"
            client-id: "${IDCS_CLIENT_ID}"
            client-secret: "${IDCS_CLIENT_SECRET}"
            authorization-code:
              redirection-endpoint-uri: "https://app.example/oidc/oracle-callback"
            cookies:
              protection:
                password: "${OIDC_COOKIE_PASSWORD}"
          keycloak:
            issuer: "https://login.example/realms/main"
            client-id: "${KEYCLOAK_CLIENT_ID}"
            client-secret: "${KEYCLOAK_CLIENT_SECRET}"
            authorization-code:
              redirection-endpoint-uri: "https://app.example/oidc/keycloak-callback"
            cookies:
              protection:
                password: "${OIDC_COOKIE_PASSWORD}"
```

The IDCS `domain-uri` must be an HTTPS domain URL without a path, userinfo, query or fragment. The adapter supplies
the documented IDCS Authorization, Token, JWKS, UserInfo, Introspection and end-session endpoint paths when they are
not configured explicitly. It defaults the exact issuer to `https://identity.oraclecloud.com/`; a tenant with a
different actual issuer must set `issuer` explicitly. Configure its normal callback, scopes, client authentication,
cookies and TLS using OIDC Next options. No IDCS-specific cookie sizing/compression heuristic is applied; for very
large tokens, configure `cookies.compression: GZIP` or increase the bounded chunk/header limits if deployment limits
permit. Normal Authorization Code Flow still uses S256 PKCE by default.
An explicit `jwks-uri` may use a different path, but must stay on the primary or explicitly configured secure domain
origin; a signing-key source belonging to another IDCS domain is rejected at configuration time.

Because different IDCS domains can report the same wire `iss` and `sub`, the adapter qualifies the *local principal ID*
with its normalized, configured domain URL. The ID Token and access-token issuer claims are still checked unchanged.
The domain must remain stable for existing application identities; ordinary OIDC tenants keep their usual issuer/subject
principal IDs. This prevents an IDCS identity in one domain from collapsing into another domain's identity even when
the issuer-uniqueness exception is explicitly enabled.

This is a *vendor-specific static bootstrap* from a domain URL, not an unvalidated alias for OIDC Discovery. Oracle's
[IDCS discovery example](https://docs.oracle.com/en/cloud/paas/identity-cloud/idcsa/op-well-known-openid-configuration-get.html)
uses a tenant host but returns the common Oracle issuer. Standard
[OIDC Discovery validation](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationValidation)
requires the issuer to identify the URL from which its document is fetched, so OIDC Next keeps its strict standard
well-known loader unchanged. This adapter does not automatically download IDCS discovery metadata; if an instance
differs from the documented endpoints, supply those endpoint overrides explicitly. It does not substitute an
unverified metadata issuer or silently downgrade a failed discovery request to static settings.

## Protected signing keys

The normal JWKS GET is attempted first. If it returns 401 or 403, this adapter obtains a narrowly scoped access
token and OIDC Next retries exactly that JWKS URI once with `Authorization: Bearer`. OIDC Next retains its normal JWK
validation, per-tenant caching, refresh and admission limits; redirects stay disabled. Public JWKS need no token.
Oracle also documents an [Access Signing Certificate setting](https://docs.oracle.com/en/cloud/paas/identity-cloud/uaids/change-default-settings.html)
that can make the certificate accessible without authentication; changing that setting is an IDCS administrator's
decision, not a requirement of this module.

The adapter's default protected-key grant is standard `client_credentials`, authenticated using the tenant's normal
Token Endpoint method and requesting `urn:opc:idm:__myscopes__`. The IDCS application must actually be permitted to
use the selected grant and read its signing certificates. A denied grant or unavailable key endpoint fails verification;
the adapter never accepts an unverified token. An unusual deployment can set:

```yaml
adapter:
  idcs:
    domain-uri: "https://idcs-example.identity.oraclecloud.com"
    jwks-scope: "urn:opc:idm:__myscopes__"
    jwks-grant: TLS_CLIENT_AUTH
    secure-domain-uri: "https://idcs-example.secure.identity.oraclecloud.com"
```

The `TLS_CLIENT_AUTH` choice uses Oracle's documented *grant type* `tls_client_auth`, not an OAuth mTLS client-
authentication method. It requires the tenant's usual `webclient.tls` client-certificate configuration. Its Token
Endpoint and JWKS URL must belong to the configured primary or secure IDCS domain. The adapter never sends the
signing-key access token to discovery, UserInfo, or the Token Endpoint; a failed authorized JWKS retry does not switch
to another URL. No credential is requested on a successful public JWKS GET. Configured tenants do not share the
adapter's credentials or verification keys.

## Multiple domains and other providers

An IDCS tenant and an ordinary OIDC tenant with a different issuer coexist without changing issuer policy. Oracle's
published IDCS examples use one issuer for multiple tenant domains; OIDC Next normally rejects different
Authorization/Token Endpoint pairs claiming the same issuer. If several IDCS domains must participate in one provider,
set `issuer-uniqueness-validation-enabled: false` at provider root **and configure distinct callback paths or origins**
for each. The adapter fills in the exact issuer and both pinned endpoint URLs. The same Authorization Endpoint origin cannot
be paired with different Token Endpoints. This deliberate exception does not satisfy
[RFC 9207 issuer uniqueness](https://www.rfc-editor.org/rfc/rfc9207.html#section-4); it relies on the separate
registered callbacks and the protected, tenant-bound OIDC Next state. The callback rejects a mismatched route before
any code or PKCE verifier is sent. For simultaneous browser sessions at different tenants, configure distinct
authentication-request, generation-derived and local-session cookie names as appropriate; the default cookie names
are shared.

Domain-qualified local IDs do not, by themselves, prove a bearer token originated in the intended domain. If two
IDCS domains also issue tokens under the same signing keys and audiences, a resource server needs a trustworthy
domain-specific token claim/policy or tenant-specific introspection before it can distinguish those tokens. Verify
the actual issuer, signing keys, audiences and client registration of every domain before enabling shared-issuer
compatibility; do not rely on the compatibility flag to manufacture a missing token boundary.

The module uses Helidon's configured-provider service mechanism. It does not use reflective access, unsafe APIs, an
alternate OIDC validation path, or a global WebClient Authorization header. Unit and synthetic HTTPS tests cover
provider discovery, mixed tenants, standard and certificate-based signing-key grants, public/protected JWKS, and a
full authorization-code callback with an IDCS-like issuer. Live IDCS interoperability depends on the tenant's
actual issuer, registered callback, PKCE support, client grants and signing-key access policy and has not yet been
claimed by these tests.
