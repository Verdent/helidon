# io.<wbr>helidon.<wbr>security.<wbr>providers.<wbr>oidc.<wbr>next.<wbr>Oidc<wbr>Token<wbr>Validation<wbr>Config

## Description

Access-token validation configuration for Protected Resource Bearer Token requests

## Configuration options


<table>
<thead>
<tr>
<th>Key</th>
<th>Type</th>
<th>Default</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>verification-<wbr>jwk</code>
</td>
<td>
<code>Resource<wbr>Config</code>
</td>
<td>
</td>
<td>Locally provisioned JWK Set for JWT access-token signature verification</td>
</tr>
<tr>
<td>
<code>audience</code>
</td>
<td>
<code>String</code>
</td>
<td>
</td>
<td>Access-token audience expected when audience validation is required</td>
</tr>
<tr>
<td>
<a id="certificate-bound-access-tokens"></a>
<a href="io.helidon.security.providers.oidc.next.OidcCertificateBoundAccessTokenConfig.md">
<code>certificate-<wbr>bound-<wbr>access-<wbr>tokens</code>
</a>
</td>
<td>
<code>Oidc<wbr>Certificate<wbr>Bound<wbr>Access<wbr>Token<wbr>Config</code>
</td>
<td>
<code>create(<wbr>)</code>
</td>
<td>RFC 8705 certificate-bound access-token validation configuration</td>
</tr>
<tr>
<td>
<a id="introspection"></a>
<a href="io.helidon.security.providers.oidc.next.OidcIntrospectionConfig.md">
<code>introspection</code>
</a>
</td>
<td>
<code>Oidc<wbr>Introspection<wbr>Config</code>
</td>
<td>
<code>create(<wbr>)</code>
</td>
<td>RFC 7662 Token Introspection request configuration</td>
</tr>
<tr>
<td>
<a id="method"></a>
<a href="io.helidon.security.providers.oidc.next.OidcTokenValidationMethod.md">
<code>method</code>
</a>
</td>
<td>
<code>Oidc<wbr>Token<wbr>Validation<wbr>Method</code>
</td>
<td>
</td>
<td>Access-token validation method</td>
</tr>
<tr>
<td>
<code>audience-<wbr>validation-<wbr>enabled</code>
</td>
<td>
<code>Boolean</code>
</td>
<td>
<code>true</code>
</td>
<td>Whether access-token audience validation is enabled</td>
</tr>
<tr>
<td>
<a id="jwt"></a>
<a href="io.helidon.security.providers.oidc.next.OidcJwtAccessTokenConfig.md">
<code>jwt</code>
</a>
</td>
<td>
<code>Oidc<wbr>JwtAccess<wbr>Token<wbr>Config</code>
</td>
<td>
</td>
<td>JWT access-token layout requirements</td>
</tr>
<tr>
<td>
<code>jwks-<wbr>uri</code>
</td>
<td>
<code>URI</code>
</td>
<td>
</td>
<td>Public JWK Set URI for independently validated JWT access tokens</td>
</tr>
<tr>
<td>
<code>allowed-<wbr>algorithms</code>
</td>
<td>
<code>List&lt;<wbr>String&gt;</code>
</td>
<td>
<code>RS256</code>
</td>
<td>Allowed JWS algorithms for JWT access tokens</td>
</tr>
<tr>
<td>
<code>clock-<wbr>skew</code>
</td>
<td>
<code>Duration</code>
</td>
<td>
<code>PT1M</code>
</td>
<td>Token time validation clock skew</td>
</tr>
<tr>
<td>
<code>issuer</code>
</td>
<td>
<code>String</code>
</td>
<td>
</td>
<td>Expected access-token issuer, independent of the OpenID Connect issuer used for ID Tokens</td>
</tr>
</tbody>
</table>



---

See the [manifest](manifest.md) for all available types.
