# io.<wbr>helidon.<wbr>security.<wbr>providers.<wbr>oidc.<wbr>next.<wbr>Oidc<wbr>User<wbr>Info<wbr>JwtConfig

## Description

UserInfo JWT response configuration matching the values negotiated during client registration

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
<code>signing-<wbr>algorithm</code>
</td>
<td>
<code>String</code>
</td>
<td>
</td>
<td>Exact JWS <code>alg</code> registered as <code>userinfo_<wbr>signed_<wbr>response_<wbr>alg</code></td>
</tr>
<tr>
<td>
<code>content-<wbr>encryption-<wbr>algorithm</code>
</td>
<td>
<code>String</code>
</td>
<td>
</td>
<td>Exact JWE <code>enc</code> registered as <code>userinfo_<wbr>encrypted_<wbr>response_<wbr>enc</code></td>
</tr>
<tr>
<td>
<code>encryption-<wbr>algorithm</code>
</td>
<td>
<code>String</code>
</td>
<td>
</td>
<td>Exact JWE <code>alg</code> registered as <code>userinfo_<wbr>encrypted_<wbr>response_<wbr>alg</code></td>
</tr>
<tr>
<td>
<code>decryption-<wbr>jwk</code>
</td>
<td>
<code>Resource<wbr>Config</code>
</td>
<td>
</td>
<td>Private RP JWK Set resource configuration used to decrypt encrypted UserInfo responses</td>
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
<td>Clock skew used when validating optional time claims in signed UserInfo JWTs</td>
</tr>
</tbody>
</table>



---

See the [manifest](manifest.md) for all available types.
