# io.<wbr>helidon.<wbr>security.<wbr>providers.<wbr>oidc.<wbr>next.<wbr>Oidc<wbr>Client<wbr>Assertion<wbr>Config

## Description

Client assertion configuration

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
<code>key-<wbr>id</code>
</td>
<td>
<code>String</code>
</td>
<td>
</td>
<td>JWS <code>kid</code> header value used for the client assertion</td>
</tr>
<tr>
<td>
<code>lifetime</code>
</td>
<td>
<code>Duration</code>
</td>
<td>
<code>PT1M</code>
</td>
<td>Client assertion lifetime used to calculate the JWT <code>exp</code> claim from the current time</td>
</tr>
<tr>
<td>
<code>algorithm</code>
</td>
<td>
<code>String</code>
</td>
<td>
</td>
<td>JWS <code>alg</code> header value used to sign the client assertion JWT</td>
</tr>
<tr>
<td>
<code>jwk</code>
</td>
<td>
<code>Resource<wbr>Config</code>
</td>
<td>
</td>
<td>Private JWK Set resource configuration used to sign a <code>Oidc<wbr>Client<wbr>Authentication<wbr>Method#<wbr>PRIVATE_<wbr>KEY_<wbr>JWT</code> client assertion</td>
</tr>
</tbody>
</table>



---

See the [manifest](manifest.md) for all available types.
