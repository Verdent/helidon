# io.<wbr>helidon.<wbr>security.<wbr>providers.<wbr>oidc.<wbr>next.<wbr>Oidc<wbr>IdToken<wbr>Config

## Description

ID Token validation and decryption configuration

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
<code>trusted-<wbr>additional-<wbr>audiences</code>
</td>
<td>
<code>List&lt;<wbr>String&gt;</code>
</td>
<td>
</td>
<td>Additional ID Token audience values trusted by this client</td>
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
<td>Private JWK Set resource configuration used to decrypt encrypted ID Tokens</td>
</tr>
<tr>
<td>
<code>allowed-<wbr>encryption-<wbr>algorithms</code>
</td>
<td>
<code>List&lt;<wbr>String&gt;</code>
</td>
<td>
<code>RSA-<wbr>OAEP-<wbr>256,<wbr> RSA-<wbr>OAEP</code>
</td>
<td>Allowed JWE <code>alg</code> algorithms for encrypted ID Tokens</td>
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
<td>Allowed JWS algorithms for signed ID Tokens</td>
</tr>
<tr>
<td>
<code>allowed-<wbr>content-<wbr>encryption-<wbr>algorithms</code>
</td>
<td>
<code>List&lt;<wbr>String&gt;</code>
</td>
<td>
<code>A256GCM,<wbr> A128CBC-<wbr>HS256</code>
</td>
<td>Allowed JWE <code>enc</code> algorithms for encrypted ID Tokens</td>
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
<td>ID Token time validation clock skew</td>
</tr>
<tr>
<td>
<code>encryption-<wbr>required</code>
</td>
<td>
<code>Boolean</code>
</td>
<td>
<code>false</code>
</td>
<td>Whether ID Tokens must be encrypted</td>
</tr>
</tbody>
</table>



---

See the [manifest](manifest.md) for all available types.
