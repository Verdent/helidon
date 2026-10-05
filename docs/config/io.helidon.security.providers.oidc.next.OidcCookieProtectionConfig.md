# io.<wbr>helidon.<wbr>security.<wbr>providers.<wbr>oidc.<wbr>next.<wbr>Oidc<wbr>Cookie<wbr>Protection<wbr>Config

## Description

Password-based protection for cookies containing OIDC state and local authentication data

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
<code>password</code>
</td>
<td>
<code>String</code>
</td>
<td>
</td>
<td>Password from which cookie encryption keys are derived</td>
</tr>
<tr>
<td>
<code>salt</code>
</td>
<td>
<code>String</code>
</td>
<td>
</td>
<td>PBKDF2 salt as the canonical, unpadded Base64URL encoding of exactly 16 bytes</td>
</tr>
<tr>
<td>
<code>iterations</code>
</td>
<td>
<code>Integer</code>
</td>
<td>
<code>600000</code>
</td>
<td>Number of PBKDF2-HMAC-SHA-256 iterations</td>
</tr>
</tbody>
</table>



---

See the [manifest](manifest.md) for all available types.
