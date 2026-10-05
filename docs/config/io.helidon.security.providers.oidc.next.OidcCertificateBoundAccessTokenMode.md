# io.<wbr>helidon.<wbr>security.<wbr>providers.<wbr>oidc.<wbr>next.<wbr>Oidc<wbr>Certificate<wbr>Bound<wbr>Access<wbr>Token<wbr>Mode

## Description

This type is an enumeration.

## Allowed Values

<table>
<thead>
<tr>
<th>Value</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td><code>DISABLED</code></td>
<td>Reject certificate-bound access tokens on Bearer Token validation paths</td>
</tr>
<tr>
<td><code>IF_<wbr>PRESENT</code></td>
<td>Validate certificate binding when the access token contains <code>cnf.<wbr>x5t#<wbr>S256</code></td>
</tr>
<tr>
<td><code>REQUIRED</code></td>
<td>Require every protected-resource Bearer Token access token to contain <code>cnf.<wbr>x5t#<wbr>S256</code> and match the request TLS client certificate</td>
</tr>
</tbody>
</table>

---

See the [manifest](manifest.md) for all available types.
