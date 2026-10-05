# io.<wbr>helidon.<wbr>security.<wbr>providers.<wbr>oidc.<wbr>next.<wbr>Oidc<wbr>Request<wbr>Object<wbr>Mode

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
<td>Never use a Request Object</td>
</tr>
<tr>
<td><code>AUTO</code></td>
<td>Use a signed Request Object when local signing key material is configured, and require one when Authorization Server metadata requires signed Request Objects</td>
</tr>
<tr>
<td><code>REQUIRED</code></td>
<td>Require every Authentication Request to use a signed Request Object</td>
</tr>
</tbody>
</table>

---

See the [manifest](manifest.md) for all available types.
