# io.<wbr>helidon.<wbr>security.<wbr>providers.<wbr>oidc.<wbr>next.<wbr>Oidc<wbr>Pushed<wbr>Authorization<wbr>Request<wbr>Mode

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
<td>Never use Pushed Authorization Requests</td>
</tr>
<tr>
<td><code>AUTO</code></td>
<td>Use Pushed Authorization Requests when the Authorization Server metadata or static endpoint configuration makes them available, and require them when Authorization Server metadata requires them</td>
</tr>
<tr>
<td><code>REQUIRED</code></td>
<td>Require every Authentication Request to use Pushed Authorization Requests</td>
</tr>
</tbody>
</table>

---

See the [manifest](manifest.md) for all available types.
