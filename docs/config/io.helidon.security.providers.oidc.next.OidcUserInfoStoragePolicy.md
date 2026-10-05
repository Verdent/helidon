# io.<wbr>helidon.<wbr>security.<wbr>providers.<wbr>oidc.<wbr>next.<wbr>Oidc<wbr>User<wbr>Info<wbr>Storage<wbr>Policy

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
<td><code>MAPPED</code></td>
<td>Store only UserInfo claims needed by subject mapping, plus explicitly configured attribute claim paths</td>
</tr>
<tr>
<td><code>ALL</code></td>
<td>Store the complete UserInfo JSON object</td>
</tr>
<tr>
<td><code>NONE</code></td>
<td>Validate the UserInfo response, then discard it</td>
</tr>
</tbody>
</table>

---

See the [manifest](manifest.md) for all available types.
