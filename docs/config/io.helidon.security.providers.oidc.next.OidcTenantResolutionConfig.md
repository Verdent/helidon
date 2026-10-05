# io.<wbr>helidon.<wbr>security.<wbr>providers.<wbr>oidc.<wbr>next.<wbr>Oidc<wbr>Tenant<wbr>Resolution<wbr>Config

## Description

Tenant id resolution configuration

## Configuration options


<table>
<thead>
<tr>
<th>Key</th>
<th>Type</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>path-<wbr>segment</code>
</td>
<td>
<code>Integer</code>
</td>
<td>Request path segment containing the tenant id</td>
</tr>
<tr>
<td>
<code>host-<wbr>template</code>
</td>
<td>
<code>String</code>
</td>
<td>DNS host template containing the tenant id as one complete <code>{tenant}</code> label</td>
</tr>
<tr>
<td>
<code>path-<wbr>template</code>
</td>
<td>
<code>String</code>
</td>
<td>Request path template containing the tenant id as a single segment</td>
</tr>
<tr>
<td>
<code>header-<wbr>name</code>
</td>
<td>
<code>String</code>
</td>
<td>Header whose value contains the tenant id</td>
</tr>
</tbody>
</table>



---

See the [manifest](manifest.md) for all available types.
