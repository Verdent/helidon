# io.<wbr>helidon.<wbr>security.<wbr>providers.<wbr>oidc.<wbr>next.<wbr>Oidc<wbr>EndSession<wbr>Config

## Description

RP-Initiated Logout End Session request configuration

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
<code>id-<wbr>token-<wbr>hint-<wbr>required</code>
</td>
<td>
<code>Boolean</code>
</td>
<td>
<code>true</code>
</td>
<td>Whether <code>id_<wbr>token_<wbr>hint</code> must be included in the End Session request</td>
</tr>
<tr>
<td>
<code>allowed-<wbr>post-<wbr>logout-<wbr>redirect-<wbr>uris</code>
</td>
<td>
<code>List&lt;<wbr>URI&gt;</code>
</td>
<td>
</td>
<td>Additional allowed <code>post_<wbr>logout_<wbr>redirect_<wbr>uri</code> values accepted from the local logout request</td>
</tr>
<tr>
<td>
<code>post-<wbr>logout-<wbr>redirect-<wbr>uri</code>
</td>
<td>
<code>URI</code>
</td>
<td>
</td>
<td>Default <code>post_<wbr>logout_<wbr>redirect_<wbr>uri</code> sent in the End Session request</td>
</tr>
<tr>
<td>
<code>enabled</code>
</td>
<td>
<code>Boolean</code>
</td>
<td>
<code>true</code>
</td>
<td>Whether RP-Initiated Logout End Session request handling is enabled</td>
</tr>
</tbody>
</table>



---

See the [manifest](manifest.md) for all available types.
