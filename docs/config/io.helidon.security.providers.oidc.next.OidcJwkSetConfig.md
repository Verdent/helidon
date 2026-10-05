# io.<wbr>helidon.<wbr>security.<wbr>providers.<wbr>oidc.<wbr>next.<wbr>Oidc<wbr>JwkSet<wbr>Config

## Description

JSON Web Key Set loading and reload policy

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
<code>max-<wbr>queued</code>
</td>
<td>
<code>Integer</code>
</td>
<td>
<code>128</code>
</td>
<td>Maximum number of callers waiting for JWK Set load or refresh coordination</td>
</tr>
<tr>
<td>
<code>failure-<wbr>retry-<wbr>interval</code>
</td>
<td>
<code>Duration</code>
</td>
<td>
<code>PT10S</code>
</td>
<td>Minimum interval before retrying a failed JWK Set load</td>
</tr>
<tr>
<td>
<code>stale-<wbr>on-error</code>
</td>
<td>
<code>Boolean</code>
</td>
<td>
<code>true</code>
</td>
<td>Whether cached keys may be used when a reload fails</td>
</tr>
<tr>
<td>
<code>unknown-<wbr>key-<wbr>id-refresh-<wbr>enabled</code>
</td>
<td>
<code>Boolean</code>
</td>
<td>
<code>true</code>
</td>
<td>Whether an unknown JWT <code>kid</code> should trigger a JWK Set reload attempt</td>
</tr>
<tr>
<td>
<code>unknown-<wbr>key-<wbr>id-refresh-<wbr>interval</code>
</td>
<td>
<code>Duration</code>
</td>
<td>
<code>PT5M</code>
</td>
<td>Global minimum interval between JWK Set reload attempts triggered by any unknown key id</td>
</tr>
<tr>
<td>
<code>admission-<wbr>timeout</code>
</td>
<td>
<code>Duration</code>
</td>
<td>
<code>PT1S</code>
</td>
<td>Maximum time an admitted waiting caller may spend obtaining JWK Set load or refresh coordination</td>
</tr>
<tr>
<td>
<code>refresh-<wbr>interval</code>
</td>
<td>
<code>Duration</code>
</td>
<td>
</td>
<td>Lazy JWK Set refresh interval</td>
</tr>
</tbody>
</table>



---

See the [manifest](manifest.md) for all available types.
