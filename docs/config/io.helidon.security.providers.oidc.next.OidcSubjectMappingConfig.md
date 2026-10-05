# io.<wbr>helidon.<wbr>security.<wbr>providers.<wbr>oidc.<wbr>next.<wbr>Oidc<wbr>Subject<wbr>Mapping<wbr>Config

## Description

Subject mapping configuration

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
<code>principal-<wbr>id-namespace</code>
</td>
<td>
<code>String</code>
</td>
<td>
</td>
<td>Fallback principal id namespace for introspection without a configured or discovered issuer</td>
</tr>
<tr>
<td>
<code>principal-<wbr>id-claim-<wbr>paths</code>
</td>
<td>
<code>List&lt;<wbr>String&gt;</code>
</td>
<td>
<code>sub</code>
</td>
<td>Protected Resource principal id claim paths, in preference order</td>
</tr>
<tr>
<td>
<code>role-<wbr>claim-<wbr>paths</code>
</td>
<td>
<code>List&lt;<wbr>String&gt;</code>
</td>
<td>
<code>groups</code>
</td>
<td>Role claim paths</td>
</tr>
<tr>
<td>
<code>principal-<wbr>name-<wbr>claim-<wbr>paths</code>
</td>
<td>
<code>List&lt;<wbr>String&gt;</code>
</td>
<td>
<code>preferred_<wbr>username,<wbr> username</code>
</td>
<td>Principal name claim paths, in preference order</td>
</tr>
<tr>
<td>
<code>scope-<wbr>claim-<wbr>paths</code>
</td>
<td>
<code>List&lt;<wbr>String&gt;</code>
</td>
<td>
<code>scope</code>
</td>
<td>Scope claim paths</td>
</tr>
<tr>
<td>
<code>scope-<wbr>grants-<wbr>enabled</code>
</td>
<td>
<code>Boolean</code>
</td>
<td>
<code>true</code>
</td>
<td>Whether scope claims are mapped to scope grants</td>
</tr>
</tbody>
</table>



---

See the [manifest](manifest.md) for all available types.
