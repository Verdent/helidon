# io.<wbr>helidon.<wbr>security.<wbr>providers.<wbr>oidc.<wbr>next.<wbr>Oidc<wbr>Protected<wbr>Resource<wbr>Config

## Description

OAuth 2.0 Protected Resource configuration

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
<code>challenge-<wbr>realm</code>
</td>
<td>
<code>String</code>
</td>
<td>
<code>helidon</code>
</td>
<td>Realm value used in Bearer <code>WWW-<wbr>Authenticate</code> challenges for Protected Resource requests</td>
</tr>
<tr>
<td>
<a id="token-validation"></a>
<a href="io.helidon.security.providers.oidc.next.OidcTokenValidationConfig.md">
<code>token-<wbr>validation</code>
</a>
</td>
<td>
<code>Oidc<wbr>Token<wbr>Validation<wbr>Config</code>
</td>
<td>
<code>create(<wbr>)</code>
</td>
<td>Access-token validation configuration</td>
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
<td>Whether Bearer Token authentication is enabled for Protected Resource requests</td>
</tr>
</tbody>
</table>



---

See the [manifest](manifest.md) for all available types.
