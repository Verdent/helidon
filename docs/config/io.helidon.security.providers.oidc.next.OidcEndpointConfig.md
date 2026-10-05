# io.<wbr>helidon.<wbr>security.<wbr>providers.<wbr>oidc.<wbr>next.<wbr>Oidc<wbr>Endpoint<wbr>Config

## Description

OpenID Provider endpoint and well-known metadata configuration

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
<code>authorization-<wbr>endpoint-<wbr>uri</code>
</td>
<td>
<code>URI</code>
</td>
<td>
</td>
<td>Authorization Endpoint URI</td>
</tr>
<tr>
<td>
<code>tls-<wbr>required</code>
</td>
<td>
<code>Boolean</code>
</td>
<td>
<code>true</code>
</td>
<td>Whether OpenID Connect endpoint URIs, OIDC post-logout redirect URIs, and OIDC outbound bearer-token targets must use transport-layer security</td>
</tr>
<tr>
<td>
<code>token-<wbr>endpoint-<wbr>uri</code>
</td>
<td>
<code>URI</code>
</td>
<td>
</td>
<td>Token Endpoint URI</td>
</tr>
<tr>
<td>
<code>user-<wbr>info-<wbr>endpoint-<wbr>uri</code>
</td>
<td>
<code>URI</code>
</td>
<td>
</td>
<td>UserInfo Endpoint URI</td>
</tr>
<tr>
<td>
<code>introspection-<wbr>endpoint-<wbr>uri</code>
</td>
<td>
<code>URI</code>
</td>
<td>
</td>
<td>Token Introspection Endpoint URI</td>
</tr>
<tr>
<td>
<code>jwks-<wbr>uri</code>
</td>
<td>
<code>URI</code>
</td>
<td>
</td>
<td>JSON Web Key Set URI</td>
</tr>
<tr>
<td>
<code>pushed-<wbr>authorization-<wbr>request-<wbr>endpoint-<wbr>uri</code>
</td>
<td>
<code>URI</code>
</td>
<td>
</td>
<td>Pushed Authorization Request Endpoint URI</td>
</tr>
<tr>
<td>
<code>well-<wbr>known-<wbr>uri</code>
</td>
<td>
<code>URI</code>
</td>
<td>
</td>
<td>Well-known URI used to retrieve well-known metadata</td>
</tr>
<tr>
<td>
<code>end-<wbr>session-<wbr>endpoint-<wbr>uri</code>
</td>
<td>
<code>URI</code>
</td>
<td>
</td>
<td>OpenID Provider End Session Endpoint URI</td>
</tr>
</tbody>
</table>



---

See the [manifest](manifest.md) for all available types.
