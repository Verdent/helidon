# io.<wbr>helidon.<wbr>security.<wbr>providers.<wbr>oidc.<wbr>next.<wbr>Oidc<wbr>Introspection<wbr>Config

## Description

RFC 7662 Token Introspection request configuration

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
<a id="auth-method"></a>
<a href="io.helidon.security.providers.oidc.next.OidcClientAuthenticationMethod.md">
<code>auth-<wbr>method</code>
</a>
</td>
<td>
<code>Oidc<wbr>Client<wbr>Authentication<wbr>Method</code>
</td>
<td>
</td>
<td>Introspection Endpoint authentication method</td>
</tr>
<tr>
<td>
<code>client-<wbr>secret</code>
</td>
<td>
<code>String</code>
</td>
<td>
</td>
<td>Client secret used to authenticate this protected resource to the Introspection Endpoint</td>
</tr>
<tr>
<td>
<a id="client-assertion"></a>
<a href="io.helidon.security.providers.oidc.next.OidcClientAssertionConfig.md">
<code>client-<wbr>assertion</code>
</a>
</td>
<td>
<code>Oidc<wbr>Client<wbr>Assertion<wbr>Config</code>
</td>
<td>
</td>
<td>Client assertion signing configuration used by <code>Oidc<wbr>Client<wbr>Authentication<wbr>Method#<wbr>CLIENT_<wbr>SECRET_<wbr>JWT</code> and <code>Oidc<wbr>Client<wbr>Authentication<wbr>Method#<wbr>PRIVATE_<wbr>KEY_<wbr>JWT</code> at the Introspection Endpoint</td>
</tr>
<tr>
<td>
<code>client-<wbr>id</code>
</td>
<td>
<code>String</code>
</td>
<td>
</td>
<td>Client identifier used to authenticate this protected resource to the Introspection Endpoint</td>
</tr>
<tr>
<td>
<a id="remote-work"></a>
<a href="io.helidon.security.providers.oidc.next.OidcRemoteWorkConfig.md">
<code>remote-<wbr>work</code>
</a>
</td>
<td>
<code>Oidc<wbr>Remote<wbr>Work<wbr>Config</code>
</td>
<td>
<code>create(<wbr>)</code>
</td>
<td>Admission limits for Introspection Endpoint requests</td>
</tr>
</tbody>
</table>



---

See the [manifest](manifest.md) for all available types.
