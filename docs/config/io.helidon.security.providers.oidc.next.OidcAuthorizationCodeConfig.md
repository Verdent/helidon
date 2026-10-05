# io.<wbr>helidon.<wbr>security.<wbr>providers.<wbr>oidc.<wbr>next.<wbr>Oidc<wbr>Authorization<wbr>Code<wbr>Config

## Description

OpenID Connect Authorization Code Flow configuration

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
<a id="request-object"></a>
<a href="io.helidon.security.providers.oidc.next.OidcRequestObjectConfig.md">
<code>request-<wbr>object</code>
</a>
</td>
<td>
<code>Oidc<wbr>Request<wbr>Object<wbr>Config</code>
</td>
<td>
<code>create(<wbr>)</code>
</td>
<td>Secured Request Object configuration</td>
</tr>
<tr>
<td>
<code>redirection-<wbr>endpoint-<wbr>uri</code>
</td>
<td>
<code>URI</code>
</td>
<td>
<code>/oidc/<wbr>callback</code>
</td>
<td>Redirection Endpoint URI used as the Authentication Request <code>redirect_<wbr>uri</code></td>
</tr>
<tr>
<td>
<code>refresh-<wbr>result-<wbr>cache-<wbr>capacity</code>
</td>
<td>
<code>Integer</code>
</td>
<td>
<code>1024</code>
</td>
<td>Maximum completed refresh outcomes retained during the grace interval</td>
</tr>
<tr>
<td>
<code>resources</code>
</td>
<td>
<code>List&lt;<wbr>String&gt;</code>
</td>
<td>
</td>
<td>Resource indicators sent as repeated <code>resource</code> parameters in the Authentication Request</td>
</tr>
<tr>
<td>
<a id="refresh-remote-work"></a>
<a href="io.helidon.security.providers.oidc.next.OidcRemoteWorkConfig.md">
<code>refresh-<wbr>remote-<wbr>work</code>
</a>
</td>
<td>
<code>Oidc<wbr>Remote<wbr>Work<wbr>Config</code>
</td>
<td>
<code>create(<wbr>)</code>
</td>
<td>Admission limits for refresh-token operations performed for local authentication sessions</td>
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
<td>Whether Authorization Code Flow initiation is enabled</td>
</tr>
<tr>
<td>
<code>refresh-<wbr>result-<wbr>retention</code>
</td>
<td>
<code>Duration</code>
</td>
<td>
<code>PT5S</code>
</td>
<td>Time for which a completed refresh outcome may be reused by late requests carrying the same source session</td>
</tr>
<tr>
<td>
<code>pkce-<wbr>s256-<wbr>support-<wbr>assured</code>
</td>
<td>
<code>Boolean</code>
</td>
<td>
<code>false</code>
</td>
<td>Whether this tenant has independently established that its Authorization Server supports S256 PKCE even when <code>code_<wbr>challenge_<wbr>methods_<wbr>supported</code> is absent from well-known metadata</td>
</tr>
<tr>
<td>
<code>pkce-<wbr>required</code>
</td>
<td>
<code>Boolean</code>
</td>
<td>
<code>true</code>
</td>
<td>Whether Proof Key for Code Exchange is required for Authorization Code Flow</td>
</tr>
<tr>
<td>
<code>scopes</code>
</td>
<td>
<code>List&lt;<wbr>String&gt;</code>
</td>
<td>
<code>openid</code>
</td>
<td>Authentication Request scopes</td>
</tr>
<tr>
<td>
<a id="pkce-method"></a>
<a href="io.helidon.security.providers.oidc.next.OidcPkceMethod.md">
<code>pkce-<wbr>method</code>
</a>
</td>
<td>
<code>Oidc<wbr>Pkce<wbr>Method</code>
</td>
<td>
<code>S256</code>
</td>
<td>PKCE code challenge method</td>
</tr>
<tr>
<td>
<code>prompts</code>
</td>
<td>
<code>List&lt;<wbr>String&gt;</code>
</td>
<td>
</td>
<td>Authentication Request prompt values</td>
</tr>
<tr>
<td>
<a id="pushed-authorization-requests"></a>
<a href="io.helidon.security.providers.oidc.next.OidcPushedAuthorizationRequestMode.md">
<code>pushed-<wbr>authorization-<wbr>requests</code>
</a>
</td>
<td>
<code>Oidc<wbr>Pushed<wbr>Authorization<wbr>Request<wbr>Mode</code>
</td>
<td>
<code>AUTO</code>
</td>
<td>Pushed Authorization Request mode</td>
</tr>
</tbody>
</table>



---

See the [manifest](manifest.md) for all available types.
