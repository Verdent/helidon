# io.<wbr>helidon.<wbr>security.<wbr>providers.<wbr>oidc.<wbr>next.<wbr>Oidc<wbr>Logout<wbr>Config

## Description

OpenID Connect logout endpoint configuration

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
<code>local-<wbr>endpoint-<wbr>uri</code>
</td>
<td>
<code>URI</code>
</td>
<td>
<code>/oidc/<wbr>logout</code>
</td>
<td>Local endpoint URI registered by <code>Oidc<wbr>Feature</code></td>
</tr>
<tr>
<td>
<a id="end-session"></a>
<a href="io.helidon.security.providers.oidc.next.OidcEndSessionConfig.md">
<code>end-<wbr>session</code>
</a>
</td>
<td>
<code>Oidc<wbr>EndSession<wbr>Config</code>
</td>
<td>
</td>
<td>RP-Initiated Logout End Session request configuration</td>
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
<td>Whether local logout endpoint handling is enabled</td>
</tr>
</tbody>
</table>



---

See the [manifest](manifest.md) for all available types.
