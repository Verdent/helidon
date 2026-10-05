# io.<wbr>helidon.<wbr>security.<wbr>providers.<wbr>oidc.<wbr>next.<wbr>Oidc<wbr>Outbound<wbr>Policy<wbr>Config

## Description

OIDC-specific outbound security policy for a configured target or an individual request

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
<code>audience</code>
</td>
<td>
<code>String</code>
</td>
<td>
</td>
<td>Expected access-token audience for Token Propagation to this outbound policy</td>
</tr>
<tr>
<td>
<code>token-<wbr>propagation-<wbr>enabled</code>
</td>
<td>
<code>Boolean</code>
</td>
<td>
<code>false</code>
</td>
<td>Whether Token Propagation is enabled for this outbound policy</td>
</tr>
<tr>
<td>
<code>audience-<wbr>validation-<wbr>enabled</code>
</td>
<td>
<code>Boolean</code>
</td>
<td>
<code>true</code>
</td>
<td>Whether Token Propagation audience validation is enabled for this outbound policy</td>
</tr>
<tr>
<td>
<code>token-<wbr>exchange-<wbr>enabled</code>
</td>
<td>
<code>Boolean</code>
</td>
<td>
<code>false</code>
</td>
<td>Whether RFC 8693 Token Exchange is enabled for this outbound policy</td>
</tr>
<tr>
<td>
<code>client-<wbr>credentials-<wbr>scopes</code>
</td>
<td>
<code>List&lt;<wbr>String&gt;</code>
</td>
<td>
</td>
<td>Access-token scopes requested by Client Credentials Grant for this outbound policy</td>
</tr>
<tr>
<td>
<code>token-<wbr>exchange-<wbr>scopes</code>
</td>
<td>
<code>List&lt;<wbr>String&gt;</code>
</td>
<td>
</td>
<td>Access-token scopes requested by Token Exchange for this outbound policy</td>
</tr>
<tr>
<td>
<code>token-<wbr>exchange-<wbr>resource</code>
</td>
<td>
<code>String</code>
</td>
<td>
</td>
<td>Target resource requested by Token Exchange for this outbound policy</td>
</tr>
<tr>
<td>
<code>client-<wbr>credentials-<wbr>grant-<wbr>enabled</code>
</td>
<td>
<code>Boolean</code>
</td>
<td>
<code>false</code>
</td>
<td>Whether Client Credentials Grant is enabled for this outbound policy; mutual TLS methods require enabled tenant <code>webclient.<wbr>tls</code> and an HTTPS Token Endpoint or HTTPS well-known metadata</td>
</tr>
<tr>
<td>
<code>token-<wbr>exchange-<wbr>audience</code>
</td>
<td>
<code>String</code>
</td>
<td>
</td>
<td>Target audience requested by Token Exchange for this outbound policy</td>
</tr>
<tr>
<td>
<code>client-<wbr>credentials-<wbr>resources</code>
</td>
<td>
<code>List&lt;<wbr>String&gt;</code>
</td>
<td>
</td>
<td>Resource indicators requested by Client Credentials Grant for this outbound policy</td>
</tr>
</tbody>
</table>



---

See the [manifest](manifest.md) for all available types.
