# io.<wbr>helidon.<wbr>security.<wbr>providers.<wbr>oidc.<wbr>next.<wbr>Oidc<wbr>Cookie<wbr>Config

## Description

Cookie configuration used by stateful OIDC flows

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
<code>max-<wbr>total-<wbr>size</code>
</td>
<td>
<code>Integer</code>
</td>
<td>
<code>12288</code>
</td>
<td>Maximum aggregate session-cookie request-header contribution in bytes, including names and separators</td>
</tr>
<tr>
<td>
<code>max-<wbr>cookie-<wbr>size</code>
</td>
<td>
<code>Integer</code>
</td>
<td>
<code>3800</code>
</td>
<td>Maximum encoded size in bytes of one Authentication Request or local-authentication Set-Cookie field value, including name and attributes</td>
</tr>
<tr>
<td>
<code>max-<wbr>session-<wbr>size</code>
</td>
<td>
<code>Integer</code>
</td>
<td>
<code>65536</code>
</td>
<td>Maximum UTF-8 session JSON size before compression and after authenticated decompression</td>
</tr>
<tr>
<td>
<code>local-<wbr>authentication-<wbr>cookie-<wbr>name</code>
</td>
<td>
<code>String</code>
</td>
<td>
<code>__<wbr>Host-<wbr>helidon-<wbr>oidc-<wbr>auth</code>
</td>
<td>Local authentication result cookie name</td>
</tr>
<tr>
<td>
<code>local-<wbr>authentication-<wbr>lifetime</code>
</td>
<td>
<code>Duration</code>
</td>
<td>
<code>PT1H</code>
</td>
<td>Maximum local authentication result lifetime</td>
</tr>
<tr>
<td>
<code>max-<wbr>chunks</code>
</td>
<td>
<code>Integer</code>
</td>
<td>
<code>4</code>
</td>
<td>Maximum local-authentication cookie pieces, including the base cookie, between 1 and 16</td>
</tr>
<tr>
<td>
<code>authentication-<wbr>request-<wbr>lifetime</code>
</td>
<td>
<code>Duration</code>
</td>
<td>
<code>PT5M</code>
</td>
<td>Authentication Request state lifetime</td>
</tr>
<tr>
<td>
<a id="protection"></a>
<a href="io.helidon.security.providers.oidc.next.OidcCookieProtectionConfig.md">
<code>protection</code>
</a>
</td>
<td>
<code>Oidc<wbr>Cookie<wbr>Protection<wbr>Config</code>
</td>
<td>
</td>
<td>Password-based cookie protection</td>
</tr>
<tr>
<td>
<a id="compression"></a>
<a href="io.helidon.security.providers.oidc.next.OidcCookieCompression.md">
<code>compression</code>
</a>
</td>
<td>
<code>Oidc<wbr>Cookie<wbr>Compression</code>
</td>
<td>
<code>NONE</code>
</td>
<td>Compression policy for new local-authentication sessions; independent of the identity provider</td>
</tr>
<tr>
<td>
<code>authentication-<wbr>request-<wbr>cookie-<wbr>name</code>
</td>
<td>
<code>String</code>
</td>
<td>
<code>__<wbr>Host-<wbr>helidon-<wbr>oidc-<wbr>state</code>
</td>
<td>Authentication Request state cookie name</td>
</tr>
</tbody>
</table>



---

See the [manifest](manifest.md) for all available types.
