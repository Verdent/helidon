# io.<wbr>helidon.<wbr>security.<wbr>providers.<wbr>oidc.<wbr>next.<wbr>Oidc<wbr>JwtAccess<wbr>Token<wbr>Config

## Description

JWT access-token layout requirements, independent of signature and issuer validation

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
<code>allowed-<wbr>types</code>
</td>
<td>
<code>List&lt;<wbr>String&gt;</code>
</td>
<td>
<code>at+jwt,<wbr> application/<wbr>at+jwt</code>
</td>
<td>Accepted JOSE header <code>typ</code> values, compared without regard to case</td>
</tr>
<tr>
<td>
<code>required-<wbr>string-<wbr>claims</code>
</td>
<td>
<code>Map&lt;<wbr>String,<wbr> String&gt;</code>
</td>
<td>
</td>
<td>Required top-level string payload claims and their exact, case-sensitive values</td>
</tr>
<tr>
<td>
<a id="profile"></a>
<a href="io.helidon.security.providers.oidc.next.OidcJwtAccessTokenProfile.md">
<code>profile</code>
</a>
</td>
<td>
<code>Oidc<wbr>JwtAccess<wbr>Token<wbr>Profile</code>
</td>
<td>
<code>RFC_<wbr>9068</code>
</td>
<td>Token layout profile</td>
</tr>
<tr>
<td>
<code>required-<wbr>claims</code>
</td>
<td>
<code>List&lt;<wbr>String&gt;</code>
</td>
<td>
</td>
<td>Additional required top-level payload claims</td>
</tr>
<tr>
<td>
<code>typ-<wbr>header-<wbr>required</code>
</td>
<td>
<code>Boolean</code>
</td>
<td>
<code>true</code>
</td>
<td>Whether the JOSE <code>typ</code> header is required</td>
</tr>
</tbody>
</table>



---

See the [manifest](manifest.md) for all available types.
