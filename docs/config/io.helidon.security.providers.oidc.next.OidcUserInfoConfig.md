# io.<wbr>helidon.<wbr>security.<wbr>providers.<wbr>oidc.<wbr>next.<wbr>Oidc<wbr>User<wbr>Info<wbr>Config

## Description

UserInfo request configuration

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
<code>attribute-<wbr>claim-<wbr>paths</code>
</td>
<td>
<code>List&lt;<wbr>String&gt;</code>
</td>
<td>
</td>
<td>Additional UserInfo claim paths stored by the mapped storage policy</td>
</tr>
<tr>
<td>
<a id="jwt"></a>
<a href="io.helidon.security.providers.oidc.next.OidcUserInfoJwtConfig.md">
<code>jwt</code>
</a>
</td>
<td>
<code>Oidc<wbr>User<wbr>Info<wbr>JwtConfig</code>
</td>
<td>
</td>
<td>Expected signed and/or encrypted JWT UserInfo response configuration</td>
</tr>
<tr>
<td>
<a id="storage-policy"></a>
<a href="io.helidon.security.providers.oidc.next.OidcUserInfoStoragePolicy.md">
<code>storage-<wbr>policy</code>
</a>
</td>
<td>
<code>Oidc<wbr>User<wbr>Info<wbr>Storage<wbr>Policy</code>
</td>
<td>
<code>MAPPED</code>
</td>
<td>UserInfo claims stored in the protected local authentication result cookie</td>
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
<td>Whether UserInfo requests are enabled when <code>user-<wbr>info</code> is configured</td>
</tr>
</tbody>
</table>



---

See the [manifest](manifest.md) for all available types.
