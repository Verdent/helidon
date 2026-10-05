# io.<wbr>helidon.<wbr>security.<wbr>providers.<wbr>oidc.<wbr>next.<wbr>Oidc<wbr>Request<wbr>Object<wbr>Config

## Description

Secured Request Object configuration for Authorization Code Flow Authentication Requests

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
<a id="mode"></a>
<a href="io.helidon.security.providers.oidc.next.OidcRequestObjectMode.md">
<code>mode</code>
</a>
</td>
<td>
<code>Oidc<wbr>Request<wbr>Object<wbr>Mode</code>
</td>
<td>
<code>AUTO</code>
</td>
<td>Request Object mode</td>
</tr>
<tr>
<td>
<code>signing-<wbr>algorithm</code>
</td>
<td>
<code>String</code>
</td>
<td>
</td>
<td>JWS <code>alg</code> header value used to sign the Request Object JWT</td>
</tr>
<tr>
<td>
<code>content-<wbr>encryption-<wbr>algorithm</code>
</td>
<td>
<code>String</code>
</td>
<td>
</td>
<td>JWE <code>enc</code> header value used to encrypt the signed Request Object</td>
</tr>
<tr>
<td>
<code>signing-<wbr>key-<wbr>id</code>
</td>
<td>
<code>String</code>
</td>
<td>
</td>
<td>JWS <code>kid</code> header value used for the Request Object</td>
</tr>
<tr>
<td>
<code>encryption-<wbr>algorithm</code>
</td>
<td>
<code>String</code>
</td>
<td>
</td>
<td>JWE <code>alg</code> header value used to encrypt the signed Request Object</td>
</tr>
<tr>
<td>
<code>lifetime</code>
</td>
<td>
<code>Duration</code>
</td>
<td>
<code>PT1M</code>
</td>
<td>Request Object lifetime used to calculate the JWT <code>exp</code> claim from the current time</td>
</tr>
<tr>
<td>
<code>encryption-<wbr>key-<wbr>id</code>
</td>
<td>
<code>String</code>
</td>
<td>
</td>
<td>Key id of the Authorization Server public JWK used to encrypt the signed Request Object</td>
</tr>
<tr>
<td>
<code>signing-<wbr>jwk</code>
</td>
<td>
<code>Resource<wbr>Config</code>
</td>
<td>
</td>
<td>Private JWK Set resource configuration used to sign Request Objects</td>
</tr>
</tbody>
</table>



---

See the [manifest](manifest.md) for all available types.
