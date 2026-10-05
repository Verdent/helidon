# io.<wbr>helidon.<wbr>security.<wbr>providers.<wbr>oidc.<wbr>next.<wbr>Oidc<wbr>Tenant<wbr>Config

## Description

OpenID Connect tenant configuration

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
<code>adapter-<wbr>discover-<wbr>services</code>
</td>
<td>
<code>Boolean</code>
</td>
<td>
<code>false</code>
</td>
<td>Whether to enable automatic service discovery for <code>adapter</code></td>
</tr>
<tr>
<td>
<code>webclient</code>
</td>
<td>
<code>Web<wbr>Client<wbr>Config</code>
</td>
<td>
<code>create(<wbr>)</code>
</td>
<td>WebClient configuration used for outbound requests to the OpenID Provider or Authorization Server; for RFC 8705 mutual TLS, TLS must be enabled and provide private key plus certificate chain, an SSL context, or a custom TLS manager</td>
</tr>
<tr>
<td>
<a id="user-info"></a>
<a href="io.helidon.security.providers.oidc.next.OidcUserInfoConfig.md">
<code>user-<wbr>info</code>
</a>
</td>
<td>
<code>Oidc<wbr>User<wbr>Info<wbr>Config</code>
</td>
<td>
</td>
<td>UserInfo request configuration for Authorization Code Flow local authentication</td>
</tr>
<tr>
<td>
<a id="endpoint-policy"></a>
<a href="io.helidon.security.providers.oidc.next.OidcEndpointPolicyConfig.md">
<code>endpoint-<wbr>policy</code>
</a>
</td>
<td>
<code>Oidc<wbr>Endpoint<wbr>Policy<wbr>Config</code>
</td>
<td>
<code>create(<wbr>)</code>
</td>
<td>Endpoint authentication policy</td>
</tr>
<tr>
<td>
<a id="jwk-set"></a>
<a href="io.helidon.security.providers.oidc.next.OidcJwkSetConfig.md">
<code>jwk-<wbr>set</code>
</a>
</td>
<td>
<code>Oidc<wbr>JwkSet<wbr>Config</code>
</td>
<td>
<code>create(<wbr>)</code>
</td>
<td>JSON Web Key Set reload policy</td>
</tr>
<tr>
<td>
<a id="cookies"></a>
<a href="io.helidon.security.providers.oidc.next.OidcCookieConfig.md">
<code>cookies</code>
</a>
</td>
<td>
<code>Oidc<wbr>Cookie<wbr>Config</code>
</td>
<td>
<code>create(<wbr>)</code>
</td>
<td>Cookie configuration used by OIDC stateful flows</td>
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
<td>Whether this tenant is enabled</td>
</tr>
<tr>
<td>
<code>issuer</code>
</td>
<td>
<code>String</code>
</td>
<td>
</td>
<td>Issuer Identifier expected for this tenant</td>
</tr>
<tr>
<td>
<a id="logout"></a>
<a href="io.helidon.security.providers.oidc.next.OidcLogoutConfig.md">
<code>logout</code>
</a>
</td>
<td>
<code>Oidc<wbr>Logout<wbr>Config</code>
</td>
<td>
</td>
<td>Local OpenID Connect logout endpoint configuration</td>
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
<code>create(<wbr>)</code>
</td>
<td>Client assertion configuration used by <code>Oidc<wbr>Client<wbr>Authentication<wbr>Method#<wbr>CLIENT_<wbr>SECRET_<wbr>JWT</code> and <code>Oidc<wbr>Client<wbr>Authentication<wbr>Method#<wbr>PRIVATE_<wbr>KEY_<wbr>JWT</code></td>
</tr>
<tr>
<td>
<a id="client-credentials-remote-work"></a>
<a href="io.helidon.security.providers.oidc.next.OidcRemoteWorkConfig.md">
<code>client-<wbr>credentials-<wbr>remote-<wbr>work</code>
</a>
</td>
<td>
<code>Oidc<wbr>Remote<wbr>Work<wbr>Config</code>
</td>
<td>
<code>create(<wbr>)</code>
</td>
<td>Admission limits for outbound Client Credentials token acquisition performed by this tenant</td>
</tr>
<tr>
<td>
<code>initialization-<wbr>max-<wbr>queued</code>
</td>
<td>
<code>Integer</code>
</td>
<td>
<code>128</code>
</td>
<td>Maximum number of callers waiting for this tenant's shared initialization attempt</td>
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
<td>OAuth 2.0 client identifier</td>
</tr>
<tr>
<td>
<a id="protected-resource"></a>
<a href="io.helidon.security.providers.oidc.next.OidcProtectedResourceConfig.md">
<code>protected-<wbr>resource</code>
</a>
</td>
<td>
<code>Oidc<wbr>Protected<wbr>Resource<wbr>Config</code>
</td>
<td>
</td>
<td>Protected Resource / Resource Server configuration</td>
</tr>
<tr>
<td>
<a id="endpoints"></a>
<a href="io.helidon.security.providers.oidc.next.OidcEndpointConfig.md">
<code>endpoints</code>
</a>
</td>
<td>
<code>Oidc<wbr>Endpoint<wbr>Config</code>
</td>
<td>
<code>create(<wbr>)</code>
</td>
<td>OpenID Provider endpoint and well-known metadata settings</td>
</tr>
<tr>
<td>
<a id="adapter"></a>
<a href="io.helidon.security.providers.oidc.next.spi.OidcTenantAdapter.md">
<code>adapter</code>
</a>
</td>
<td>
<code>Map&lt;<wbr>String,<wbr> Oidc<wbr>Tenant<wbr>Adapter&gt;<wbr> or List&lt;<wbr>Oidc<wbr>Tenant<wbr>Adapter&gt;</code>
</td>
<td>
</td>
<td>Explicitly selected tenant adapter supplied by an optional module</td>
</tr>
<tr>
<td>
<code>outbound-<wbr>mutual-<wbr>tls</code>
</td>
<td>
<code>Boolean</code>
</td>
<td>
<code>false</code>
</td>
<td>Whether this tenant intends outbound mutual TLS independently of its OAuth client-authentication method</td>
</tr>
<tr>
<td>
<a id="authorization-code"></a>
<a href="io.helidon.security.providers.oidc.next.OidcAuthorizationCodeConfig.md">
<code>authorization-<wbr>code</code>
</a>
</td>
<td>
<code>Oidc<wbr>Authorization<wbr>Code<wbr>Config</code>
</td>
<td>
</td>
<td>Authorization Code Flow configuration</td>
</tr>
<tr>
<td>
<a id="subject-mapping"></a>
<a href="io.helidon.security.providers.oidc.next.OidcSubjectMappingConfig.md">
<code>subject-<wbr>mapping</code>
</a>
</td>
<td>
<code>Oidc<wbr>Subject<wbr>Mapping<wbr>Config</code>
</td>
<td>
<code>create(<wbr>)</code>
</td>
<td>Subject mapping configuration</td>
</tr>
<tr>
<td>
<a id="token-exchange-remote-work"></a>
<a href="io.helidon.security.providers.oidc.next.OidcRemoteWorkConfig.md">
<code>token-<wbr>exchange-<wbr>remote-<wbr>work</code>
</a>
</td>
<td>
<code>Oidc<wbr>Remote<wbr>Work<wbr>Config</code>
</td>
<td>
<code>create(<wbr>)</code>
</td>
<td>Admission limits for RFC 8693 Token Exchange operations performed by this tenant</td>
</tr>
<tr>
<td>
<a id="id-token"></a>
<a href="io.helidon.security.providers.oidc.next.OidcIdTokenConfig.md">
<code>id-<wbr>token</code>
</a>
</td>
<td>
<code>Oidc<wbr>IdToken<wbr>Config</code>
</td>
<td>
<code>create(<wbr>)</code>
</td>
<td>ID Token validation and decryption configuration</td>
</tr>
<tr>
<td>
<a id="token-endpoint-auth-method"></a>
<a href="io.helidon.security.providers.oidc.next.OidcClientAuthenticationMethod.md">
<code>token-<wbr>endpoint-<wbr>auth-<wbr>method</code>
</a>
</td>
<td>
<code>Oidc<wbr>Client<wbr>Authentication<wbr>Method</code>
</td>
<td>
</td>
<td>Token Endpoint client authentication method; mutual TLS methods require enabled tenant <code>webclient.<wbr>tls</code> with private key plus certificate chain, an SSL context, or a custom TLS manager</td>
</tr>
<tr>
<td>
<a id="token-transport"></a>
<a href="io.helidon.security.providers.oidc.next.OidcTokenTransportConfig.md">
<code>token-<wbr>transport</code>
</a>
</td>
<td>
<code>Oidc<wbr>Token<wbr>Transport<wbr>Config</code>
</td>
<td>
<code>create(<wbr>)</code>
</td>
<td>Token transport configuration</td>
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
<td>OAuth 2.0 client secret</td>
</tr>
<tr>
<td>
<code>initialization-<wbr>retry-<wbr>interval</code>
</td>
<td>
<code>Duration</code>
</td>
<td>
<code>PT10S</code>
</td>
<td>Minimum interval before retrying tenant initialization after a transient well-known metadata failure</td>
</tr>
</tbody>
</table>



---

See the [manifest](manifest.md) for all available types.
