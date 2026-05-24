/*
 * Copyright (c) 2026 Oracle and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.helidon.security.providers.oidc.next;

/**
 * Token Endpoint client authentication method.
 * <p>
 * These are Token Endpoint Authentication Method values defined by OpenID Connect Core 1.0, section
 * {@code 9 Client Authentication}, and OAuth extension specifications. The {@linkplain #wireName() wire name} is the
 * value used by OpenID Provider metadata {@code token_endpoint_auth_methods_supported} and Dynamic Client Registration
 * {@code token_endpoint_auth_method}.
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication">
 * OpenID Connect Core 1.0, 9 Client Authentication</a>
 * @see <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata">
 * OpenID Connect Discovery 1.0, 3 OpenID Provider Metadata</a>
 * @see <a href="https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata">
 * OpenID Connect Dynamic Client Registration 1.0, 2 Client Metadata</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc8705.html#section-2">
 * RFC 8705, 2 Mutual TLS for OAuth Client Authentication</a>
 */
public enum OidcClientAuthenticationMethod {
    /**
     * {@code client_secret_basic}.
     * <p>
     * Client authenticates with HTTP Basic using {@code client_id} and {@code client_secret}, as defined by
     * OAuth 2.0 {@code 2.3.1 Client Password}. This corresponds to the OpenID Connect Core
     * {@code client_secret_basic} Token Endpoint Authentication Method value.
     */
    CLIENT_SECRET_BASIC("client_secret_basic"),

    /**
     * {@code client_secret_post}.
     * <p>
     * Client authenticates with {@code client_id} and {@code client_secret} in the Token Endpoint form body, as
     * allowed by OAuth 2.0 {@code 2.3.1 Client Password}. This corresponds to the OpenID Connect Core
     * {@code client_secret_post} Token Endpoint Authentication Method value.
     */
    CLIENT_SECRET_POST("client_secret_post"),

    /**
     * {@code client_secret_jwt}.
     * <p>
     * Client authenticates with {@code client_assertion_type} and {@code client_assertion}; the assertion is a JWT
     * signed with a MAC using the {@code client_secret} as the symmetric key. This corresponds to the OpenID Connect
     * Core {@code client_secret_jwt} Token Endpoint Authentication Method value.
     */
    CLIENT_SECRET_JWT("client_secret_jwt"),

    /**
     * {@code private_key_jwt}.
     * <p>
     * Client authenticates with {@code client_assertion_type} and {@code client_assertion}; the assertion is a JWT
     * signed with a private key registered for the client. This corresponds to the OpenID Connect Core
     * {@code private_key_jwt} Token Endpoint Authentication Method value.
     */
    PRIVATE_KEY_JWT("private_key_jwt"),

    /**
     * {@code tls_client_auth}: PKI mutual TLS client authentication.
     * <p>
     * Client authenticates with a mutual TLS client certificate whose subject or subject alternative name matches
     * client metadata registered with the Authorization Server. This corresponds to the RFC 8705
     * {@code tls_client_auth} Token Endpoint Authentication Method value.
     */
    TLS_CLIENT_AUTH("tls_client_auth"),

    /**
     * {@code self_signed_tls_client_auth}: self-signed certificate mutual TLS client authentication.
     * <p>
     * Client authenticates with a mutual TLS client certificate that matches a self-signed certificate or public key
     * registered with the Authorization Server. This corresponds to the RFC 8705
     * {@code self_signed_tls_client_auth} Token Endpoint Authentication Method value.
     */
    SELF_SIGNED_TLS_CLIENT_AUTH("self_signed_tls_client_auth"),

    /**
     * {@code none}.
     * <p>
     * Client does not authenticate at the Token Endpoint and sends only {@code client_id}. This corresponds to the
     * OpenID Connect Core {@code none} Token Endpoint Authentication Method value used for public clients.
     */
    NONE("none");

    private final String wireName;

    OidcClientAuthenticationMethod(String wireName) {
        this.wireName = wireName;
    }

    /**
     * Method name used by OpenID Provider metadata and Dynamic Client Registration.
     *
     * @return method wire name
     */
    public String wireName() {
        return wireName;
    }
}
