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

import java.net.URI;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import io.helidon.common.uri.UriQuery;

final class OidcEndpointUris {
    static final URI DEFAULT_REDIRECTION_ENDPOINT_URI = URI.create("/oidc/callback");

    private OidcEndpointUris() {
    }

    static URI redirectionEndpointUri(OidcAuthorizationCodeConfig authorizationCode) {
        return authorizationCode.redirectionEndpointUri()
                .orElse(DEFAULT_REDIRECTION_ENDPOINT_URI);
    }

    static List<URI> redirectionEndpointUris(OidcProviderConfig config) {
        return config.tenants().values().stream()
                .filter(OidcTenantConfig::enabled)
                .map(OidcTenantConfig::authorizationCode)
                .flatMap(Optional::stream)
                .filter(OidcAuthorizationCodeConfig::enabled)
                .map(OidcEndpointUris::redirectionEndpointUri)
                .toList();
    }

    static Set<String> backChannelLogoutPaths(OidcProviderConfig config) {
        return config.tenants().values().stream()
                .filter(OidcTenantConfig::enabled)
                .flatMap(tenant -> tenant.logout().stream())
                .filter(OidcLogoutConfig::enabled)
                .flatMap(logout -> logout.backChannel().stream())
                .map(backChannel -> OidcUri.path(backChannel.uri()))
                .collect(Collectors.toUnmodifiableSet());
    }

    static boolean redirectionEndpointMatches(URI callbackUri, UriQuery callbackQuery, URI expectedUri) {
        if (!OidcUri.sameOrigin(callbackUri, expectedUri)
                || !Objects.equals(OidcUri.path(callbackUri), OidcUri.path(expectedUri))) {
            return false;
        }

        /*
         * RFC 6749 sections 3.1.2 and 4.1.2: retain the redirection endpoint's query component when adding response
         * parameters. Match configured values, including repetitions, without rejecting unknown response parameters.
         * https://www.rfc-editor.org/rfc/rfc6749.html#section-3.1.2
         * https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.2
         * Both URIs must be absolute. Protected transaction state binds callbacks to the original request origin.
         * Use the original query parameters: UriInfo.toUri() reconstructs a decoded query and joins repeated values.
         */
        UriQuery expectedQuery = UriQuery.create(expectedUri);
        for (String name : expectedQuery.names()) {
            if (!callbackQuery.all(name, List::of).equals(expectedQuery.all(name))) {
                return false;
            }
        }
        return true;
    }

    static void requireEndpointOrWellKnown(Optional<URI> endpointUri,
                                           Optional<URI> wellKnownUri,
                                           String endpointConfigKey,
                                           String operation,
                                           boolean tlsRequired,
                                           EndpointUriValidator endpointValidator) {
        requireEndpointOrWellKnown(endpointUri,
                                   wellKnownUri,
                                   endpointConfigKey,
                                   operation,
                                   tlsRequired,
                                   tlsRequired,
                                   endpointValidator);
    }

    static void requireEndpointOrWellKnown(Optional<URI> endpointUri,
                                           Optional<URI> wellKnownUri,
                                           String endpointConfigKey,
                                           String operation,
                                           boolean endpointTlsRequired,
                                           boolean wellKnownTlsRequired,
                                           EndpointUriValidator endpointValidator) {
        endpointUri
                .or(() -> wellKnownUri)
                .orElseThrow(() -> new IllegalArgumentException(
                        endpointConfigKey + " or well-known-uri must be configured when " + operation + " is enabled"));
        endpointUri.ifPresent(uri -> endpointValidator.validate(uri, endpointTlsRequired));
        if (endpointUri.isEmpty()) {
            wellKnownUri.ifPresent(uri -> validateWellKnownUri(uri, wellKnownTlsRequired));
        }
    }

    static void validateAuthorizationEndpointUri(URI uri, boolean tlsRequired) {
        /*
         * Spec: OpenID Connect Discovery 1.0, 3 OpenID Provider Metadata
         * https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
         * Quote: "This URL MUST use the `https` scheme and MAY contain port, path, and query parameter components."
         *
         * Spec: RFC 6749, 3.1 Authorization Endpoint
         * https://www.rfc-editor.org/rfc/rfc6749.html#section-3.1
         * Quote: "The endpoint URI MUST NOT include a fragment component".
         */
        validateHttpsEndpointUri("authorization-endpoint-uri", uri, tlsRequired, false);
        validateNoFragment("authorization-endpoint-uri", uri);
    }

    static void validatePushedAuthorizationRequestEndpointUri(URI uri) {
        /*
         * Spec: RFC 9126, 2 Pushed Authorization Request Endpoint
         * https://www.rfc-editor.org/rfc/rfc9126.html#section-2
         * Quote: "The PAR endpoint URL MUST use the `https` scheme."
         * The endpoints.tls-required exception can permit a local HTTP callback, but it cannot relax the PAR URL:
         * authorization data and client credentials may be sent directly to this endpoint.
         */
        validateHttpsEndpointUri("pushed-authorization-request-endpoint-uri", uri, true, false);
        validateNoFragment("pushed-authorization-request-endpoint-uri", uri);
    }

    static void validateIssuerUri(URI uri, boolean tlsRequired) {
        /*
         * Spec: OpenID Connect Discovery 1.0, 3 OpenID Provider Metadata
         * https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
         * Quote: "`issuer` REQUIRED. URL using the `https` scheme with no query or fragment components that the OP
         * asserts as its Issuer Identifier."
         */
        validateHttpsEndpointUri("issuer", uri, tlsRequired, false);
        validateNoQuery("issuer", uri);
        validateNoFragment("issuer", uri);
    }

    static void validateIssuerUri(String issuer, boolean tlsRequired) {
        validateIssuerUri(URI.create(issuer), tlsRequired);
    }

    static void validateRedirectionEndpointUri(URI uri, boolean tlsRequired) {
        /*
         * Spec: RFC 6749, 3.1.2 Redirection Endpoint
         * https://www.rfc-editor.org/rfc/rfc6749.html#section-3.1.2
         * Quote: "The redirection endpoint URI MUST be an absolute URI as defined by [RFC3986] Section 4.3."
         * Quote: "The endpoint URI MUST NOT include a fragment component."
         *
         * A local absolute path is accepted as Helidon shorthand. It is resolved to an absolute URI from the incoming
         * request origin before it is sent as the Authentication Request `redirect_uri`.
         */
        if (uri.isAbsolute()) {
            validateHttpsEndpointUri("redirection-endpoint-uri", uri, tlsRequired, false);
            validateNoFragment("redirection-endpoint-uri", uri);
            return;
        }
        if (uri.getRawAuthority() != null) {
            throw new IllegalArgumentException("redirection-endpoint-uri must be an absolute URI or local absolute path: "
                                                       + uri);
        }
        String path = uri.getPath();
        if (path == null || path.isEmpty() || !path.startsWith("/")) {
            throw new IllegalArgumentException("redirection-endpoint-uri must be an absolute URI or local absolute path: "
                                                       + uri);
        }
        validateNoFragment("redirection-endpoint-uri", uri);
    }

    static void validateJwksUri(URI uri, boolean tlsRequired) {
        /*
         * Spec: OpenID Connect Discovery 1.0, 3 OpenID Provider Metadata
         * https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
         * Quote: "`jwks_uri` REQUIRED. URL of the OP's JWK Set [JWK] document, which MUST use the `https` scheme."
         */
        validateHttpsEndpointUri("jwks-uri", uri, tlsRequired, true);
    }

    static void validateEndSessionEndpointUri(URI uri, boolean tlsRequired) {
        /*
         * Spec: OpenID Connect RP-Initiated Logout 1.0, 2.1 OpenID Provider Discovery Metadata
         * https://openid.net/specs/openid-connect-rpinitiated-1_0.html#OPMetadata
         * Quote: "`end_session_endpoint` REQUIRED. URL at the OP to which an RP can perform a redirect to request that
         * the End-User be logged out at the OP."
         * Quote: "This URL MUST use the `https` scheme and MAY contain port, path, and query parameter components."
         */
        validateHttpsEndpointUri("end-session-endpoint-uri", uri, tlsRequired, false);
        validateNoFragment("end-session-endpoint-uri", uri);
    }

    static void validateBackChannelLogoutUri(URI uri, boolean tlsRequired) {
        /*
         * Spec: OpenID Connect Back-Channel Logout 1.0, 2.2 Indicating RP Support
         * https://openid.net/specs/openid-connect-backchannel-1_0.html#BCRegistration
         * The registered URI must be absolute and must not contain a fragment. Query parameters are permitted.
         */
        validateHttpsEndpointUri("logout.back-channel.uri", uri, tlsRequired, false);
        if (uri.getHost() == null || uri.getRawUserInfo() != null) {
            throw new IllegalArgumentException("logout.back-channel.uri must identify an HTTP server: " + uri);
        }
        validateNoFragment("logout.back-channel.uri", uri);
    }

    static void validateUserInfoEndpointUri(URI uri, boolean tlsRequired) {
        /*
         * Spec: OpenID Connect Discovery 1.0, 3 OpenID Provider Metadata
         * https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
         * Quote: "This URL MUST use the `https` scheme and MAY contain port, path, and query parameter components."
         */
        validateHttpsEndpointUri("user-info-endpoint-uri", uri, tlsRequired, false);
        validateNoFragment("user-info-endpoint-uri", uri);
    }

    static void validatePostLogoutRedirectUri(String configKey, URI uri, boolean tlsRequired) {
        /*
         * Spec: OpenID Connect RP-Initiated Logout 1.0, 2 RP-Initiated Logout
         * https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout
         * Quote: "The `post_logout_redirect_uri` value MUST have been previously registered with the OP, either using
         * the `post_logout_redirect_uris` Registration parameter or via another mechanism."
         * Quote: "This URI SHOULD use the `https` scheme and MAY contain port, path, and query parameter components."
         */
        validateHttpsEndpointUri(configKey, uri, tlsRequired, false);
        validateNoFragment(configKey, uri);
    }

    static void validateTokenEndpointUri(URI uri, boolean tlsRequired) {
        /*
         * Spec: RFC 6749, 3.2 Token Endpoint
         * https://www.rfc-editor.org/rfc/rfc6749.html#section-3.2
         * Quote: "The endpoint URI MUST NOT include a fragment component."
         * Quote: "The authorization server MUST require the use of TLS as described in Section 1.6 when sending
         * requests to the token endpoint."
         */
        validateHttpsEndpointUri("token-endpoint-uri", uri, tlsRequired, false);
        validateNoFragment("token-endpoint-uri", uri);
    }

    static void validateIntrospectionEndpointUri(URI uri, boolean tlsRequired) {
        /*
         * Spec: RFC 7662, 2 Introspection Endpoint
         * https://www.rfc-editor.org/rfc/rfc7662.html#section-2
         * Quote: "The introspection endpoint MUST be protected by a transport-layer security mechanism as described in
         * Section 4."
         */
        validateHttpsEndpointUri("introspection-endpoint-uri", uri, tlsRequired, false);
        validateNoFragment("introspection-endpoint-uri", uri);
    }

    static void validateLocalEndpointUri(String configKey, URI uri) {
        if (uri.getScheme() != null || uri.getRawAuthority() != null) {
            throw new IllegalArgumentException(configKey + " must be a local absolute path: " + uri);
        }
        String path = uri.getPath();
        if (path == null || path.isEmpty() || !path.startsWith("/")) {
            throw new IllegalArgumentException(configKey + " must be a local absolute path: " + uri);
        }
        if (uri.getRawQuery() != null) {
            throw new IllegalArgumentException(configKey + " must not include a query component: " + uri);
        }
        validateNoFragment(configKey, uri);
    }

    static void validateWellKnownUri(URI uri, boolean tlsRequired) {
        /*
         * Spec: OpenID Connect Discovery 1.0, 4 Obtaining OpenID Provider Configuration Information
         * https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest
         * Quote: "OpenID Providers supporting Discovery MUST make a JSON document available at the path formed by
         * concatenating the string `/.well-known/openid-configuration` to the Issuer."
         *
         * Spec: RFC 8414, 3 Obtaining Authorization Server Metadata
         * https://www.rfc-editor.org/rfc/rfc8414.html#section-3
         * Quote: "This path MUST use the \"https\" scheme."
         */
        validateHttpsEndpointUri("well-known-uri", uri, tlsRequired, false);
    }

    static URI oidcWellKnownUri(String issuer) {
        while (issuer.endsWith("/")) {
            issuer = issuer.substring(0, issuer.length() - 1);
        }
        return URI.create(issuer + "/.well-known/openid-configuration");
    }

    static boolean wellKnownUriMatchesIssuer(URI wellKnownUri, String issuer) {
        URI issuerUri = URI.create(issuer);
        if (issuerUri.getScheme() == null || issuerUri.getRawAuthority() == null
                || issuerUri.getRawQuery() != null || issuerUri.getRawFragment() != null) {
            return false;
        }
        String oauthWellKnownUri = issuerUri.getScheme() + "://" + issuerUri.getRawAuthority()
                + "/.well-known/oauth-authorization-server"
                + (issuerUri.getRawPath() == null ? "" : issuerUri.getRawPath());
        // URI.equals folds host/scheme case, but discovery issuer identity uses exact string comparison.
        String fetchedUri = wellKnownUri.toString();
        return fetchedUri.equals(oidcWellKnownUri(issuer).toString()) || fetchedUri.equals(oauthWellKnownUri);
    }

    static void validateWellKnownMetadataIssuer(URI wellKnownUri, String issuer) {
        /*
         * Spec: OpenID Connect Discovery 1.0, 4.3 OpenID Provider Configuration Validation
         * https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationValidation
         * Spec: RFC 8414, 3.3 Authorization Server Metadata Validation and 6.2 Impersonation Attacks
         * https://www.rfc-editor.org/rfc/rfc8414.html#section-3.3
         * https://www.rfc-editor.org/rfc/rfc8414.html#section-6.2
         * The issuer in a fetched document must identify the issuer used to construct its actual well-known URL.
         */
        if (!wellKnownUriMatchesIssuer(wellKnownUri, issuer)) {
            throw new IllegalArgumentException("well-known metadata issuer must match well-known-uri");
        }
    }

    private static void validateHttpsEndpointUri(String configKey, URI uri, boolean tlsRequired, boolean fileAllowed) {
        String scheme = uri.getScheme();
        if (scheme == null) {
            throw new IllegalArgumentException(configKey + " must define a URI scheme");
        }
        if ("https".equalsIgnoreCase(scheme)) {
            return;
        }
        if (!tlsRequired && ("http".equalsIgnoreCase(scheme) || fileAllowed && "file".equalsIgnoreCase(scheme))) {
            return;
        }
        throw new IllegalArgumentException(
                configKey + " must use https"
                        + (tlsRequired ? "" : " unless endpoints.tls-required is disabled") + ": " + uri);
    }

    private static void validateNoFragment(String configKey, URI uri) {
        if (uri.getRawFragment() != null) {
            throw new IllegalArgumentException(configKey + " must not include a fragment component: " + uri);
        }
    }

    private static void validateNoQuery(String configKey, URI uri) {
        if (uri.getRawQuery() != null) {
            throw new IllegalArgumentException(configKey + " must not include a query component: " + uri);
        }
    }

    @FunctionalInterface
    interface EndpointUriValidator {
        void validate(URI uri, boolean tlsRequired);
    }
}
