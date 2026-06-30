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
import java.util.Optional;

import io.helidon.common.tls.ConfiguredTlsManager;
import io.helidon.common.tls.TlsConfig;
import io.helidon.webclient.api.WebClientConfig;

final class OidcClientAuthenticationConfigValidator {
    private OidcClientAuthenticationConfigValidator() {
    }

    static void validateClientCredentialsGrant(OidcTenantConfig tenant,
                                               OidcEndpointConfig endpoints,
                                               String operation) {
        /*
         * Spec: RFC 6749, 4.4 Client Credentials Grant and 4.4.2 Access Token Request
         * https://www.rfc-editor.org/rfc/rfc6749.html#section-4.4
         * https://www.rfc-editor.org/rfc/rfc6749.html#section-4.4.2
         * RFC 6749 section 4.4 quote: "The client credentials grant type MUST only be used by confidential clients."
         * RFC 6749 section 4.4.2 quote: "The authorization server MUST authenticate the client."
         */
        validateConfidentialTokenEndpointGrant(tenant, endpoints, operation);
    }

    static void validateTokenExchange(OidcTenantConfig tenant, OidcEndpointConfig endpoints) {
        /*
         * Spec: RFC 8693, 2.1 Request
         * https://www.rfc-editor.org/rfc/rfc8693.html#section-2.1
         * Quote: "Client authentication to the authorization server is done using the normal mechanisms provided by
         * OAuth 2.0."
         * Quote: "omitting client authentication allows for a compromised token to be leveraged via an STS into other
         * tokens"
         */
        validateConfidentialTokenEndpointGrant(tenant, endpoints, "Token Exchange");
    }

    static boolean tokenEndpointTlsRequired(OidcTenantConfig tenant) {
        return tenant.endpoints().tlsRequired()
                || mutualTlsTokenEndpointAuthentication(tenant.clientSecret(), tenant.tokenEndpointAuthenticationMethod());
    }

    static void validateTokenEndpointAuthentication(OidcTenantConfig.BuilderBase<?, ?> tenant,
                                                    boolean confidentialClientRequired,
                                                    String operation) {
        validateTokenEndpointAuthentication(tenant.clientSecret(),
                                            tenant.tokenEndpointAuthenticationMethod(),
                                            tenant.clientAssertion(),
                                            tenant.webClient(),
                                            confidentialClientRequired,
                                            operation);
    }

    static void validateIntrospectionEndpointAuthentication(OidcTenantConfig.BuilderBase<?, ?> tenant,
                                                            OidcTokenValidationConfig tokenValidation) {
        /*
         * Spec: RFC 7662, 4 Security Considerations
         * https://www.rfc-editor.org/rfc/rfc7662.html#section-4
         * Quote: "To prevent this, the authorization server MUST require authentication of protected resources that
         * need to access the introspection endpoint and SHOULD require protected resources to be specifically
         * authorized to call the introspection endpoint."
         * Quote: "A single piece of software acting as both a client and a protected resource MAY reuse the same
         * credentials between the token endpoint and the introspection endpoint, though doing so potentially conflates
         * the activities of the client and protected resource portions of the software and the authorization server MAY
         * require separate credentials for each mode."
         */
        OidcIntrospectionConfig introspection = tokenValidation.introspection();
        Optional<String> clientSecret = introspection.clientSecret().or(tenant::clientSecret);
        OidcClientAssertionConfig clientAssertion = introspection.clientAssertion()
                .orElseGet(tenant::clientAssertion);
        OidcClientAuthenticationMethod method =
                introspectionEndpointAuthenticationMethod(tenant.clientSecret(), introspection);
        introspection.clientId()
                .or(tenant::clientId)
                .orElseThrow(() -> new IllegalArgumentException(
                        "client-id must be configured when introspection is enabled"));
        switch (method) {
        case CLIENT_SECRET_BASIC, CLIENT_SECRET_POST -> clientSecret
                .orElseThrow(() -> new IllegalArgumentException(
                        "client-secret must be configured for " + method
                                + " Introspection Endpoint authentication when introspection is enabled"));
        case CLIENT_SECRET_JWT -> {
            clientSecret.orElseThrow(() -> new IllegalArgumentException(
                    "client-secret must be configured for CLIENT_SECRET_JWT Introspection Endpoint authentication when "
                            + "introspection is enabled"));
            validateClientAssertionAlgorithm(clientAssertion,
                                             OidcClientAuthenticationMethod.CLIENT_SECRET_JWT,
                                             "Introspection Endpoint",
                                             "introspection");
        }
        case PRIVATE_KEY_JWT -> {
            clientAssertion.jwk()
                    .orElseThrow(() -> new IllegalArgumentException(
                            "client-assertion.jwk must be configured for PRIVATE_KEY_JWT Introspection Endpoint "
                                    + "authentication when introspection is enabled"));
            validateClientAssertionAlgorithm(clientAssertion,
                                             OidcClientAuthenticationMethod.PRIVATE_KEY_JWT,
                                             "Introspection Endpoint",
                                             "introspection");
        }
        case TLS_CLIENT_AUTH, SELF_SIGNED_TLS_CLIENT_AUTH -> {
            validateMutualTlsClientAuthentication(tenant.webClient(),
                                                  method,
                                                  "Introspection Endpoint",
                                                  "introspection");
        }
        case NONE -> throw new IllegalArgumentException(
                "Introspection Endpoint authentication cannot be NONE when introspection is enabled");
        default -> throw new IllegalStateException("Unexpected client authentication method: " + method);
        }
    }

    static void validateClientAssertion(OidcClientAssertionConfig clientAssertion) {
        if (clientAssertion.lifetime().isZero() || clientAssertion.lifetime().isNegative()) {
            throw new IllegalArgumentException("client-assertion.lifetime must be positive");
        }
        clientAssertion.algorithm()
                .filter(algorithm -> algorithm.isBlank()
                        || !algorithm.equals(algorithm.strip())
                        || "none".equalsIgnoreCase(algorithm))
                .ifPresent(_ -> {
                    throw new IllegalArgumentException(
                            "client-assertion.algorithm must not be blank, padded, or none");
                });
        clientAssertion.keyId()
                .filter(keyId -> keyId.isBlank() || !keyId.equals(keyId.strip()))
                .ifPresent(_ -> {
                    throw new IllegalArgumentException("client-assertion.key-id must not be blank or padded");
                });
    }

    private static void validateConfidentialTokenEndpointGrant(OidcTenantConfig tenant,
                                                               OidcEndpointConfig endpoints,
                                                               String operation) {
        tenant.clientId().orElseThrow(() -> new IllegalArgumentException(
                "client-id must be configured when " + operation + " is enabled"));
        validateTokenEndpointAuthentication(tenant.clientSecret(),
                                            tenant.tokenEndpointAuthenticationMethod(),
                                            tenant.clientAssertion(),
                                            tenant.webClient(),
                                            true,
                                            operation);
        boolean tokenEndpointTlsRequired = endpoints.tlsRequired()
                || mutualTlsTokenEndpointAuthentication(tenant.clientSecret(),
                                                        tenant.tokenEndpointAuthenticationMethod());
        Optional<URI> wellKnownUri = OidcProviderMetadata.wellKnownUri(tenant.issuer(), endpoints);
        OidcEndpointUris.requireEndpointOrWellKnown(endpoints.tokenEndpointUri(),
                                                    wellKnownUri,
                                                    "token-endpoint-uri",
                                                    operation,
                                                    tokenEndpointTlsRequired,
                                                    tokenEndpointTlsRequired,
                                                    OidcEndpointUris::validateTokenEndpointUri);
    }

    private static void validateTokenEndpointAuthentication(Optional<String> clientSecret,
                                                            Optional<OidcClientAuthenticationMethod> authenticationMethod,
                                                            OidcClientAssertionConfig clientAssertion,
                                                            WebClientConfig webClient,
                                                            boolean confidentialClientRequired,
                                                            String operation) {
        OidcClientAuthenticationMethod method = tokenEndpointAuthenticationMethod(clientSecret, authenticationMethod);
        switch (method) {
        case CLIENT_SECRET_BASIC, CLIENT_SECRET_POST -> clientSecret
                .orElseThrow(() -> new IllegalArgumentException(
                        "client-secret must be configured for " + method
                                + " Token Endpoint authentication when " + operation + " is enabled"));
        case CLIENT_SECRET_JWT -> {
            clientSecret.orElseThrow(() -> new IllegalArgumentException(
                    "client-secret must be configured for CLIENT_SECRET_JWT Token Endpoint authentication when "
                            + operation + " is enabled"));
            validateClientAssertionAlgorithm(clientAssertion,
                                             OidcClientAuthenticationMethod.CLIENT_SECRET_JWT,
                                             "Token Endpoint",
                                             operation);
        }
        case PRIVATE_KEY_JWT -> {
            clientAssertion.jwk()
                    .orElseThrow(() -> new IllegalArgumentException(
                            "client-assertion.jwk must be configured for PRIVATE_KEY_JWT Token Endpoint authentication "
                                    + "when " + operation + " is enabled"));
            validateClientAssertionAlgorithm(clientAssertion,
                                             OidcClientAuthenticationMethod.PRIVATE_KEY_JWT,
                                             "Token Endpoint",
                                             operation);
        }
        case TLS_CLIENT_AUTH, SELF_SIGNED_TLS_CLIENT_AUTH -> {
            validateMutualTlsClientAuthentication(webClient, method, "Token Endpoint", operation);
        }
        case NONE -> {
            if (confidentialClientRequired) {
                throw new IllegalArgumentException(
                        "Token Endpoint authentication cannot be NONE when " + operation + " is enabled");
            }
        }
        default -> throw new IllegalStateException("Unexpected client authentication method: " + method);
        }
    }

    private static void validateMutualTlsClientAuthentication(WebClientConfig webClient,
                                                              OidcClientAuthenticationMethod method,
                                                              String endpointName,
                                                              String operation) {
        TlsConfig tls = webClient.tls().prototype();
        /*
         * Spec: RFC 8705, 2 Mutual TLS for OAuth Client Authentication
         * https://www.rfc-editor.org/rfc/rfc8705.html#section-2
         * Quote: "In order to utilize TLS for OAuth client authentication, the TLS connection between the client and the
         * authorization server MUST have been established or re-established with mutual-TLS X.509 certificate
         * authentication (i.e., the client Certificate and CertificateVerify messages are sent during the TLS
         * handshake)."
         */
        if (tls.enabled()
                && (tls.sslContext().isPresent()
                        || tls.privateKey().isPresent() && !tls.privateKeyCertChain().isEmpty()
                        || !(tls.manager() instanceof ConfiguredTlsManager))) {
            return;
        }
        throw new IllegalArgumentException(
                "webclient.tls must be enabled and private-key plus certificate chain, ssl-context, or custom manager "
                        + "must be configured for " + method + " " + endpointName + " authentication when " + operation
                        + " is enabled");
    }

    private static boolean mutualTlsTokenEndpointAuthentication(Optional<String> clientSecret,
                                                               Optional<OidcClientAuthenticationMethod> authenticationMethod) {
        OidcClientAuthenticationMethod method = tokenEndpointAuthenticationMethod(clientSecret, authenticationMethod);
        return method == OidcClientAuthenticationMethod.TLS_CLIENT_AUTH
                || method == OidcClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH;
    }

    static boolean mutualTlsIntrospectionEndpointAuthentication(OidcTokenValidationConfig tokenValidation) {
        OidcClientAuthenticationMethod method = introspectionEndpointAuthenticationMethod(Optional.empty(),
                                                                                          tokenValidation.introspection());
        return method == OidcClientAuthenticationMethod.TLS_CLIENT_AUTH
                || method == OidcClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH;
    }

    static OidcClientAuthenticationMethod tokenEndpointAuthenticationMethod(
            Optional<String> clientSecret,
            Optional<OidcClientAuthenticationMethod> authenticationMethod) {
        return authenticationMethod
                .orElseGet(() -> clientSecret
                        .isPresent()
                        ? OidcClientAuthenticationMethod.CLIENT_SECRET_BASIC
                        : OidcClientAuthenticationMethod.NONE);
    }

    private static OidcClientAuthenticationMethod introspectionEndpointAuthenticationMethod(
            Optional<String> tenantClientSecret,
            OidcIntrospectionConfig introspection) {
        return introspection.authenticationMethod()
                .orElseGet(() -> introspection.clientSecret()
                        .or(() -> tenantClientSecret)
                        .isPresent()
                        ? OidcClientAuthenticationMethod.CLIENT_SECRET_BASIC
                        : OidcClientAuthenticationMethod.NONE);
    }

    private static void validateClientAssertionAlgorithm(OidcClientAssertionConfig clientAssertion,
                                                         OidcClientAuthenticationMethod method,
                                                         String endpointName,
                                                         String operation) {
        clientAssertion.algorithm()
                .filter(algorithm -> switch (method) {
                case CLIENT_SECRET_JWT -> !OidcClientAuthenticationSupport.isClientSecretJwtAlgorithm(algorithm);
                case PRIVATE_KEY_JWT -> !OidcClientAuthenticationSupport.isPrivateKeyJwtAlgorithm(algorithm);
                default -> false;
                })
                .ifPresent(algorithm -> {
                    String algorithms = switch (method) {
                    case CLIENT_SECRET_JWT -> OidcClientAuthenticationSupport.clientSecretJwtAlgorithms();
                    case PRIVATE_KEY_JWT -> OidcClientAuthenticationSupport.privateKeyJwtAlgorithms();
                    default -> throw new IllegalStateException(
                            "Unexpected client assertion authentication method: " + method);
                    };
                    throw new IllegalArgumentException("client-assertion.algorithm must be one of "
                                                               + algorithms
                                                               + " for " + method + " " + endpointName
                                                               + " authentication when "
                                                               + operation + " is enabled");
                });
    }
}
