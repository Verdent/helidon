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

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

import io.helidon.common.parameters.Parameters;
import io.helidon.http.HeaderNames;
import io.helidon.webclient.api.HttpClientRequest;

final class OidcClientAuthenticationSupport {
    private OidcClientAuthenticationSupport() {
    }

    static void applyTokenEndpointAuthentication(OidcTenantConfig tenantConfig,
                                                 Parameters.Builder form,
                                                 HttpClientRequest request) {
        String clientId = tenantConfig.clientId().orElseThrow();
        switch (tokenEndpointAuthenticationMethod(tenantConfig)) {
        case CLIENT_SECRET_BASIC -> request.header(HeaderNames.AUTHORIZATION,
                                                  basicAuthorization(clientId, requireClientSecret(tenantConfig)));
        case CLIENT_SECRET_POST -> {
            /*
             * Spec: RFC 6749, 2.3.1 Client Password
             * https://www.rfc-editor.org/rfc/rfc6749.html#section-2.3.1
             * Quote: "including the client credentials in the request-body".
             */
            form.add("client_id", clientId)
                    .add("client_secret", requireClientSecret(tenantConfig));
        }
        case NONE -> {
            /*
             * Spec: RFC 6749, 3.2.1 Client Authentication
             * https://www.rfc-editor.org/rfc/rfc6749.html#section-3.2.1
             * Quote: "MUST send its `client_id`".
             */
            form.add("client_id", clientId);
        }
        default -> throw new IllegalStateException("Unexpected client authentication method: "
                                                           + tokenEndpointAuthenticationMethod(tenantConfig));
        }
    }

    static OidcClientAuthenticationMethod tokenEndpointAuthenticationMethod(OidcTenantConfig tenantConfig) {
        return tenantConfig.tokenEndpointAuthenticationMethod()
                .or(() -> Optional.of(tenantConfig.clientSecret()
                                               .isPresent()
                                               ? OidcClientAuthenticationMethod.CLIENT_SECRET_BASIC
                                               : OidcClientAuthenticationMethod.NONE))
                .orElseThrow();
    }

    static String basicAuthorization(String clientId, String clientSecret) {
        /*
         * Spec: RFC 6749, 2.3.1 Client Password
         * https://www.rfc-editor.org/rfc/rfc6749.html#section-2.3.1
         * Quote: "The authorization server MUST support the HTTP Basic authentication scheme".
         */
        String credentials = formEncode(clientId) + ":" + formEncode(clientSecret);
        return "Basic " + Base64.getEncoder()
                .encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
    }

    private static String formEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static String requireClientSecret(OidcTenantConfig tenantConfig) {
        return tenantConfig.clientSecret()
                .orElseThrow(() -> new IllegalArgumentException("client-secret must be configured for "
                                                                        + tokenEndpointAuthenticationMethod(tenantConfig)
                                                                        + " Token Endpoint authentication"));
    }
}
