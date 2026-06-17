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

import java.security.cert.Certificate;
import java.util.Objects;
import java.util.Optional;

record OidcAccessTokenValidationRequest(String token,
                                        OidcTenantContext tenantContext,
                                        Use use,
                                        Optional<Certificate> peerCertificate) {

    OidcAccessTokenValidationRequest {
        Objects.requireNonNull(token);
        Objects.requireNonNull(tenantContext);
        Objects.requireNonNull(use);
        peerCertificate = Objects.requireNonNull(peerCertificate);
    }

    static OidcAccessTokenValidationRequest protectedResource(String token, OidcRequestContext context) {
        return new OidcAccessTokenValidationRequest(token,
                                                    context.tenantContext().orElseThrow(),
                                                    Use.PROTECTED_RESOURCE,
                                                    context.peerCertificate());
    }

    static OidcAccessTokenValidationRequest refreshedAuthorizationCodeAccessToken(String token,
                                                                                  OidcTenantContext tenantContext) {
        return new OidcAccessTokenValidationRequest(token,
                                                    tenantContext,
                                                    Use.REFRESHED_AUTHORIZATION_CODE_ACCESS_TOKEN,
                                                    Optional.empty());
    }

    boolean protectedResource() {
        return use == Use.PROTECTED_RESOURCE;
    }

    enum Use {
        PROTECTED_RESOURCE,
        REFRESHED_AUTHORIZATION_CODE_ACCESS_TOKEN
    }
}
