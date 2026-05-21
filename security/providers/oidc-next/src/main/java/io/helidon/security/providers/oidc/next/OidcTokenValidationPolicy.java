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

import java.util.List;
import java.util.Optional;

final class OidcTokenValidationPolicy {
    private final OidcTokenValidationConfig tokenValidation;

    private OidcTokenValidationPolicy(OidcTokenValidationConfig tokenValidation) {
        this.tokenValidation = tokenValidation;
    }

    static OidcTokenValidationPolicy create(OidcTenantConfig tenantConfig) {
        return new OidcTokenValidationPolicy(tenantConfig.protectedResource().tokenValidation());
    }

    Optional<OidcTokenValidationMethod> method() {
        return tokenValidation.method();
    }

    boolean audienceValidationEnabled() {
        return tokenValidation.audienceValidationEnabled();
    }

    Optional<String> audience() {
        return tokenValidation.audience();
    }

    List<String> allowedAlgorithms() {
        return tokenValidation.allowedAlgorithms();
    }
}
