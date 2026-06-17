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

import io.helidon.builder.api.Description;
import io.helidon.builder.api.Option;
import io.helidon.builder.api.Prototype;

/**
 * RFC 8705 certificate-bound access-token validation configuration.
 */
@Prototype.Blueprint
@Prototype.Configured
interface OidcCertificateBoundAccessTokenConfigBlueprint {
    /**
     * Certificate-bound access-token validation mode.
     *
     * @return certificate-bound access-token validation mode
     */
    @Description("RFC 8705 certificate-bound access-token validation mode.")
    @Option.Configured
    @Option.Default("DISABLED")
    OidcCertificateBoundAccessTokenMode mode();
}
