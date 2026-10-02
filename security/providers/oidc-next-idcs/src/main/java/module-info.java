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

import io.helidon.common.features.api.Features;
import io.helidon.common.features.api.HelidonFlavor;

/**
 * Optional Oracle IDCS tenant adapter for OIDC Next.
 */
@Features.Name("OIDC Next IDCS Adapter")
@Features.Description("Oracle IDCS tenant defaults and protected signing-key access for OIDC Next")
@Features.Flavor({HelidonFlavor.SE, HelidonFlavor.MP})
@Features.Path({"Security", "Provider", "OIDC Next", "IDCS"})
module io.helidon.security.providers.oidc.next.idcs {
    requires static io.helidon.common.features.api;

    requires io.helidon.common;
    requires io.helidon.common.parameters;
    requires io.helidon.config;
    requires io.helidon.http;
    requires io.helidon.json;
    requires io.helidon.security.providers.oidc.next;
    requires io.helidon.webclient.api;

    exports io.helidon.security.providers.oidc.next.idcs;

    provides io.helidon.security.providers.oidc.next.spi.OidcTenantAdapterProvider
            with io.helidon.security.providers.oidc.next.idcs.IdcsTenantAdapterProvider;
}
