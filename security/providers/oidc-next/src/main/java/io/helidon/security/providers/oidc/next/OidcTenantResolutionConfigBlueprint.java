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

import java.util.Optional;

import io.helidon.builder.api.Option;
import io.helidon.builder.api.Prototype;

/**
 * Tenant id resolution configuration.
 */
@Prototype.Blueprint(decorator = OidcTenantResolutionConfigDecorator.class)
@Prototype.Configured
interface OidcTenantResolutionConfigBlueprint {
    /**
     * Header whose value contains the tenant id.
     *
     * @return tenant header name
     */
    @Option.Configured
    Optional<String> headerName();

    /**
     * Request path segment containing the tenant id.
     *
     * @return tenant path segment index
     */
    @Option.Configured
    Optional<Integer> pathSegment();

    /**
     * Request path template containing the tenant id as a single segment.
     *
     * @return tenant path template
     */
    @Option.Configured
    Optional<String> pathTemplate();

    /**
     * DNS host template containing the tenant id as one complete {@code {tenant}} label.
     * <p>
     * The template is normalized to lower-case ASCII using {@link io.helidon.common.uri.UriHost}; a terminal DNS dot is
     * removed. Request authorities are normalized the same way, and a port does not participate in matching. The
     * resulting tenant id is therefore a canonical ASCII DNS label and must match the configured tenant-map key.
     * <p>
     * When this strategy is reached and a request authority is present, a malformed, repeated, IP-literal, nonmatching,
     * or unknown host does not fall through to the default tenant. The default tenant remains available when the request
     * has no authority. The effective target URI authority takes precedence over the {@code Host} header.
     *
     * @return tenant host template
     * @see <a href="https://www.rfc-editor.org/rfc/rfc3986.html#section-3.2.2">RFC 3986, 3.2.2 Host</a>
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9110.html#section-7.2">RFC 9110, 7.2 Host and :authority</a>
     */
    @Option.Configured
    Optional<String> hostTemplate();
}
