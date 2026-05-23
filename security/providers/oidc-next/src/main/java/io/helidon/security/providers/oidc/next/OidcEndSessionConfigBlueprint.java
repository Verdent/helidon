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
import java.util.Optional;

import io.helidon.builder.api.Option;
import io.helidon.builder.api.Prototype;

/**
 * RP-Initiated Logout End Session request configuration.
 */
@Prototype.Blueprint
@Prototype.Configured
interface OidcEndSessionConfigBlueprint {
    /**
     * Whether RP-Initiated Logout End Session request handling is enabled.
     *
     * @return whether RP-Initiated Logout End Session request handling is enabled
     */
    @Option.Configured
    @Option.DefaultBoolean(true)
    boolean enabled();

    /**
     * Whether {@code id_token_hint} must be included in the End Session request.
     *
     * @return whether {@code id_token_hint} must be included
     */
    @Option.Configured
    @Option.DefaultBoolean(true)
    boolean idTokenHintRequired();

    /**
     * Default {@code post_logout_redirect_uri} sent in the End Session request.
     *
     * @return default {@code post_logout_redirect_uri}
     */
    @Option.Configured
    Optional<URI> postLogoutRedirectUri();

    /**
     * Additional allowed {@code post_logout_redirect_uri} values accepted from the local logout request.
     * <p>
     * The configured {@link #postLogoutRedirectUri()} is always allowed.
     *
     * @return additional allowed {@code post_logout_redirect_uri} values
     */
    @Option.Configured
    @Option.Singular("allowedPostLogoutRedirectUri")
    List<URI> allowedPostLogoutRedirectUris();
}
