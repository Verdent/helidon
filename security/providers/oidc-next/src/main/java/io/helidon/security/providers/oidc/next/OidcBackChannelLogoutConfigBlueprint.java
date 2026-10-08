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

import io.helidon.builder.api.Option;
import io.helidon.builder.api.Prototype;
import io.helidon.security.providers.oidc.next.spi.OidcBackChannelLogoutStore;
import io.helidon.security.providers.oidc.next.spi.OidcBackChannelLogoutStoreProvider;

/**
 * OpenID Connect Back-Channel Logout configuration for a browser-authentication tenant.
 */
@Prototype.Blueprint
@Prototype.Configured
interface OidcBackChannelLogoutConfigBlueprint {
    /**
     * Absolute public URI registered with the OpenID Provider as {@code backchannel_logout_uri}.
     * The OIDC feature registers its path as an HTTP POST route.
     *
     * @return registered back-channel logout URI
     */
    @Option.Configured
    URI uri();

    /**
     * Whether a Logout Token must contain the OP session identifier {@code sid}.
     * This must match the RP's {@code backchannel_logout_session_required} registration with the OP.
     *
     * @return whether a session ID is mandatory
     */
    @Option.Configured
    @Option.DefaultBoolean(false)
    boolean sessionRequired();

    /**
     * Per-tenant admission limits for Logout Token verification and a custom store's potentially remote operations.
     * Waiting remains interruptible and bounded on virtual threads.
     *
     * @return Back-Channel Logout work limits
     */
    @Option.Configured
    @Option.Default("create()")
    OidcRemoteWorkConfig remoteWork();

    /**
     * Optional application-owned revocation store. Without one, a process-local in-memory store is used: previously
     * issued cookies remain valid after restart, but outstanding revocations are forgotten. Several server instances
     * or durable logout enforcement require a shared store.
     *
     * @return configured revocation store
     */
    @Option.Configured
    @Option.Confidential
    @Option.Provider(value = OidcBackChannelLogoutStoreProvider.class, discoverServices = false)
    Optional<OidcBackChannelLogoutStore> store();
}
