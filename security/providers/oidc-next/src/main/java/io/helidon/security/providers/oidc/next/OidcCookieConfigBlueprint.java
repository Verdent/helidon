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

import java.time.Duration;
import java.util.Optional;

import io.helidon.builder.api.Option;
import io.helidon.builder.api.Prototype;

/**
 * Cookie configuration used by stateful OIDC flows.
 */
@Prototype.Blueprint
@Prototype.Configured
interface OidcCookieConfigBlueprint {
    /**
     * Authentication Request state cookie name.
     * <p>
     * Must be a valid HTTP cookie token. The base name and derived chunk names must not overlap local authentication
     * cookies or the browser-session generation cookie.
     *
     * @return cookie name
     */
    @Option.Configured
    @Option.Default("__Host-helidon-oidc-state")
    String authenticationRequestCookieName();

    /**
     * Local authentication result cookie name.
     * <p>
     * Must be a valid HTTP cookie token. The provider derives a browser-session generation cookie name by appending
     * {@code -generation}; both names must differ from {@link #authenticationRequestCookieName()}.
     *
     * @return local authentication result cookie name
     */
    @Option.Configured
    @Option.Default("__Host-helidon-oidc-auth")
    String localAuthenticationCookieName();

    /**
     * Authentication Request state lifetime.
     * <p>
     * Must be positive.
     *
     * @return Authentication Request state lifetime
     */
    @Option.Configured
    @Option.Default("PT5M")
    Duration authenticationRequestLifetime();

    /**
     * Maximum local authentication result lifetime.
     * <p>
     * Must be positive.
     *
     * @return maximum local authentication result lifetime
     */
    @Option.Configured
    @Option.Default("PT1H")
    Duration localAuthenticationLifetime();

    /**
     * Maximum encoded size in bytes of one Authentication Request or local-authentication Set-Cookie field value,
     * including name and attributes.
     * Must leave room for the cookie framing and payload and must not exceed 4096.
     * Larger protected values are split into pieces within this limit, subject to {@link #maxChunks()}
     * and {@link #maxTotalSize()}.
     *
     * @return maximum serialized cookie size
     */
    @Option.Configured
    @Option.DefaultInt(3800)
    int maxCookieSize();

    /**
     * Maximum cookie pieces in each Authentication Request or local authentication result, including the base cookie,
     * between 1 and 16. A value of one permits only single-cookie values. Applies to reads and writes.
     *
     * @return maximum cookie count
     */
    @Option.Configured
    @Option.DefaultInt(4)
    int maxChunks();

    /**
     * Maximum aggregate request-header contribution of this tenant's OIDC cookies in bytes, including names and separators.
     * Includes authentication state, local authentication and browser generation. Also bounds outgoing login and session
     * Set-Cookie updates, including required deletion headers, and must allow clearing
     * the fixed session cookie namespace. Must not exceed 65536.
     * Other application cookies and HTTP headers need separate header headroom.
     *
     * @return maximum encoded OIDC cookie header size
     */
    @Option.Configured
    @Option.DefaultInt(12288)
    int maxTotalSize();

    /**
     * Compression policy for new local-authentication sessions; independent of the identity provider.
     * GZIP remains readable when writing compression is disabled. Decompression follows successful authentication
     * and is bounded by {@link #maxSessionSize()}.
     *
     * @return compression policy
     */
    @Option.Configured
    @Option.Default("NONE")
    OidcCookieCompression compression();

    /**
     * Maximum UTF-8 Authentication Request or session JSON size before compression and after authenticated decompression.
     * Must be positive and no greater than 1048576 bytes. Applies even when compression is disabled.
     *
     * @return maximum decoded protected payload size
     */
    @Option.Configured
    @Option.DefaultInt(65536)
    int maxSessionSize();

    /**
     * Deployment-specific password from which cookie encryption keys are derived.
     * <p>
     * Must contain between 16 and 1024 characters. Use a strong, randomly generated value and configure the same
     * password on all replicas that accept the same browser session. Authorization Code Flow requires this setting
     * because its Authentication Request and local authentication cookies contain security-sensitive state.
     *
     * @return cookie protection password, if configured
     */
    @Option.Configured
    @Option.Confidential
    Optional<String> password();
}
