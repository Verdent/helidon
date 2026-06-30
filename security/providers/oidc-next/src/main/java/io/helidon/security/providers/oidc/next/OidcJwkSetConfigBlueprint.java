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
 * JSON Web Key Set loading and reload policy.
 */
@Prototype.Blueprint
@Prototype.Configured
interface OidcJwkSetConfigBlueprint {
    /**
     * Whether an unknown JWT {@code kid} should trigger a JWK Set reload attempt.
     *
     * @return whether unknown key ids trigger JWK Set reload
     */
    @Option.Configured
    @Option.DefaultBoolean(true)
    boolean unknownKeyIdRefreshEnabled();

    /**
     * Global minimum interval between JWK Set reload attempts triggered by any unknown key id.
     *
     * @return unknown key id refresh interval
     */
    @Option.Configured
    @Option.Default("PT5M")
    Duration unknownKeyIdRefreshInterval();

    /**
     * Lazy JWK Set refresh interval.
     * <p>
     * If configured, cached keys older than this interval are refreshed during token validation. No background refresh
     * thread is started.
     *
     * @return lazy refresh interval
     */
    @Option.Configured
    Optional<Duration> refreshInterval();

    /**
     * Whether cached keys may be used when a reload fails.
     * <p>
     * Initial JWK Set loading still fails when no cached keys exist.
     *
     * @return whether stale cached keys may be used on reload failure
     */
    @Option.Configured
    @Option.DefaultBoolean(true)
    boolean staleOnError();
}
