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
@Prototype.Blueprint(decorator = OidcJwkSetConfigDecorator.class)
@Prototype.Configured
interface OidcJwkSetConfigBlueprint {
    /**
     * Maximum number of callers waiting for JWK Set load or refresh coordination.
     * <p>
     * Each key-set manager admits one caller at a time and coalesces its waiting callers using the published outcome.
     * Cache hits bypass admission. This limit applies independently to the provider's JWK Set and a configured local
     * access-token verification set. Zero rejects callers immediately when coordination is occupied.
     *
     * @return maximum queued callers
     */
    @Option.Configured
    @Option.DefaultInt(128)
    int maxQueued();

    /**
     * Maximum time an admitted waiting caller may spend obtaining JWK Set load or refresh coordination.
     * <p>
     * Queue capacity is reserved without waiting. Waiting is interruptible and does not cancel the shared load.
     * This is not the key-source I/O timeout; remote loads use the tenant WebClient timeouts. Zero configures fail-fast
     * admission. Exhaustion, timeout, and interruption are unavailable outcomes, not invalid-token decisions.
     *
     * @return coordination admission timeout
     */
    @Option.Configured
    @Option.Default("PT1S")
    Duration admissionTimeout();

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
     * Minimum interval before retrying a failed JWK Set load.
     * <p>
     * All callers within this interval observe the same failed refresh outcome. When cached keys exist,
     * {@link #staleOnError()} determines whether those keys may be returned during the interval.
     *
     * @return failed-load retry interval
     */
    @Option.Configured
    @Option.Default("PT10S")
    Duration failureRetryInterval();

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
