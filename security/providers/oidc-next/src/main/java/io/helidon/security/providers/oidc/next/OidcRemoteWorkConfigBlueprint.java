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

import io.helidon.builder.api.Option;
import io.helidon.builder.api.Prototype;

/**
 * Admission limits for high-cardinality OIDC remote work.
 * <p>
 * The active limit bounds remote HTTP operations. The queued limit is shared by leaders waiting for an active permit
 * and callers waiting for an existing same-key operation. Queue capacity is reserved without waiting, making the queued
 * limit a hard bound. Requests that cannot reserve a slot fail without starting remote work.
 */
@Prototype.Blueprint(decorator = OidcRemoteWorkConfigDecorator.class)
@Prototype.Configured
interface OidcRemoteWorkConfigBlueprint {
    /**
     * Maximum number of concurrent remote HTTP operations.
     *
     * @return maximum concurrent operations
     */
    @Option.Configured
    @Option.DefaultInt(32)
    int maxConcurrent();

    /**
     * Maximum number of callers waiting for an active operation or same-key result.
     * <p>
     * Zero configures fail-fast admission when all active permits are occupied.
     *
     * @return maximum queued callers
     */
    @Option.Configured
    @Option.DefaultInt(128)
    int maxQueued();

    /**
     * Time allowed for an admitted new operation to obtain an active-operation permit.
     * <p>
     * Queue capacity is reserved without waiting. A new operation which reserves a queue slot may wait for this duration
     * to obtain an active-operation permit. Once a same-key follower reserves a queue slot, it waits interruptibly for
     * that operation rather than applying this timeout to the remote operation itself. Zero configures fail-fast active
     * admission.
     *
     * @return admission timeout
     */
    @Option.Configured
    @Option.Default("PT1S")
    Duration admissionTimeout();
}
