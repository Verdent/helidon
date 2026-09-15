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
 * and callers waiting for an existing same-key operation. Requests that cannot enter the queue within the admission
 * timeout fail without starting remote work.
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
     * Total time allowed for admission.
     * <p>
     * A new operation may join the bounded queue and obtain an active-operation permit; a same-key follower may reserve
     * a queue slot. Zero configures fail-fast admission when capacity is unavailable. Once admitted as a same-key
     * follower, a caller waits interruptibly for that operation rather than applying this timeout to the remote
     * operation itself.
     *
     * @return admission timeout
     */
    @Option.Configured
    @Option.Default("PT1S")
    Duration admissionTimeout();
}
