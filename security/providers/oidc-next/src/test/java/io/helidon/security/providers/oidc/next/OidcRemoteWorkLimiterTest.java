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

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

class OidcRemoteWorkLimiterTest {
    @Test
    void boundsActiveAndQueuedPermitsAndReclaimsCapacity() {
        OidcRemoteWorkLimiter limiter = limiter(2, 2);
        OidcRemoteWorkLimiter.Permit firstActive = limiter.acquireActive().orElseThrow();
        OidcRemoteWorkLimiter.Permit secondActive = limiter.acquireActive().orElseThrow();
        OidcRemoteWorkLimiter.Permit firstWaiter = limiter.acquireWaiter().orElseThrow();
        OidcRemoteWorkLimiter.Permit secondWaiter = limiter.acquireWaiter().orElseThrow();

        assertThat(limiter.activeCount(), is(2));
        assertThat(limiter.queuedCount(), is(2));
        assertThat(limiter.acquireActive().isEmpty(), is(true));
        assertThat(limiter.acquireWaiter().isEmpty(), is(true));

        firstActive.close();
        secondActive.close();
        firstWaiter.close();
        secondWaiter.close();
        assertThat(limiter.activeCount(), is(0));
        assertThat(limiter.queuedCount(), is(0));
    }

    @Test
    void interruptedCallerIsNotAdmittedAndInterruptRemainsSet() {
        OidcRemoteWorkLimiter limiter = limiter(1, 1);
        Thread.currentThread().interrupt();
        try {
            assertThat(limiter.acquireActive().isEmpty(), is(true));
            assertThat(limiter.acquireWaiter().isEmpty(), is(true));
            assertThat(Thread.currentThread().isInterrupted(), is(true));
        } finally {
            Thread.interrupted();
        }
    }

    @Test
    void zeroQueueRejectsImmediatelyRegardlessOfAdmissionTimeout() {
        OidcRemoteWorkLimiter limiter = new OidcRemoteWorkLimiter(OidcRemoteWorkConfig.builder()
                                                                          .maxConcurrent(1)
                                                                          .maxQueued(0)
                                                                          .admissionTimeout(Duration.ofHours(1))
                                                                          .buildPrototype());
        try (OidcRemoteWorkLimiter.Permit ignored = limiter.acquireActive().orElseThrow()) {
            assertTimeoutPreemptively(Duration.ofSeconds(1),
                                      () -> assertThat(limiter.acquireActive().isEmpty(), is(true)));
            assertTimeoutPreemptively(Duration.ofSeconds(1),
                                      () -> assertThat(limiter.acquireWaiter().isEmpty(), is(true)));
        }
    }

    private static OidcRemoteWorkLimiter limiter(int maxConcurrent, int maxQueued) {
        return new OidcRemoteWorkLimiter(OidcRemoteWorkConfig.builder()
                                                 .maxConcurrent(maxConcurrent)
                                                 .maxQueued(maxQueued)
                                                 .admissionTimeout(Duration.ZERO)
                                                 .buildPrototype());
    }
}
