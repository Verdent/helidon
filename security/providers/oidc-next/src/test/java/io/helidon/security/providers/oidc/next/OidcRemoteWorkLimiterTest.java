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
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class OidcRemoteWorkLimiterTest {
    @Test
    void untimedAdmissionIgnoresTheConfiguredTimeoutAndReclaimsPermits() throws Exception {
        OidcRemoteWorkLimiter limiter = limiter(1, 1);
        CompletableFuture<Boolean> completed = new CompletableFuture<>();
        OidcRemoteWorkLimiter.Permit leader = limiter.acquireActiveWithoutTimeout().orElseThrow();
        try {
            Thread.ofVirtual().start(() -> {
                var permit = limiter.acquireActiveWithoutTimeout();
                permit.ifPresent(OidcRemoteWorkLimiter.Permit::close);
                completed.complete(permit.isPresent());
            });
            awaitQueued(limiter, 1);
            assertThrows(TimeoutException.class, () -> completed.get(50, TimeUnit.MILLISECONDS));
            assertThat(limiter.acquireActiveWithoutTimeout().isEmpty(), is(true));
        } finally {
            leader.close();
        }
        assertThat(completed.get(5, TimeUnit.SECONDS), is(true));
        assertThat(limiter.activeCount(), is(0));
        assertThat(limiter.queuedCount(), is(0));
    }

    @Test
    void untimedAdmissionIsInterruptibleAndReleasesItsQueueSlot() throws Exception {
        OidcRemoteWorkLimiter limiter = limiter(1, 1);
        AtomicBoolean admitted = new AtomicBoolean(true);
        AtomicBoolean interrupted = new AtomicBoolean();
        try (var _ = limiter.acquireActiveWithoutTimeout().orElseThrow()) {
            Thread follower = Thread.ofVirtual().start(() -> {
                var permit = limiter.acquireActiveWithoutTimeout();
                admitted.set(permit.isPresent());
                interrupted.set(Thread.currentThread().isInterrupted());
                permit.ifPresent(OidcRemoteWorkLimiter.Permit::close);
            });
            awaitQueued(limiter, 1);
            follower.interrupt();
            follower.join(Duration.ofSeconds(5));
            assertThat(follower.isAlive(), is(false));
            assertThat(admitted.get(), is(false));
            assertThat(interrupted.get(), is(true));
            assertThat(limiter.activeCount(), is(1));
            assertThat(limiter.queuedCount(), is(0));
        }
        assertThat(limiter.activeCount(), is(0));
    }

    @Test
    void untimedAdmissionPreservesPreInterruptionAndZeroQueueSemantics() {
        OidcRemoteWorkLimiter limiter = limiter(1, 0);
        Thread.currentThread().interrupt();
        try {
            assertThat(limiter.acquireActiveWithoutTimeout().isEmpty(), is(true));
            assertThat(Thread.currentThread().isInterrupted(), is(true));
            assertThat(limiter.activeCount(), is(0));
        } finally {
            Thread.interrupted();
        }
        try (var _ = limiter.acquireActiveWithoutTimeout().orElseThrow()) {
            assertThat(limiter.acquireActiveWithoutTimeout().isEmpty(), is(true));
            assertThat(limiter.queuedCount(), is(0));
        }
        assertThat(limiter.activeCount(), is(0));
    }

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
    void zeroQueueRejectsImmediatelyRegardlessOfAdmissionTimeout() throws Exception {
        OidcRemoteWorkLimiter limiter = new OidcRemoteWorkLimiter(OidcRemoteWorkConfig.builder()
                                                                          .maxConcurrent(1)
                                                                          .maxQueued(0)
                                                                          .admissionTimeout(Duration.ofHours(1))
                                                                          .buildPrototype());
        try (OidcRemoteWorkLimiter.Permit _ = limiter.acquireActive().orElseThrow();
                ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            // Bound the test despite the one-hour admission timeout if zero-queue rejection regresses.
            Future<Boolean> rejected = executor.submit(() -> limiter.acquireActive().isEmpty()
                    && limiter.acquireWaiter().isEmpty());
            try {
                assertThat(rejected.get(1, TimeUnit.SECONDS), is(true));
            } finally {
                rejected.cancel(true);
            }
        }
    }

    @Test
    void fullQueueRejectsOverflowVirtualThreadWithoutParkingOutsideBound() throws Exception {
        OidcRemoteWorkLimiter limiter = new OidcRemoteWorkLimiter(OidcRemoteWorkConfig.builder()
                                                                          .maxConcurrent(1)
                                                                          .maxQueued(1)
                                                                          .admissionTimeout(Duration.ofHours(1))
                                                                          .buildPrototype());
        AtomicBoolean admitted = new AtomicBoolean(true);
        try (OidcRemoteWorkLimiter.Permit _ = limiter.acquireWaiter().orElseThrow()) {
            Thread overflow = Thread.ofVirtual().start(() -> {
                var permit = limiter.acquireWaiter();
                admitted.set(permit.isPresent());
                permit.ifPresent(OidcRemoteWorkLimiter.Permit::close);
            });
            overflow.join(500);
            boolean completedWithoutInterruption = !overflow.isAlive();
            if (overflow.isAlive()) {
                overflow.interrupt();
                overflow.join(5_000);
            }

            assertThat(completedWithoutInterruption, is(true));
            assertThat(admitted.get(), is(false));
            assertThat(limiter.queuedCount(), is(1));
        }
        assertThat(limiter.queuedCount(), is(0));
    }

    @Test
    void virtualThreadWaitingForActivePermitIsInterruptibleAndReleasesQueueSlot() throws Exception {
        OidcRemoteWorkLimiter limiter = new OidcRemoteWorkLimiter(OidcRemoteWorkConfig.builder()
                                                                          .maxConcurrent(1)
                                                                          .maxQueued(1)
                                                                          .admissionTimeout(Duration.ofHours(1))
                                                                          .buildPrototype());
        AtomicBoolean admitted = new AtomicBoolean(true);
        AtomicBoolean interrupted = new AtomicBoolean();
        try (OidcRemoteWorkLimiter.Permit _ = limiter.acquireActive().orElseThrow()) {
            Thread queued = Thread.ofVirtual().start(() -> {
                var permit = limiter.acquireActive();
                admitted.set(permit.isPresent());
                interrupted.set(Thread.currentThread().isInterrupted());
                permit.ifPresent(OidcRemoteWorkLimiter.Permit::close);
            });
            awaitQueued(limiter, 1);

            assertThat(limiter.acquireActive().isEmpty(), is(true));
            queued.interrupt();
            queued.join(5_000);

            assertThat(queued.isAlive(), is(false));
            assertThat(admitted.get(), is(false));
            assertThat(interrupted.get(), is(true));
            assertThat(limiter.activeCount(), is(1));
            assertThat(limiter.queuedCount(), is(0));
        }
        assertThat(limiter.activeCount(), is(0));
    }

    private static OidcRemoteWorkLimiter limiter(int maxConcurrent, int maxQueued) {
        return new OidcRemoteWorkLimiter(OidcRemoteWorkConfig.builder()
                                                 .maxConcurrent(maxConcurrent)
                                                 .maxQueued(maxQueued)
                                                 .admissionTimeout(Duration.ZERO)
                                                 .buildPrototype());
    }

    private static void awaitQueued(OidcRemoteWorkLimiter limiter, int expected) {
        long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
        while (limiter.queuedCount() != expected) {
            if (System.nanoTime() >= deadline) {
                throw new AssertionError("Timed out waiting for queued remote work");
            }
            Thread.onSpinWait();
        }
    }
}
