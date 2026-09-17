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
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Per-tenant admission control for one category of remote OIDC work.
 */
final class OidcRemoteWorkLimiter {
    private final int maxConcurrent;
    private final int maxQueued;
    private final long admissionTimeoutNanos;
    private final Semaphore active;
    private final Semaphore queued;

    OidcRemoteWorkLimiter(OidcRemoteWorkConfig config) {
        this.maxConcurrent = config.maxConcurrent();
        this.maxQueued = config.maxQueued();
        this.admissionTimeoutNanos = saturatedNanos(config.admissionTimeout());
        this.active = new Semaphore(maxConcurrent, true);
        this.queued = new Semaphore(maxQueued, true);
    }

    Optional<Permit> acquireActive() {
        if (Thread.currentThread().isInterrupted()) {
            return Optional.empty();
        }
        Optional<Permit> activePermit = acquire(active, 0);
        if (activePermit.isPresent()) {
            return activePermit;
        }
        if (maxQueued == 0) {
            return Optional.empty();
        }

        // Reserve queue capacity without waiting so maxQueued is a hard bound on retained callers.
        Optional<Permit> queuePermit = acquire(queued, 0);
        if (queuePermit.isEmpty()) {
            return Optional.empty();
        }
        try (Permit ignored = queuePermit.orElseThrow()) {
            return acquire(active, admissionTimeoutNanos);
        }
    }

    Optional<Permit> acquireWaiter() {
        return maxQueued == 0 ? Optional.empty() : acquire(queued, 0);
    }

    int activeCount() {
        return maxConcurrent - active.availablePermits();
    }

    int queuedCount() {
        return maxQueued - queued.availablePermits();
    }

    private Optional<Permit> acquire(Semaphore semaphore, long timeoutNanos) {
        if (Thread.currentThread().isInterrupted()) {
            return Optional.empty();
        }
        try {
            // Timed zero honors the fair semaphore's queue; untimed tryAcquire would allow new callers to barge.
            boolean acquired = semaphore.tryAcquire(0, TimeUnit.NANOSECONDS)
                    || (timeoutNanos > 0 && semaphore.tryAcquire(timeoutNanos, TimeUnit.NANOSECONDS));
            return acquired ? Optional.of(new Permit(semaphore)) : Optional.empty();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Optional.empty();
        }
    }

    private static long saturatedNanos(Duration duration) {
        try {
            return duration.toNanos();
        } catch (ArithmeticException _) {
            return Long.MAX_VALUE;
        }
    }

    static final class Permit implements AutoCloseable {
        private final Semaphore semaphore;
        private final AtomicBoolean closed = new AtomicBoolean();

        private Permit(Semaphore semaphore) {
            this.semaphore = semaphore;
        }

        @Override
        public void close() {
            if (closed.compareAndSet(false, true)) {
                semaphore.release();
            }
        }
    }
}
