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

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import java.util.stream.Stream;

import io.helidon.config.Config;
import io.helidon.config.ConfigSources;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import static org.hamcrest.CoreMatchers.anyOf;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.sameInstance;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;

class OidcTenantInitializationTest {
    @Test
    void interruptedWaiterReleasesCapacityForAnotherFollower() throws Exception {
        try (Initialization initialization = new Initialization(1)) {
            Call leader = initialization.call();
            assertThat(initialization.entered.await(5, TimeUnit.SECONDS), is(true));
            Call cancelled = initialization.call();
            cancelled.awaitWaiting();
            assertThat(initialization.call().failure(), instanceOf(OidcTenantRuntimeRegistry.UnavailableException.class));
            cancelled.thread.interrupt();
            assertThat(cancelled.failure(), instanceOf(OidcTenantRuntimeRegistry.UnavailableException.class));
            assertThat(cancelled.interrupted.get(), is(true));
            Call replacement = initialization.call();
            replacement.awaitWaiting();
            assertThat(initialization.call().failure(), instanceOf(OidcTenantRuntimeRegistry.UnavailableException.class));
            initialization.release.countDown();
            assertThat(replacement.result.get(5, TimeUnit.SECONDS), sameInstance(leader.result.get(5, TimeUnit.SECONDS)));
            assertThat(initialization.attempts.get(), is(1));
        }
    }

    @Test
    void zeroQueueAdmitsAnIdleInitializerAndRejectsFollowers() throws Exception {
        try (Initialization initialization = new Initialization(0)) {
            Call leader = initialization.call();
            assertThat(initialization.entered.await(5, TimeUnit.SECONDS), is(true));
            assertThat(initialization.call().failure(), instanceOf(OidcTenantRuntimeRegistry.UnavailableException.class));
            initialization.release.countDown();
            OidcTenantContext ready = leader.result.get(5, TimeUnit.SECONDS);
            assertThat(initialization.context(), sameInstance(ready));
            assertThat(initialization.attempts.get(), is(1));
        }
    }

    @Test
    void preInterruptedColdCallerDoesNotInitializeAndReadyContextBypassesAdmission() throws Exception {
        try (Initialization initialization = new Initialization(0)) {
            Supplier<OidcTenantContext> interruptedLookup = () -> {
                Thread.currentThread().interrupt();
                return initialization.context();
            };
            Call rejected = new Call(interruptedLookup);
            assertThat(rejected.failure(), instanceOf(OidcTenantRuntimeRegistry.UnavailableException.class));
            assertThat(rejected.interrupted.get(), is(true));
            assertThat(initialization.attempts.get(), is(0));
            initialization.release.countDown();
            OidcTenantContext ready = initialization.context();
            Call warm = new Call(interruptedLookup);
            assertThat(warm.result.get(5, TimeUnit.SECONDS), sameInstance(ready));
            assertThat(warm.interrupted.get(), is(true));
            assertThat(initialization.attempts.get(), is(1));
        }
    }

    @TestFactory
    Stream<DynamicTest> retryAdmissionPreservesTheSharedOutcomeAndBackoff() {
        return Stream.of(false, true).map(retryFails -> dynamicTest("retryFails=" + retryFails, () -> {
            MutableClock clock = new MutableClock();
            AtomicInteger attempts = new AtomicInteger();
            CountDownLatch entered = new CountDownLatch(1);
            CountDownLatch release = new CountDownLatch(1);
            OidcProviderConfig config = OidcProviderConfig.builder().putTenant("tenant", tenant(1)).buildPrototype();
            OidcTenantRuntimeRegistry registry = OidcTenantRuntimeRegistry.create(config,
                    OidcTenantContextFactory.create((id, tenant) -> {
                        int attempt = attempts.incrementAndGet();
                        if (attempt == 1) {
                            return OidcTenantContext.retryableFailure(id, tenant, new IllegalStateException("initial failure"));
                        }
                        if (attempt == 2) {
                            entered.countDown();
                            await(release);
                            if (retryFails) {
                                return OidcTenantContext.retryableFailure(id, tenant, new IllegalStateException("retry failure"));
                            }
                        }
                        return OidcTenantContext.ready(id, tenant);
                    }), clock);
            Supplier<OidcTenantContext> lookup = () -> registry.tenantContext("tenant").orElseThrow();
            try {
                OidcTenantContext original = lookup.get();
                clock.advance(Duration.ofSeconds(9));
                Call heldFailure = new Call(() -> {
                    Thread.currentThread().interrupt();
                    return lookup.get();
                });
                assertThat(heldFailure.result.get(5, TimeUnit.SECONDS), sameInstance(original));
                assertThat(heldFailure.interrupted.get(), is(true));
                assertThat(attempts.get(), is(1));
                clock.advance(Duration.ofSeconds(1));
                Call leader = new Call(lookup);
                assertThat(entered.await(5, TimeUnit.SECONDS), is(true));
                Call follower = new Call(lookup);
                follower.awaitWaiting();
                assertThat(new Call(lookup).failure(), instanceOf(OidcTenantRuntimeRegistry.UnavailableException.class));
                release.countDown();
                OidcTenantContext retried = leader.result.get(5, TimeUnit.SECONDS);
                assertThat(follower.result.get(5, TimeUnit.SECONDS), sameInstance(retried));
                assertThat(retried.ready(), is(!retryFails));
                assertThat(attempts.get(), is(2));
                clock.advance(Duration.ofSeconds(9));
                assertThat(lookup.get(), sameInstance(retried));
                assertThat(attempts.get(), is(2));
                clock.advance(Duration.ofSeconds(1));
                assertThat(lookup.get().ready(), is(true));
                assertThat(attempts.get(), is(retryFails ? 3 : 2));
            } finally {
                release.countDown();
                registry.close();
            }
        }));
    }

    @Test
    void permanentFailureIsRetainedWithoutAdmissionOrRetry() throws Exception {
        MutableClock clock = new MutableClock();
        AtomicInteger attempts = new AtomicInteger();
        OidcProviderConfig config = OidcProviderConfig.builder().putTenant("tenant", tenant(0)).buildPrototype();
        OidcTenantRuntimeRegistry registry = OidcTenantRuntimeRegistry.create(config,
                OidcTenantContextFactory.create((id, tenant) -> {
                    attempts.incrementAndGet();
                    return OidcTenantContext.failed(id, tenant, new IllegalStateException("incompatible metadata"));
                }), clock);
        try {
            OidcTenantContext failed = registry.tenantContext("tenant").orElseThrow();
            clock.advance(Duration.ofDays(1));
            Call warm = new Call(() -> {
                Thread.currentThread().interrupt();
                return registry.tenantContext("tenant").orElseThrow();
            });
            assertThat(warm.result.get(5, TimeUnit.SECONDS), sameInstance(failed));
            assertThat(warm.interrupted.get(), is(true));
            assertThat(attempts.get(), is(1));
        } finally {
            registry.close();
        }
    }

    @Test
    void oneTenantsInitializationDoesNotConsumeAnotherTenantsCapacity() throws Exception {
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicInteger attempts = new AtomicInteger();
        OidcProviderConfig config = OidcProviderConfig.builder().putTenant("busy", tenant(0))
                .putTenant("independent", tenant(0)).buildPrototype();
        OidcTenantRuntimeRegistry registry = OidcTenantRuntimeRegistry.create(config,
                OidcTenantContextFactory.create((id, tenant) -> {
                    attempts.incrementAndGet();
                    if ("busy".equals(id)) {
                        entered.countDown();
                        await(release);
                    }
                    return OidcTenantContext.ready(id, tenant);
                }));
        try {
            Call leader = new Call(() -> registry.tenantContext("busy").orElseThrow());
            assertThat(entered.await(5, TimeUnit.SECONDS), is(true));
            Call rejected = new Call(() -> registry.tenantContext("busy").orElseThrow());
            assertThat(rejected.failure(), instanceOf(OidcTenantRuntimeRegistry.UnavailableException.class));
            Call independent = new Call(() -> registry.tenantContext("independent").orElseThrow());
            OidcTenantContext ready = independent.result.get(5, TimeUnit.SECONDS);
            assertThat(ready.ready(), is(true));
            assertThat(registry.tenantContext("independent").orElseThrow(), sameInstance(ready));
            assertThat(leader.result.isDone(), is(false));
            assertThat(attempts.get(), is(2));
            release.countDown();
            assertThat(leader.result.get(5, TimeUnit.SECONDS).ready(), is(true));
        } finally {
            release.countDown();
            registry.close();
        }
    }

    @Test
    void interruptedFollowerStopsWaitingWithoutCancellingInitialization() throws Exception {
        try (Initialization initialization = new Initialization(1)) {
            Call leader = initialization.call();
            assertThat(initialization.entered.await(5, TimeUnit.SECONDS), is(true));
            Call follower = initialization.call();
            follower.awaitWaiting();
            follower.thread.interrupt();

            assertThat(follower.failure(), instanceOf(IllegalStateException.class));
            assertThat(follower.interrupted.get(), is(true));
            assertThat(leader.result.isDone(), is(false));
            initialization.release.countDown();
            OidcTenantContext ready = leader.result.get(5, TimeUnit.SECONDS);
            assertThat(initialization.context(), sameInstance(ready));
            assertThat(initialization.attempts.get(), is(1));
        }
    }

    @Test
    void callerBeyondQueueCapacityDoesNotWaitForInitialization() throws Exception {
        try (Initialization initialization = new Initialization(1)) {
            Call leader = initialization.call();
            assertThat(initialization.entered.await(5, TimeUnit.SECONDS), is(true));
            Call admitted = initialization.call();
            admitted.awaitWaiting();
            Call rejected = initialization.call();

            assertThat(rejected.failure(), instanceOf(IllegalStateException.class));
            assertThat(leader.result.isDone(), is(false));
            assertThat(admitted.result.isDone(), is(false));
            initialization.release.countDown();
            OidcTenantContext ready = leader.result.get(5, TimeUnit.SECONDS);
            assertThat(admitted.result.get(5, TimeUnit.SECONDS), sameInstance(ready));
            assertThat(initialization.context(), sameInstance(ready));
            assertThat(initialization.attempts.get(), is(1));
        }
    }

    @Test
    void admittedFollowerCanWaitLongerThanOneSecond() throws Exception {
        try (Initialization initialization = new Initialization(1)) {
            Call leader = initialization.call();
            assertThat(initialization.entered.await(5, TimeUnit.SECONDS), is(true));
            Call admitted = initialization.call();
            admitted.awaitWaiting();
            assertThrows(TimeoutException.class, () -> admitted.result.get(1500, TimeUnit.MILLISECONDS));
            initialization.release.countDown();
            assertThat(admitted.result.get(5, TimeUnit.SECONDS), sameInstance(leader.result.get(5, TimeUnit.SECONDS)));
            assertThat(initialization.attempts.get(), is(1));
        }
    }

    private static OidcTenantConfig tenant(int maxQueued) {
        return OidcTenantConfig.create(Config.builder().disableEnvironmentVariablesSource().disableSystemPropertiesSource()
                .sources(ConfigSources.create(Map.of("initialization-max-queued", Integer.toString(maxQueued)))).build());
    }

    private static void await(CountDownLatch latch) {
        try {
            if (!latch.await(10, TimeUnit.SECONDS)) {
                throw new IllegalStateException("Test did not release tenant initialization");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    private static final class Initialization implements AutoCloseable {
        private final CountDownLatch entered = new CountDownLatch(1);
        private final CountDownLatch release = new CountDownLatch(1);
        private final AtomicInteger attempts = new AtomicInteger();
        private final OidcTenantRuntimeRegistry registry;

        private Initialization(int maxQueued) {
            registry = OidcTenantRuntimeRegistry.create(OidcProviderConfig.builder().putTenant("tenant", tenant(maxQueued))
                    .buildPrototype(), OidcTenantContextFactory.create((id, config) -> {
                        attempts.incrementAndGet();
                        entered.countDown();
                        await(release);
                        return OidcTenantContext.ready(id, config);
                    }));
        }

        @Override
        public void close() {
            release.countDown();
            registry.close();
        }

        private OidcTenantContext context() {
            return registry.tenantContext("tenant").orElseThrow();
        }

        private Call call() {
            return new Call(this::context);
        }
    }

    private static final class Call {
        private final CompletableFuture<OidcTenantContext> result = new CompletableFuture<>();
        private final AtomicBoolean interrupted = new AtomicBoolean();
        private final Thread thread;

        private Call(Supplier<OidcTenantContext> action) {
            thread = Thread.ofVirtual().start(() -> {
                OidcTenantContext context = null;
                Throwable failure = null;
                try {
                    context = action.get();
                } catch (Throwable e) {
                    failure = e;
                }
                interrupted.set(Thread.currentThread().isInterrupted());
                if (failure == null) {
                    result.complete(context);
                } else {
                    result.completeExceptionally(failure);
                }
            });
        }

        private Throwable failure() {
            return assertThrows(ExecutionException.class, () -> result.get(2, TimeUnit.SECONDS)).getCause();
        }

        private void awaitWaiting() throws InterruptedException {
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            while (thread.getState() != Thread.State.WAITING && thread.getState() != Thread.State.TIMED_WAITING
                    && !result.isDone() && System.nanoTime() < deadline) {
                Thread.sleep(5);
            }
            assertThat(thread.getState(), anyOf(is(Thread.State.WAITING), is(Thread.State.TIMED_WAITING)));
        }
    }

    private static final class MutableClock extends Clock {
        private final AtomicReference<Instant> now;
        private final ZoneId zone;

        private MutableClock() {
            this(new AtomicReference<>(Instant.parse("2026-09-21T00:00:00Z")), ZoneOffset.UTC);
        }

        private MutableClock(AtomicReference<Instant> now, ZoneId zone) {
            this.now = now;
            this.zone = zone;
        }

        @Override
        public ZoneId getZone() {
            return zone;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return new MutableClock(now, zone);
        }

        @Override
        public Instant instant() {
            return now.get();
        }

        private void advance(Duration duration) {
            now.updateAndGet(value -> value.plus(duration));
        }
    }
}
