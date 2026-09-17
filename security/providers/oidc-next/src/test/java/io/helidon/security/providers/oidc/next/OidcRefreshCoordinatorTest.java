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
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import io.helidon.common.configurable.Resource;
import io.helidon.security.jwt.Jwt;
import io.helidon.security.jwt.SignedJwt;
import io.helidon.security.jwt.jwk.JwkKeys;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

class OidcRefreshCoordinatorTest {
    private static final Instant CREATED_AT = Instant.parse("2026-09-16T12:00:00Z");

    private static OidcValidatedIdToken idToken;

    @BeforeAll
    static void initClass() {
        JwkKeys signKeys = JwkKeys.builder()
                .resource(Resource.create("oidc-next-sign-jwk.json"))
                .build();
        Jwt jwt = Jwt.builder()
                .type("JWT")
                .subject("subject")
                .issuer("https://issuer.example")
                .algorithm("RS256")
                .keyId("sign-rsa")
                .issueTime(CREATED_AT)
                .expirationTime(CREATED_AT.plus(Duration.ofHours(1)))
                .addAudience("client-id")
                .build();
        SignedJwt signedJwt = SignedJwt.sign(jwt, signKeys.forKeyId("sign-rsa").orElseThrow());
        idToken = new OidcValidatedIdToken(signedJwt.tokenContent(), false, signedJwt, signedJwt.getJwt());
    }

    @Test
    void completedResultUsesBoundedMonotonicGraceInterval() {
        Duration retention = Duration.ofSeconds(5);
        AtomicLong nanoTime = new AtomicLong(100);
        OidcRefreshCoordinator<String> coordinator = new OidcRefreshCoordinator<>(
                config(retention, 2, 1, 2),
                nanoTime::get);
        OidcLocalAuthenticationResult source = authentication("access", "refresh", CREATED_AT, "generation");
        AtomicInteger loads = new AtomicInteger();

        assertThat(resolve(coordinator, source, loads), is("result-1"));
        assertThat(resolve(coordinator, source, loads), is("result-1"));
        nanoTime.addAndGet(retention.toNanos() - 1);
        assertThat(resolve(coordinator, source, loads), is("result-1"));
        nanoTime.incrementAndGet();
        assertThat(resolve(coordinator, source, loads), is("result-2"));
        assertThat(coordinator.cachedResultCount(), is(1));
    }

    @Test
    void changedSourceStateDoesNotReuseNonRotatingRefreshTokenResult() {
        AtomicLong nanoTime = new AtomicLong();
        OidcRefreshCoordinator<String> coordinator = new OidcRefreshCoordinator<>(
                config(Duration.ofSeconds(5), 2, 1, 2),
                nanoTime::get);
        OidcLocalAuthenticationResult first = authentication("access-1", "same-refresh", CREATED_AT, "generation");
        OidcLocalAuthenticationResult refreshed = authentication("access-2",
                                                                  "same-refresh",
                                                                  CREATED_AT.plusMillis(1),
                                                                  "generation");
        AtomicInteger loads = new AtomicInteger();

        assertThat(resolve(coordinator, first, loads), is("result-1"));
        assertThat(resolve(coordinator, refreshed, loads), is("result-2"));
        assertThat(coordinator.cachedResultCount(), is(2));
    }

    @Test
    void cachedResultMustRemainValidForCurrentCaller() {
        OidcRefreshCoordinator<String> coordinator = new OidcRefreshCoordinator<>(
                config(Duration.ofSeconds(5), 2, 1, 2),
                System::nanoTime);
        OidcLocalAuthenticationResult source = authentication("access", "refresh", CREATED_AT, "generation");
        AtomicInteger loads = new AtomicInteger();

        assertThat(coordinator.resolve(source,
                                       _ -> true,
                                       () -> "result-" + loads.incrementAndGet(),
                                       () -> "rejected"),
                   is("result-1"));
        assertThat(coordinator.resolve(source,
                                       _ -> false,
                                       () -> "result-" + loads.incrementAndGet(),
                                       () -> "rejected"),
                   is("result-2"));
    }

    @Test
    void coordinatorInstancesDoNotShareTenantOrProviderState() {
        OidcAuthorizationCodeConfig config = config(Duration.ofSeconds(5), 2, 1, 2);
        OidcRefreshCoordinator<String> first = new OidcRefreshCoordinator<>(config);
        OidcRefreshCoordinator<String> second = new OidcRefreshCoordinator<>(config);
        OidcLocalAuthenticationResult source = authentication("access", "refresh", CREATED_AT, "generation");
        AtomicInteger loads = new AtomicInteger();

        assertThat(resolve(first, source, loads), is("result-1"));
        assertThat(resolve(second, source, loads), is("result-2"));
    }

    @Test
    void completedResultCacheHasStrictCapacity() {
        OidcRefreshCoordinator<String> coordinator = new OidcRefreshCoordinator<>(
                config(Duration.ofSeconds(5), 2, 1, 2),
                System::nanoTime);
        AtomicInteger loads = new AtomicInteger();

        resolve(coordinator, authentication("access-1", "refresh-1", CREATED_AT, "generation-1"), loads);
        resolve(coordinator, authentication("access-2", "refresh-2", CREATED_AT, "generation-2"), loads);
        resolve(coordinator, authentication("access-3", "refresh-3", CREATED_AT, "generation-3"), loads);

        assertThat(loads.get(), is(3));
        assertThat(coordinator.cachedResultCount(), is(2));
    }

    @Test
    void virtualThreadFollowerWaitIsInterruptibleAndDoesNotCancelLeader() throws Exception {
        OidcRefreshCoordinator<String> coordinator = new OidcRefreshCoordinator<>(
                config(Duration.ofSeconds(5), 2, 1, 1),
                System::nanoTime);
        OidcLocalAuthenticationResult source = authentication("access", "refresh", CREATED_AT, "generation");
        CountDownLatch leaderStarted = new CountDownLatch(1);
        CountDownLatch releaseLeader = new CountDownLatch(1);
        AtomicBoolean leaderVirtual = new AtomicBoolean();
        AtomicBoolean followerVirtual = new AtomicBoolean();
        AtomicBoolean interruptedAtRejection = new AtomicBoolean();
        AtomicReference<String> followerResult = new AtomicReference<>();

        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            Future<String> leader = executor.submit(() -> coordinator.resolve(source,
                                                                               _ -> true,
                                                                               () -> {
                                                                                   leaderVirtual.set(
                                                                                           Thread.currentThread().isVirtual());
                                                                                   leaderStarted.countDown();
                                                                                   await(releaseLeader);
                                                                                   return "loaded";
                                                                               },
                                                                               () -> "leader-rejected"));
            assertThat(leaderStarted.await(5, TimeUnit.SECONDS), is(true));

            Thread follower = Thread.ofVirtual().start(() -> {
                followerVirtual.set(Thread.currentThread().isVirtual());
                followerResult.set(coordinator.resolve(source,
                                                       _ -> true,
                                                       () -> {
                                                           throw new AssertionError("Follower must not refresh");
                                                       },
                                                       () -> {
                                                           interruptedAtRejection.set(Thread.currentThread()
                                                                                             .isInterrupted());
                                                           return "interrupted";
                                                       }));
            });
            awaitQueued(coordinator.remoteWorkLimiter(), 1);
            follower.interrupt();
            follower.join(5_000);

            assertThat(follower.isAlive(), is(false));
            assertThat(followerResult.get(), is("interrupted"));
            assertThat(followerVirtual.get(), is(true));
            assertThat(interruptedAtRejection.get(), is(true));
            assertThat(coordinator.remoteWorkLimiter().queuedCount(), is(0));
            assertThat(leader.isDone(), is(false));

            releaseLeader.countDown();
            assertThat(leader.get(5, TimeUnit.SECONDS), is("loaded"));
            assertThat(leaderVirtual.get(), is(true));
            assertThat(coordinator.remoteWorkLimiter().activeCount(), is(0));
        } finally {
            releaseLeader.countDown();
        }
    }

    @Test
    void highCardinalityVirtualThreadRefreshesHaveExactActiveAndQueueBounds() throws Exception {
        int taskCount = 500;
        int maxConcurrent = 4;
        int maxQueued = 8;
        OidcRefreshCoordinator<String> coordinator = new OidcRefreshCoordinator<>(
                config(Duration.ofSeconds(5), 32, maxConcurrent, maxQueued));
        CountDownLatch tasksReady = new CountDownLatch(taskCount);
        CountDownLatch startTasks = new CountDownLatch(1);
        CountDownLatch activeLoadersStarted = new CountDownLatch(maxConcurrent);
        CountDownLatch releaseLoaders = new CountDownLatch(1);
        AtomicBoolean allTasksVirtual = new AtomicBoolean(true);
        AtomicInteger rejectionCount = new AtomicInteger();

        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<String>> results = new ArrayList<>(taskCount);
            for (int i = 0; i < taskCount; i++) {
                int task = i;
                results.add(executor.submit(() -> {
                    if (!Thread.currentThread().isVirtual()) {
                        allTasksVirtual.set(false);
                    }
                    OidcLocalAuthenticationResult source = authentication("access-" + task,
                                                                          "refresh-" + task,
                                                                          CREATED_AT,
                                                                          "generation-" + task);
                    tasksReady.countDown();
                    if (!startTasks.await(5, TimeUnit.SECONDS)) {
                        throw new AssertionError("Timed out waiting to start refresh task");
                    }
                    return coordinator.resolve(source,
                                               _ -> true,
                                               () -> {
                                                   activeLoadersStarted.countDown();
                                                   await(releaseLoaders);
                                                   return "loaded";
                                               },
                                               () -> {
                                                   rejectionCount.incrementAndGet();
                                                   return "rejected";
                                               });
                }));
            }
            assertThat(tasksReady.await(5, TimeUnit.SECONDS), is(true));
            startTasks.countDown();
            assertThat(activeLoadersStarted.await(5, TimeUnit.SECONDS), is(true));
            awaitQueued(coordinator.remoteWorkLimiter(), maxQueued);
            awaitCount(rejectionCount, taskCount - maxConcurrent - maxQueued);

            assertThat(coordinator.remoteWorkLimiter().activeCount(), is(maxConcurrent));
            assertThat(coordinator.remoteWorkLimiter().queuedCount(), is(maxQueued));
            releaseLoaders.countDown();

            int loaded = 0;
            int rejected = 0;
            for (Future<String> result : results) {
                if ("loaded".equals(result.get(5, TimeUnit.SECONDS))) {
                    loaded++;
                } else {
                    rejected++;
                }
            }
            assertThat(loaded, is(maxConcurrent + maxQueued));
            assertThat(rejected, is(taskCount - maxConcurrent - maxQueued));
            assertThat(allTasksVirtual.get(), is(true));
            assertThat(coordinator.remoteWorkLimiter().activeCount(), is(0));
            assertThat(coordinator.remoteWorkLimiter().queuedCount(), is(0));
        } finally {
            releaseLoaders.countDown();
        }
    }

    private static OidcAuthorizationCodeConfig config(Duration retention,
                                                      int cacheCapacity,
                                                      int maxConcurrent,
                                                      int maxQueued) {
        return OidcAuthorizationCodeConfig.builder()
                .refreshResultRetention(retention)
                .refreshResultCacheCapacity(cacheCapacity)
                .refreshRemoteWork(OidcRemoteWorkConfig.builder()
                                           .maxConcurrent(maxConcurrent)
                                           .maxQueued(maxQueued)
                                           .admissionTimeout(Duration.ofSeconds(5))
                                           .buildPrototype())
                .buildPrototype();
    }

    private static String resolve(OidcRefreshCoordinator<String> coordinator,
                                  OidcLocalAuthenticationResult source,
                                  AtomicInteger loads) {
        return coordinator.resolve(source,
                                   _ -> true,
                                   () -> "result-" + loads.incrementAndGet(),
                                   () -> "rejected");
    }

    private static OidcLocalAuthenticationResult authentication(String accessToken,
                                                                String refreshToken,
                                                                Instant createdAt,
                                                                String browserSessionGeneration) {
        return OidcLocalAuthenticationResult.fromStoredValues(OidcLocalAuthenticationState.builder()
                                                                       .tenantId("default")
                                                                       .idToken(idToken)
                                                                       .accessToken(accessToken)
                                                                       .tokenType("Bearer")
                                                                       .refreshToken(refreshToken)
                                                                       .browserSessionGeneration(
                                                                               browserSessionGeneration)
                                                                       .scope("openid")
                                                                       .createdAt(createdAt)
                                                                       .expiresAt(createdAt.plusSeconds(3600))
                                                                       .accessTokenExpiresAt(createdAt)
                                                                       .buildPrototype());
    }

    private static void awaitQueued(OidcRemoteWorkLimiter limiter, int expected) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (limiter.queuedCount() != expected) {
            if (System.nanoTime() >= deadline) {
                throw new AssertionError("Timed out waiting for queued refresh follower");
            }
            Thread.onSpinWait();
        }
    }

    private static void awaitCount(AtomicInteger counter, int expected) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (counter.get() < expected) {
            if (System.nanoTime() >= deadline) {
                throw new AssertionError("Timed out waiting for rejected refresh operations: " + counter.get());
            }
            Thread.onSpinWait();
        }
    }

    private static void await(CountDownLatch latch) {
        try {
            if (!latch.await(5, TimeUnit.SECONDS)) {
                throw new AssertionError("Timed out waiting for test synchronization");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AssertionError("Interrupted during test synchronization", e);
        }
    }
}
