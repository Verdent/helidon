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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OidcSingleFlightCacheTest {
    @Test
    void cachedValueIsReusedUntilInvalid() {
        OidcSingleFlightCache<String, CachedValue, String> cache = new OidcSingleFlightCache<>(10);
        AtomicInteger generation = new AtomicInteger(1);
        AtomicInteger loads = new AtomicInteger();

        String first = resolve(cache, "key", generation, loads);
        String cached = resolve(cache, "key", generation, loads);
        generation.incrementAndGet();
        String refreshed = resolve(cache, "key", generation, loads);

        assertThat(first, is("key-1"));
        assertThat(cached, is("key-1"));
        assertThat(refreshed, is("key-2"));
        assertThat(loads.get(), is(2));
        assertThat(cache.size(), is(1));
    }

    @Test
    void uncachedResultIsNotRetained() {
        OidcSingleFlightCache<String, CachedValue, String> cache = new OidcSingleFlightCache<>(10);
        AtomicInteger loads = new AtomicInteger();

        String first = cache.resolve("key",
                                     ignored -> true,
                                     CachedValue::result,
                                     () -> OidcSingleFlightCache.Resolution.doNotCache(
                                             "failure-" + loads.incrementAndGet()));
        String second = cache.resolve("key",
                                      ignored -> true,
                                      CachedValue::result,
                                      () -> OidcSingleFlightCache.Resolution.doNotCache(
                                              "failure-" + loads.incrementAndGet()));

        assertThat(first, is("failure-1"));
        assertThat(second, is("failure-2"));
        assertThat(loads.get(), is(2));
        assertThat(cache.size(), is(0));
    }

    @Test
    void leastRecentlyUsedEntryIsEvictedAtCapacity() {
        OidcSingleFlightCache<String, CachedValue, String> cache = new OidcSingleFlightCache<>(2);
        AtomicInteger generation = new AtomicInteger(1);
        Map<String, AtomicInteger> loads = new ConcurrentHashMap<>();

        resolve(cache, "first", generation, loads);
        resolve(cache, "second", generation, loads);
        resolve(cache, "first", generation, loads);
        resolve(cache, "third", generation, loads);
        resolve(cache, "second", generation, loads);

        assertThat(loads.get("first").get(), is(1));
        assertThat(loads.get("second").get(), is(2));
        assertThat(loads.get("third").get(), is(1));
        assertThat(cache.size(), is(2));
    }

    @Test
    void concurrentSameKeyLoadIsSingleFlight() throws Exception {
        int taskCount = 32;
        OidcSingleFlightCache<String, CachedValue, String> cache = new OidcSingleFlightCache<>(10);
        AtomicInteger loads = new AtomicInteger();
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch loaderStarted = new CountDownLatch(1);
        CountDownLatch releaseLoader = new CountDownLatch(1);

        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<String>> futures = new ArrayList<>(taskCount);
            for (int i = 0; i < taskCount; i++) {
                futures.add(executor.submit(() -> {
                    assertTrue(start.await(5, TimeUnit.SECONDS));
                    return cache.resolve("key",
                                         ignored -> true,
                                         CachedValue::result,
                                         () -> {
                                             loads.incrementAndGet();
                                             loaderStarted.countDown();
                                             await(releaseLoader);
                                             CachedValue value = new CachedValue("loaded", 1);
                                             return OidcSingleFlightCache.Resolution.cache(value, value.result());
                                         });
                }));
            }

            start.countDown();
            assertTrue(loaderStarted.await(5, TimeUnit.SECONDS));
            releaseLoader.countDown();
            for (Future<String> future : futures) {
                assertThat(future.get(), is("loaded"));
            }
        }

        assertThat(loads.get(), is(1));
        assertThat(cache.size(), is(1));
    }

    @Test
    void differentKeysLoadConcurrentlyOnVirtualThreads() throws Exception {
        OidcSingleFlightCache<String, CachedValue, String> cache = new OidcSingleFlightCache<>(10);
        CountDownLatch bothLoadersStarted = new CountDownLatch(2);
        CountDownLatch releaseLoaders = new CountDownLatch(1);

        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            Future<String> first = executor.submit(() -> resolveBlocked(cache,
                                                                        "first",
                                                                        bothLoadersStarted,
                                                                        releaseLoaders));
            Future<String> second = executor.submit(() -> resolveBlocked(cache,
                                                                         "second",
                                                                         bothLoadersStarted,
                                                                         releaseLoaders));
            try {
                assertTrue(bothLoadersStarted.await(5, TimeUnit.SECONDS));
            } finally {
                releaseLoaders.countDown();
            }

            assertThat(first.get(), is("first"));
            assertThat(second.get(), is("second"));
        }
    }

    private static String resolve(OidcSingleFlightCache<String, CachedValue, String> cache,
                                  String key,
                                  AtomicInteger generation,
                                  AtomicInteger loads) {
        return cache.resolve(key,
                             value -> value.generation() == generation.get(),
                             CachedValue::result,
                             () -> {
                                 loads.incrementAndGet();
                                 CachedValue value = new CachedValue(key + "-" + generation.get(), generation.get());
                                 return OidcSingleFlightCache.Resolution.cache(value, value.result());
                             });
    }

    private static String resolveBlocked(OidcSingleFlightCache<String, CachedValue, String> cache,
                                         String key,
                                         CountDownLatch bothLoadersStarted,
                                         CountDownLatch releaseLoaders) {
        return cache.resolve(key,
                             ignored -> true,
                             CachedValue::result,
                             () -> {
                                 bothLoadersStarted.countDown();
                                 await(releaseLoaders);
                                 CachedValue value = new CachedValue(key, 1);
                                 return OidcSingleFlightCache.Resolution.cache(value, value.result());
                             });
    }

    private static String resolve(OidcSingleFlightCache<String, CachedValue, String> cache,
                                  String key,
                                  AtomicInteger generation,
                                  Map<String, AtomicInteger> loads) {
        return cache.resolve(key,
                             value -> value.generation() == generation.get(),
                             CachedValue::result,
                             () -> {
                                 int load = loads.computeIfAbsent(key, ignored -> new AtomicInteger()).incrementAndGet();
                                 CachedValue value = new CachedValue(key + "-" + load, generation.get());
                                 return OidcSingleFlightCache.Resolution.cache(value, value.result());
                             });
    }

    private static void await(CountDownLatch latch) {
        try {
            assertTrue(latch.await(5, TimeUnit.SECONDS));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while waiting for test latch", e);
        }
    }

    private record CachedValue(String result, int generation) {
    }
}
