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

import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.Supplier;

import io.helidon.common.LruCache;

/**
 * A bounded, process-local value cache with per-key single-flight loading.
 * <p>
 * This type deliberately combines two components with separate responsibilities:
 * <ul>
 *     <li>{@link LruCache} owns reusable values, thread-safe access ordering, and the strict capacity bound.</li>
 *     <li>{@link #inFlight} owns only loads that are currently running and coalesces concurrent misses for one key.</li>
 * </ul>
 * The separation matters because {@link LruCache#computeValue(Object, Supplier)} does not provide single-flight
 * semantics. Its contract permits multiple concurrent callers to execute their suppliers for the same key. That is
 * appropriate for inexpensive computations, but an OIDC cache miss performs a remote Token Endpoint request. Allowing
 * every concurrent caller to perform that request would amplify traffic, consume provider rate limits, and potentially
 * issue several independent tokens for one logical operation.
 * <p>
 * This cache is intentionally local to one {@code OidcProvider} instance. It provides no node affinity, persistence,
 * distributed coordination, or cross-process token sharing. Separate service instances may acquire their own tokens,
 * which keeps this optimization compatible with ordinary multi-node Helidon deployments.
 * <p>
 * The coordination path is safe for virtual-thread callers. No potentially blocking application or network operation
 * runs while holding an LRU lock or from inside a {@link ConcurrentMap} update callback. A waiting caller joins the
 * elected loader's future while holding no cache or map lock, so it can park without blocking unrelated keys. The map
 * operations themselves are deliberately limited to short {@code putIfAbsent} and conditional {@code remove} calls.
 *
 * @param <K> cache key type
 * @param <V> reusable cached value type
 * @param <R> result returned to the current callers
 */
final class OidcSingleFlightCache<K, V, R> {
    private final LruCache<K, V> values;

    /**
     * Active loads keyed by the same identity as cached values.
     * <p>
     * Entries exist only from leadership election until the load completes. They are always removed by the loading
     * caller, so this map is neither a second value cache nor an unbounded history of cache keys. A future carries the
     * complete resolution so concurrent callers observe the same success or protocol failure produced by the one
     * Token Endpoint request.
     * <p>
     * An {@link LruCache} is intentionally not used for this registry. Its API has no atomic {@code putIfAbsent} or
     * conditional remove operation, and evicting a still-running future at an LRU capacity boundary would break the
     * single-flight guarantee by allowing another load for the same key. The registry instead contains exactly one entry
     * per distinct load currently in progress and removes that entry in {@code finally}. If endpoint concurrency ever
     * needs a hard limit, that is an explicit admission-control policy; silently evicting active operations is not one.
     */
    private final ConcurrentMap<K, CompletableFuture<Resolution<V, R>>> inFlight = new ConcurrentHashMap<>();

    OidcSingleFlightCache() {
        this(LruCache.DEFAULT_CAPACITY);
    }

    OidcSingleFlightCache(int maxEntries) {
        if (maxEntries < 1) {
            throw new IllegalArgumentException("OIDC cache maximum entries must be positive");
        }
        this.values = LruCache.create(maxEntries);
    }

    /**
     * Returns a valid cached result or loads one resolution for all concurrent callers of the same key.
     * <p>
     * The cache-validity predicate belongs to the caller because token validity depends on request time and tenant clock
     * skew. An invalid value is never returned. It may remain in the bounded LRU until a successful load replaces it or
     * normal capacity eviction removes it. Avoiding a separate get-then-remove sequence is intentional: without a
     * compare-and-remove operation, that sequence could remove a newer value inserted between the two calls.
     * <p>
     * The loading supplier executes outside all {@link LruCache} locks. Consequently, a slow remote request for one key
     * cannot block cache access or Token Endpoint requests for unrelated keys. The loader must not recursively resolve
     * the same key through this cache, because it would wait for its own incomplete future.
     *
     * @param key key identifying both the reusable value and an active load
     * @param valid predicate that determines whether a cached value is reusable for this request
     * @param cachedResultFactory maps a reusable value to the result expected by the caller
     * @param loader performs the remote load and decides whether its result is reusable
     * @return a cached result or the result of the single load for this key
     */
    R resolve(K key,
              Predicate<V> valid,
              Function<V, R> cachedResultFactory,
              Supplier<Resolution<V, R>> loader) {
        Objects.requireNonNull(key);
        Objects.requireNonNull(valid);
        Objects.requireNonNull(cachedResultFactory);
        Objects.requireNonNull(loader);

        Optional<V> cached = cachedValue(key, valid);
        if (cached.isPresent()) {
            return Objects.requireNonNull(cachedResultFactory.apply(cached.orElseThrow()));
        }

        // Do not use computeIfAbsent with the remote loader: map callbacks may execute under internal coordination.
        // putIfAbsent limits map work to leader election and keeps all potentially blocking work outside the map.
        CompletableFuture<Resolution<V, R>> loading = new CompletableFuture<>();
        CompletableFuture<Resolution<V, R>> existing = inFlight.putIfAbsent(key, loading);
        if (existing != null) {
            return existing.join().result();
        }

        try {
            // A value may have been cached after the first lookup but before this caller became the elected loader.
            cached = cachedValue(key, valid);
            if (cached.isPresent()) {
                R result = Objects.requireNonNull(cachedResultFactory.apply(cached.orElseThrow()));
                loading.complete(Resolution.doNotCache(result));
                return result;
            }

            Resolution<V, R> resolution = Objects.requireNonNull(loader.get());
            resolution.cacheValue().ifPresent(value -> values.put(key, value));
            loading.complete(resolution);
            return resolution.result();
        } catch (RuntimeException | Error e) {
            loading.completeExceptionally(e);
            throw e;
        } finally {
            // Conditional removal cannot delete a later load that reused the same key after this future completed.
            inFlight.remove(key, loading);
        }
    }

    int size() {
        return values.size();
    }

    private Optional<V> cachedValue(K key, Predicate<V> valid) {
        return values.get(key).filter(valid);
    }

    /**
     * Separates the result returned to current callers from the optional value retained for later requests.
     * <p>
     * OAuth error results and successful responses without a reusable lifetime must be delivered consistently to all
     * callers waiting for the current load, but they must not become negative or permanent cache entries. Modeling the
     * two decisions independently prevents the single-flight mechanism from accidentally changing cache policy.
     *
     * @param cacheValue value to retain after this load, or empty when this result must not be retained
     * @param result result returned to the loading caller and all callers waiting on its future
     * @param <V> reusable cached value type
     * @param <R> current-call result type
     */
    record Resolution<V, R>(Optional<V> cacheValue, R result) {
        Resolution {
            cacheValue = Objects.requireNonNull(cacheValue);
            result = Objects.requireNonNull(result);
        }

        static <V, R> Resolution<V, R> cache(V value, R result) {
            return new Resolution<>(Optional.of(value), result);
        }

        static <V, R> Resolution<V, R> doNotCache(R result) {
            return new Resolution<>(Optional.empty(), result);
        }
    }
}
