/*
 * Copyright (c) 2019 Oracle and/or its affiliates. All rights reserved.
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
package io.helidon.common.reactive;

import java.util.Objects;

import io.helidon.common.reactive.Flow.Subscriber;

/**
 * Implementation of {@link Mono} that represents a non {@code null} value.
 *
 * @param <T> item type
 */
final class MonoJust<T> implements Mono<T> {

    private final T value;

    MonoJust(T value) {
        this.value = Objects.requireNonNull(value, "value cannot be null!");
    }

    @Override
    public void subscribe(Subscriber<? super T> subscriber) {
        subscriber.onSubscribe(new MonoSubscription<>(value, subscriber));
    }
}