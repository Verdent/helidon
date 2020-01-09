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
package io.helidon.webclient;

import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

/**
 * TODO javadoc.
 */ // graal vm workaround - until called, not referencing anything

    //EDIT: pouzit to co je v io.helidon.common -> LazyValue
final class LazyValue<T> {
    private final AtomicReference<T> value = new AtomicReference<>();
    private volatile Supplier<T> supplier;

    private LazyValue(Supplier<T> supplier) {
        this.supplier = supplier;
    }

    T get() {
        return value.updateAndGet(t -> (null == t) ? supplier.get() : t);
    }

    void set(Supplier<T> supplier) {
        this.supplier = supplier;
        this.value.set(null);
    }

    static <T> LazyValue<T> create() {
        Supplier<T> sup = () -> {
            throw new IllegalStateException("Value supplier not yet set");
        };
        return new LazyValue<>(sup);
    }

    static <T> LazyValue<T> create(Supplier<T> supplier) {
        return new LazyValue<>(supplier);
    }
}
