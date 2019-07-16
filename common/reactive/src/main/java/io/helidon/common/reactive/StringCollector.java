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

/**
 * {@link Collector} implementation that concatenates items
 * {@link Object#toString()} in a {@link String}.
 *
 * @param <T> collected item type
 */
final class StringCollector<T extends Object> implements Collector<String, T> {

    private final StringBuilder sb;

    StringCollector() {
        this.sb = new StringBuilder();
    }

    @Override
    public void collect(T item) {
        sb.append(item.toString());
    }

    @Override
    public String value() {
        return sb.toString();
    }
}
