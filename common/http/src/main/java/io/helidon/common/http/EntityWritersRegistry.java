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
package io.helidon.common.http;

import io.helidon.common.reactive.Flow.Publisher;
import java.util.function.Function;
import java.util.function.Predicate;

/**
 * Entity writers registry.
 */
public interface EntityWritersRegistry {

    @Deprecated
    <T> EntityWritersRegistry registerWriter(Class<T> type,
            Function<T, Publisher<DataChunk>> function);

    @Deprecated
    <T> EntityWritersRegistry registerWriter(Class<T> type,
            MediaType contentType,
            Function<? extends T, Publisher<DataChunk>> function);

    @Deprecated
    <T> EntityWritersRegistry registerWriter(Predicate<?> predicate,
            Function<T, Publisher<DataChunk>> function);

    @Deprecated
    <T> EntityWritersRegistry registerWriter(Predicate<?> predicate,
            MediaType contentType, Function<T, Publisher<DataChunk>> function);

   EntityWritersRegistry registerWriter(EntityWriter<?> writer);

   EntityWritersRegistry registerStreamWriter(EntityStreamWriter<?> writer); 
}
