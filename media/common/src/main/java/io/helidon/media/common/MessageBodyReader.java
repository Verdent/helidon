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
package io.helidon.media.common;

import io.helidon.common.GenericType;
import io.helidon.common.http.DataChunk;
import io.helidon.common.reactive.Flow.Publisher;
import io.helidon.common.reactive.Mono;

/**
 * Conversion operator that can convert HTTP payload into an object.
 *
 * @param <T> type or base type supported by the operator
 */
public interface MessageBodyReader<T>
        extends MessageBodyOperator<MessageBodyReaderContext> {

    /**
     * Convert a HTTP payload into a {@link Mono} of the given type.
     *
     * @param <U> requested type
     * @param publisher HTTP payload
     * @param type requested type representation
     * @param context reader context
     * @return single item publisher
     */
    <U extends T> Mono<U> read(Publisher<DataChunk> publisher,
            GenericType<U> type, MessageBodyReaderContext context);
}