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
 * Message body reader for {@link String}.
 */
public final class StringBodyReader implements MessageBodyReader<String> {

    /**
     * Singleton instance.
     */
    private static final StringBodyReader INSTANCE = new StringBodyReader();

    /**
     * Private to enforce the use of {@link #get()}.
     */
    private StringBodyReader() {
    }

    @Override
    public boolean accept(GenericType<?> type,
            MessageBodyReaderContext context) {

        return String.class.isAssignableFrom(type.rawType());
    }

    @Override
    @SuppressWarnings("unchecked")
    public <U extends String> Mono<U> read(Publisher<DataChunk> publisher,
            GenericType<U> type, MessageBodyReaderContext context) {

        return (Mono<U>) ContentReaders.readString(publisher,
                context.charset());
    }

    /**
     * Create a new {@link StringBodyReader} instance.
     * @return StringBodyReader
     */
    public static StringBodyReader get() {
        return INSTANCE;
    }
}