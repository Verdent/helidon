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
package io.helidon.media.jsonp.common;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.Objects;

import javax.json.JsonReader;
import javax.json.JsonReaderFactory;
import javax.json.JsonStructure;

import io.helidon.common.GenericType;
import io.helidon.common.http.DataChunk;
import io.helidon.common.reactive.Flow.Publisher;
import io.helidon.common.reactive.Mono;
import io.helidon.common.reactive.MonoMapper;
import io.helidon.media.common.ContentReaders;
import io.helidon.media.common.MessageBodyReader;
import io.helidon.media.common.MessageBodyReaderContext;

/**
 * Message body reader for {@link JsonStructure} sub-classes (JSON-P).
 */
public final class JsonpBodyReader implements MessageBodyReader<JsonStructure> {

    private final JsonReaderFactory jsonFactory;

    JsonpBodyReader(JsonReaderFactory jsonFactory) {
        Objects.requireNonNull(jsonFactory);
        this.jsonFactory = jsonFactory;
    }

    @Override
    public boolean accept(GenericType<?> type,
            MessageBodyReaderContext context) {

        return JsonStructure.class.isAssignableFrom(type.rawType());
    }

    @Override
    public <U extends JsonStructure> Mono<U> read(
            Publisher<DataChunk> publisher, GenericType<U> type,
            MessageBodyReaderContext context) {

        return ContentReaders.readBytes(publisher)
                .map(new BytesToJsonStructure<>(context.charset()));
    }

    private final class BytesToJsonStructure<T extends JsonStructure>
            extends MonoMapper<byte[], T> {

        private final Charset charset;

        BytesToJsonStructure(Charset charset) {
            this.charset = charset;
        }

        @Override
        @SuppressWarnings("unchecked")
        public T mapNext(byte[] bytes) {
            InputStream is = new ByteArrayInputStream(bytes);
            JsonReader reader = jsonFactory.createReader(is, charset);
            return (T) reader.read();
        }
    }
}