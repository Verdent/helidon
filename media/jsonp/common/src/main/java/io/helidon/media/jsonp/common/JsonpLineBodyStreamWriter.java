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

import javax.json.JsonStructure;
import javax.json.JsonWriterFactory;

import io.helidon.common.GenericType;
import io.helidon.common.http.DataChunk;
import io.helidon.common.http.MediaType;
import io.helidon.common.reactive.Flow.Publisher;
import io.helidon.media.common.MessageBodyWriterContext;

/**
 * JSON-P line delimited stream writer.
 */
public final class JsonpLineBodyStreamWriter extends JsonpBodyStreamWriter {

    JsonpLineBodyStreamWriter(JsonWriterFactory factory) {
        super(factory, /* begin */ null, "\r\n", /* end */ null);
    }

    @Override
    public Publisher<DataChunk> write(Publisher<JsonStructure> publisher,
            GenericType<? extends JsonStructure> type,
            MessageBodyWriterContext context) {

         MediaType contentType = context.findAccepted(MediaType.JSON_PREDICATE,
                MediaType.APPLICATION_STREAM_JSON);
         context.contentType(contentType);
         return new JsonArrayStreamProcessor(publisher, context.charset());
    }
}