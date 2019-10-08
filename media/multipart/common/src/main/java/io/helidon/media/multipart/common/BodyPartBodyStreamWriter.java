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
package io.helidon.media.multipart.common;

import io.helidon.common.GenericType;
import io.helidon.common.http.DataChunk;
import io.helidon.common.http.MediaType;
import io.helidon.common.reactive.Flow.Publisher;
import io.helidon.media.common.MessageBodyStreamWriter;
import io.helidon.media.common.MessageBodyWriterContext;

/**
 * {@link WriteableBodyPart} stream writer.
 */
public final class BodyPartBodyStreamWriter implements MessageBodyStreamWriter<WriteableBodyPart> {

    /**
     * Singleton instance.
     */
    private static final BodyPartBodyStreamWriter INSTANCE = new BodyPartBodyStreamWriter(MultiPartBodyWriter.DEFAULT_BOUNDARY);

    private final String boundary;

    /**
     * Private to enforce the use of {@link #create(java.lang.String).
     */
    private BodyPartBodyStreamWriter(String boundary) {
        this.boundary = boundary;
    }

    @Override
    public boolean accept(GenericType<?> type, MessageBodyWriterContext context) {
        return WriteableBodyPart.class.isAssignableFrom(type.rawType());
    }

    @Override
    public Publisher<DataChunk> write(Publisher<WriteableBodyPart> content, GenericType<? extends WriteableBodyPart> type,
            MessageBodyWriterContext context) {

        context.contentType(MediaType.MULTIPART_FORM_DATA);
        MultiPartEncoder encoder = MultiPartEncoder.create(boundary, context);
        content.subscribe(encoder);
        return encoder;
    }

    /**
     * Create a new instance of {@link BodyPartBodyStreamWriter} with the default
     * boundary delimiter ({@link MultiPartBodyWriter#DEFAULT_BOUNDARY}.
     * @return BodyPartStreamWriter
     */
    public static BodyPartBodyStreamWriter get() {
        return INSTANCE;
    }

    /**
     * Create a new instance of {@link BodyPartBodyStreamWriter} with the specified
     * boundary delimiter.
     * @param boundary boundary string
     * @return BodyPartStreamWriter
     */
    public static BodyPartBodyStreamWriter create(String boundary) {
        return new BodyPartBodyStreamWriter(boundary);
    }
}