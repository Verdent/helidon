package io.helidon.media.jsonp.common;

import javax.json.JsonWriterFactory;

/**
 * JSON-P array stream writer.
 */
public final class JsonpArrayStreamWriter extends JsonpStreamWriter {

    public JsonpArrayStreamWriter(JsonWriterFactory writerFactory) {
        super(writerFactory, "[", ",", "]");
    }
}
