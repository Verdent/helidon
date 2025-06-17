package io.helidon.json.binding;

import io.helidon.json.processor.JsonParser;
import io.helidon.json.processor.ReusableJsonParser;

class CachedParser {

    private ReusableJsonParser parser = (ReusableJsonParser) JsonParser.create();

    ReusableJsonParser get() {
        if (parser == null) {
            return  (ReusableJsonParser) JsonParser.create();
        }
        ReusableJsonParser toReturn = parser;
        parser = null;
        return toReturn;
    }

    void set(ReusableJsonParser parser) {
        this.parser = parser;
    }
}
