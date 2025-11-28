package io.helidon.json.binding;

import io.helidon.json.JsonParser;
import io.helidon.json.ReusableJsonParser;

class CachedParser {

    private ReusableJsonParser parser = (ReusableJsonParser) JsonParser.empty();

    ReusableJsonParser get() {
        if (parser == null) {
            return  (ReusableJsonParser) JsonParser.empty();
        }
        ReusableJsonParser toReturn = parser;
        parser = null;
        return toReturn;
    }

    void set(ReusableJsonParser parser) {
        this.parser = parser;
    }
}
