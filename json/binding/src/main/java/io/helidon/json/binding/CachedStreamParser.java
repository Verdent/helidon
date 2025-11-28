package io.helidon.json.binding;

import io.helidon.json.JsonParser;
import io.helidon.json.ReusableJsonParser;

class CachedStreamParser {

    private ReusableJsonParser parser = (ReusableJsonParser) JsonParser.emptyStream();

    ReusableJsonParser get() {
        if (parser == null) {
            return  (ReusableJsonParser) JsonParser.emptyStream();
        }
        ReusableJsonParser toReturn = parser;
        parser = null;
        return toReturn;
    }

    void set(ReusableJsonParser parser) {
        this.parser = parser;
    }
}
