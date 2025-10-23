package io.helidon.json.processor;

public class CachedParser {

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
