package io.helidon.json.processor;

public class CachedParser {

    private ReusableJsonParser parser = new ArrayJsonParser();

    ReusableJsonParser get() {
        if (parser == null) {
            return  new ArrayJsonParser();
        }
        ReusableJsonParser toReturn = parser;
        parser = null;
        return toReturn;
    }

    void set(ReusableJsonParser parser) {
        this.parser = parser;
    }
}
