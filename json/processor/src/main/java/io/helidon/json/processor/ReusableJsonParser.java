package io.helidon.json.processor;

public sealed interface ReusableJsonParser extends JsonParser permits JsonParserImpl{

    void reset(byte[] buffer);

}
