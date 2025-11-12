package io.helidon.json.processor;

import java.math.BigDecimal;
import java.util.List;

public final class JsonArray extends JsonValue {

    static final JsonArray EMPTY_ARRAY = JsonArray.create(List.of());

    private final List<? extends JsonValue> jsonValues;

    private JsonArray(List<? extends JsonValue> jsonValues) {
        this.jsonValues = jsonValues;
    }

    public static JsonArray create(List<JsonValue> jsonValues) {
        return new JsonArray(jsonValues);
    }

    public static JsonValue createStrings(List<String> values) {
        List<JsonString> jsonValues = values.stream()
                .map(JsonString::create)
                .toList();
        return new JsonArray(jsonValues);
    }

    public static JsonValue createNumbers(List<BigDecimal> values) {
        List<JsonNumber> jsonValues = values.stream()
                .map(JsonNumber::create)
                .toList();
        return new JsonArray(jsonValues);
    }

    public static JsonValue createBooleans(List<Boolean> values) {
        List<JsonBoolean> jsonValues = values.stream()
                .map(JsonBoolean::create)
                .toList();
        return new JsonArray(jsonValues);
    }

    public List<JsonValue> values() {
        return List.copyOf(jsonValues);
    }

    @Override
    public JsonValueType type() {
        return JsonValueType.ARRAY;
    }

    @Override
    public void toJson(Generator generator) {
        generator.writeArrayStart();
        for (JsonValue jsonValue : jsonValues) {
            jsonValue.toJson(generator);
        }
        generator.writeArrayEnd();
    }
}
