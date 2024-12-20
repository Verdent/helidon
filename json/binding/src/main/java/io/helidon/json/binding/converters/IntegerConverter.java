package io.helidon.json.binding.converters;

import io.helidon.json.binding.JsonConverter;
import io.helidon.json.processor.Generator;
import io.helidon.json.processor.JsonParser;

public final class IntegerConverter implements JsonConverter<Integer> {

    public static final IntegerConverter INSTANCE = new IntegerConverter();

    @Override
    public void toJson(Generator generator, Integer instance) {
        if (instance == null) {
            generator.writeNull();
        } else {
            generator.writeValue(instance);
        }
    }

    @Override
    public Integer fromJson(JsonParser parser) {
        if (parser.checkNull()) {
            return null;
        }
        return parser.readInt();
    }

}
