package io.helidon.json.binding.converters;

import io.helidon.json.binding.JsonConverter;
import io.helidon.json.processor.Generator;
import io.helidon.json.processor.JsonParser;

public final class StringConverter implements JsonConverter<String> {

    public static final StringConverter INSTANCE = new StringConverter();

    @Override
    public void toJson(Generator generator, String instance) {
        if (instance == null) {
            generator.writeNull();
        } else {
            generator.writeQuoted(instance);
        }
    }

    @Override
    public String fromJson(JsonParser parser) {
        return parser.readString();
    }
}
