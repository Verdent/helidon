package io.helidon.json.binding.converters;

import io.helidon.common.GenericType;
import io.helidon.common.Weight;
import io.helidon.common.Weighted;
import io.helidon.json.binding.JsonConverter;
import io.helidon.json.Generator;
import io.helidon.json.JsonParser;
import io.helidon.json.JsonValue;
import io.helidon.service.registry.Service;

@Service.Singleton
@Weight(Weighted.DEFAULT_WEIGHT - 10)
class JsonValueConverter implements JsonConverter<JsonValue> {

    private static final GenericType<JsonValue> TYPE = GenericType.create(JsonValue.class);

    @Override
    public JsonValue deserialize(JsonParser parser) {
        return parser.readJsonValue();
    }

    @Override
    public void serialize(Generator generator, JsonValue instance, boolean writeNulls) {
        generator.write(instance);
    }

    @Override
    public GenericType<JsonValue> type() {
        return TYPE;
    }
}
