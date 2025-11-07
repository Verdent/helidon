package io.helidon.json.binding.converters;

import io.helidon.common.GenericType;
import io.helidon.common.Weight;
import io.helidon.common.Weighted;
import io.helidon.json.binding.TypedJsonConverter;
import io.helidon.json.processor.Generator;
import io.helidon.json.processor.JsonParser;
import io.helidon.json.processor.JsonValue;
import io.helidon.json.processor.JsonValue;
import io.helidon.service.registry.Service;

@Service.Singleton
@Weight(Weighted.DEFAULT_WEIGHT - 10)
class JsonValueConverter implements TypedJsonConverter<JsonValue> {

    private static final GenericType<JsonValue> TYPE = GenericType.create(JsonValue.class);

    @Override
    public JsonValue deserialize(JsonParser parser) {
        return parser.readJsonValue();
    }

    @Override
    public void serialize(Generator generator, JsonValue instance, boolean writeNulls) {
        generator.writeValue(instance);
    }

    @Override
    public GenericType<JsonValue> type() {
        return TYPE;
    }
}
