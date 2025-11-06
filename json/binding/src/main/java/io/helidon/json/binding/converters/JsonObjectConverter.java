package io.helidon.json.binding.converters;

import io.helidon.common.GenericType;
import io.helidon.common.Weight;
import io.helidon.common.Weighted;
import io.helidon.json.binding.TypedJsonConverter;
import io.helidon.json.processor.Generator;
import io.helidon.json.processor.JsonObject;
import io.helidon.json.processor.JsonParser;
import io.helidon.service.registry.Service;

@Service.Singleton
@Weight(Weighted.DEFAULT_WEIGHT - 10)
class JsonObjectConverter implements TypedJsonConverter<JsonObject> {

    private static final GenericType<JsonObject> TYPE = GenericType.create(JsonObject.class);

    @Override
    public JsonObject deserialize(JsonParser parser) {
        return parser.readJsonObject();
    }

    @Override
    public void serialize(Generator generator, JsonObject instance, boolean writeNulls) {
        generator.writeValue(instance);
    }

    @Override
    public GenericType<JsonObject> type() {
        return TYPE;
    }
}
