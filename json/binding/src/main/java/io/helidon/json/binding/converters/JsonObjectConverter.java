package io.helidon.json.binding.converters;

import io.helidon.common.GenericType;
import io.helidon.common.Weight;
import io.helidon.common.Weighted;
import io.helidon.json.binding.JsonConverter;
import io.helidon.json.Generator;
import io.helidon.json.JsonObject;
import io.helidon.json.JsonParser;
import io.helidon.service.registry.Service;

@Service.Singleton
@Weight(Weighted.DEFAULT_WEIGHT - 10)
class JsonObjectConverter implements JsonConverter<JsonObject> {

    private static final GenericType<JsonObject> TYPE = GenericType.create(JsonObject.class);

    @Override
    public JsonObject deserialize(JsonParser parser) {
        return parser.readJsonObject();
    }

    @Override
    public void serialize(Generator generator, JsonObject instance, boolean writeNulls) {
        generator.write(instance);
    }

    @Override
    public GenericType<JsonObject> type() {
        return TYPE;
    }
}
