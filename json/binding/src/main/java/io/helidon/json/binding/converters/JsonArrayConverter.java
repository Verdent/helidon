package io.helidon.json.binding.converters;

import io.helidon.common.GenericType;
import io.helidon.common.Weight;
import io.helidon.common.Weighted;
import io.helidon.json.binding.TypedJsonConverter;
import io.helidon.json.processor.Generator;
import io.helidon.json.processor.JsonArray;
import io.helidon.json.processor.JsonParser;
import io.helidon.service.registry.Service;

@Service.Singleton
@Weight(Weighted.DEFAULT_WEIGHT - 10)
class JsonArrayConverter implements TypedJsonConverter<JsonArray> {

    private static final GenericType<JsonArray> TYPE = GenericType.create(JsonArray.class);

    @Override
    public JsonArray deserialize(JsonParser parser) {
        return parser.readJsonArray();
    }

    @Override
    public void serialize(Generator generator, JsonArray instance, boolean writeNulls) {
        generator.write(instance);
    }

    @Override
    public GenericType<JsonArray> type() {
        return TYPE;
    }
}
