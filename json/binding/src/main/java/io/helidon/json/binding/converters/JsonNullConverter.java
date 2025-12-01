package io.helidon.json.binding.converters;

import io.helidon.common.GenericType;
import io.helidon.common.Weight;
import io.helidon.common.Weighted;
import io.helidon.json.binding.JsonConverter;
import io.helidon.json.Generator;
import io.helidon.json.JsonException;
import io.helidon.json.JsonNull;
import io.helidon.json.JsonParser;
import io.helidon.service.registry.Service;

@Service.Singleton
@Weight(Weighted.DEFAULT_WEIGHT - 10)
class JsonNullConverter implements JsonConverter<JsonNull> {

    private static final GenericType<JsonNull> TYPE = GenericType.create(JsonNull.class);

    @Override
    public JsonNull deserialize(JsonParser parser) {
        throw new JsonException("Expected null value, but got: " + (char) parser.currentByte());
    }

    @Override
    public JsonNull deserializeNull() {
        return JsonNull.instance();
    }

    @Override
    public void serialize(Generator generator, JsonNull instance, boolean writeNulls) {
        generator.write(instance);
    }

    @Override
    public GenericType<JsonNull> type() {
        return TYPE;
    }
}
