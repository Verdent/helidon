package io.helidon.json.binding.converters;

import io.helidon.common.GenericType;
import io.helidon.common.Weight;
import io.helidon.common.Weighted;
import io.helidon.json.binding.TypedJsonConverter;
import io.helidon.json.processor.Generator;
import io.helidon.json.processor.JsonException;
import io.helidon.json.processor.JsonNull;
import io.helidon.json.processor.JsonParser;
import io.helidon.json.processor.JsonNull;
import io.helidon.service.registry.Service;

@Service.Singleton
@Weight(Weighted.DEFAULT_WEIGHT - 10)
class JsonNullConverter implements TypedJsonConverter<JsonNull> {

    private static final GenericType<JsonNull> TYPE = GenericType.create(JsonNull.class);

    @Override
    public JsonNull deserialize(JsonParser parser) {
        if (parser.checkNull()) {
            return JsonNull.instance();
        }
        throw new JsonException("Expected null value, but got: " + (char) parser.lastByte());
    }

    @Override
    public void serialize(Generator generator, JsonNull instance, boolean writeNulls) {
        generator.writeValue(instance);
    }

    @Override
    public GenericType<JsonNull> type() {
        return TYPE;
    }
}
