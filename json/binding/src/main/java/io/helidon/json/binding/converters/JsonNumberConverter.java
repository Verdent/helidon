package io.helidon.json.binding.converters;

import io.helidon.common.GenericType;
import io.helidon.common.Weight;
import io.helidon.common.Weighted;
import io.helidon.json.binding.JsonConverter;
import io.helidon.json.processor.Generator;
import io.helidon.json.processor.JsonNumber;
import io.helidon.json.processor.JsonParser;
import io.helidon.service.registry.Service;

@Service.Singleton
@Weight(Weighted.DEFAULT_WEIGHT - 10)
class JsonNumberConverter implements JsonConverter<JsonNumber> {

    private static final GenericType<JsonNumber> TYPE = GenericType.create(JsonNumber.class);

    @Override
    public JsonNumber deserialize(JsonParser parser) {
        return parser.readJsonNumber();
    }

    @Override
    public void serialize(Generator generator, JsonNumber instance, boolean writeNulls) {
        generator.write(instance);
    }

    @Override
    public GenericType<JsonNumber> type() {
        return TYPE;
    }
}
