package io.helidon.json.binding.converters;

import io.helidon.common.GenericType;
import io.helidon.common.Weight;
import io.helidon.common.Weighted;
import io.helidon.json.binding.JsonConverter;
import io.helidon.json.Generator;
import io.helidon.json.JsonString;
import io.helidon.json.JsonParser;
import io.helidon.service.registry.Service;

@Service.Singleton
@Weight(Weighted.DEFAULT_WEIGHT - 10)
class JsonStringConverter implements JsonConverter<JsonString> {

    private static final GenericType<JsonString> TYPE = GenericType.create(JsonString.class);

    @Override
    public JsonString deserialize(JsonParser parser) {
        return parser.readJsonString();
    }

    @Override
    public void serialize(Generator generator, JsonString instance, boolean writeNulls) {
        generator.write(instance);
    }

    @Override
    public GenericType<JsonString> type() {
        return TYPE;
    }
}
