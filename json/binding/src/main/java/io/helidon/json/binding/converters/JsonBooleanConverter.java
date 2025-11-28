package io.helidon.json.binding.converters;

import io.helidon.common.GenericType;
import io.helidon.common.Weight;
import io.helidon.common.Weighted;
import io.helidon.json.binding.JsonConverter;
import io.helidon.json.Generator;
import io.helidon.json.JsonBoolean;
import io.helidon.json.JsonParser;
import io.helidon.service.registry.Service;

@Service.Singleton
@Weight(Weighted.DEFAULT_WEIGHT - 10)
class JsonBooleanConverter implements JsonConverter<JsonBoolean> {

    private static final GenericType<JsonBoolean> TYPE = GenericType.create(JsonBoolean.class);

    @Override
    public JsonBoolean deserialize(JsonParser parser) {
        return JsonBoolean.create(parser.readAsBoolean());
    }

    @Override
    public void serialize(Generator generator, JsonBoolean instance, boolean writeNulls) {
        generator.write(instance);
    }

    @Override
    public GenericType<JsonBoolean> type() {
        return TYPE;
    }
}
