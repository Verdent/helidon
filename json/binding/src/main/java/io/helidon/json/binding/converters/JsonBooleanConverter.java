package io.helidon.json.binding.converters;

import io.helidon.common.GenericType;
import io.helidon.common.Weight;
import io.helidon.common.Weighted;
import io.helidon.json.binding.TypedJsonConverter;
import io.helidon.json.processor.Generator;
import io.helidon.json.processor.JsonBoolean;
import io.helidon.json.processor.JsonParser;
import io.helidon.json.processor.JsonBoolean;
import io.helidon.service.registry.Service;

@Service.Singleton
@Weight(Weighted.DEFAULT_WEIGHT - 10)
class JsonBooleanConverter implements TypedJsonConverter<JsonBoolean> {

    private static final GenericType<JsonBoolean> TYPE = GenericType.create(JsonBoolean.class);

    @Override
    public JsonBoolean deserialize(JsonParser parser) {
        return JsonBoolean.create(parser.readAsBoolean());
    }

    @Override
    public void serialize(Generator generator, JsonBoolean instance, boolean writeNulls) {
        generator.writeValue(instance);
    }

    @Override
    public GenericType<JsonBoolean> type() {
        return TYPE;
    }
}
