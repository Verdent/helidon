package io.helidon.json.binding.converters;

import io.helidon.common.GenericType;
import io.helidon.common.Weight;
import io.helidon.common.Weighted;
import io.helidon.json.binding.JsonConverter;
import io.helidon.json.binding.TypedJsonConverter;
import io.helidon.json.processor.Generator;
import io.helidon.json.processor.JsonParser;
import io.helidon.service.registry.Service;

@Service.Singleton
@Weight(Weighted.DEFAULT_WEIGHT - 10)
class StringConverter implements TypedJsonConverter<String> {

    private static final GenericType<String> TYPE = GenericType.create(String.class);

    @Override
    public GenericType<String> type() {
        return TYPE;
    }

    @Override
    public void serialize(Generator generator, String instance, boolean writeNulls) {
        generator.write(instance);
    }

    @Override
    public String deserialize(JsonParser parser) {
        return parser.readString();
    }

    @Override
    public boolean isMapKeySerializer() {
        return true;
    }

    @Override
    public String serializeAsMapKey(String instance) {
        return instance;
    }
}
