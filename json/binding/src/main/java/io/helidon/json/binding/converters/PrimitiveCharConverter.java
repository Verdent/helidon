package io.helidon.json.binding.converters;

import io.helidon.common.GenericType;
import io.helidon.common.Weight;
import io.helidon.common.Weighted;
import io.helidon.json.binding.JsonConverter;
import io.helidon.json.processor.Generator;
import io.helidon.json.processor.JsonException;
import io.helidon.json.processor.JsonParser;
import io.helidon.service.registry.Service;

@Service.Singleton
@Weight(Weighted.DEFAULT_WEIGHT - 10)
class PrimitiveCharConverter implements JsonConverter<Character> {

    private static final GenericType<Character> TYPE = GenericType.create(char.class);

    @Override
    public GenericType<Character> type() {
        return TYPE;
    }

    @Override
    public void serialize(Generator generator, Character instance, boolean writeNulls) {
        generator.write(instance);
    }

    @Override
    public Character deserialize(JsonParser parser) {
        return parser.readAsChar();
    }

    @Override
    public Character deserializeNull() {
        return 0;
    }
}
