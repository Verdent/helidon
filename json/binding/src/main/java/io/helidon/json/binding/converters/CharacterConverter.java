package io.helidon.json.binding.converters;

import io.helidon.common.GenericType;
import io.helidon.common.Weight;
import io.helidon.common.Weighted;
import io.helidon.json.binding.JsonConverter;
import io.helidon.json.Generator;
import io.helidon.json.JsonParser;
import io.helidon.service.registry.Service;

@Service.Singleton
@Weight(Weighted.DEFAULT_WEIGHT - 10)
class CharacterConverter implements JsonConverter<Character> {

    private static final GenericType<Character> TYPE = GenericType.create(Character.class);

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
