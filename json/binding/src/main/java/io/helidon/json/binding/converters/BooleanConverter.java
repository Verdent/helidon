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
class BooleanConverter implements JsonConverter<Boolean> {

    @Override
    public void serialize(Generator generator, Boolean instance, boolean writeNulls) {
        generator.write(instance);
    }

    @Override
    public Boolean deserialize(JsonParser parser) {
        byte lastByte = parser.lastByte();
        switch (lastByte) {
        case '\"':
            lastByte = parser.readNextByte();
            Boolean toReturn;
            switch (lastByte) {
            case 't':
            case 'f':
                toReturn = parser.readAsBoolean();
                break;
            case 'n':
                parser.checkNull();
                toReturn = null;
                break;
            default:
                throw new JsonException("Expected Boolean value but got '" + (char) lastByte + "'");
            }
            if (parser.readNextByte() != '\"') {
                throw new JsonException("Expected end of the boolean value was '\"' but got '" + (char) lastByte + "'");
            }
            return toReturn;
        case 't':
        case 'f':
            return parser.readAsBoolean();
        default:
            throw new JsonException("Expected Boolean value but got '" + (char) lastByte + "'");
        }
    }

    @Override
    public GenericType<Boolean> type() {
        return new GenericType<>() {};
    }
}
