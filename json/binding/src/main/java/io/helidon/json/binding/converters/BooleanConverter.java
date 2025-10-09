package io.helidon.json.binding.converters;

import io.helidon.common.GenericType;
import io.helidon.common.Weight;
import io.helidon.common.Weighted;
import io.helidon.json.binding.TypedJsonConverter;
import io.helidon.json.processor.Generator;
import io.helidon.json.processor.JsonException;
import io.helidon.json.processor.JsonParser;
import io.helidon.service.registry.Service;

@Service.Singleton
@Weight(Weighted.DEFAULT_WEIGHT - 10)
class BooleanConverter implements TypedJsonConverter<Boolean> {

    @Override
    public void toJson(Generator generator, Boolean instance, boolean writeNulls) {
        generator.writeValue(instance);
    }

    @Override
    public Boolean fromJsonValue(JsonParser parser) {
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
            parser.checkTrue();
            return true;
        case 'f':
            parser.checkFalse();
            return false;
        default:
            throw new JsonException("Expected Boolean value but got '" + (char) lastByte + "'");
        }
    }

    @Override
    public GenericType<Boolean> type() {
        return new GenericType<>() {};
    }
}
