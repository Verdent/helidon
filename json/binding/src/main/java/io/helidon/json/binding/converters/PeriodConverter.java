package io.helidon.json.binding.converters;

import java.time.Period;

import io.helidon.common.GenericType;
import io.helidon.common.Weight;
import io.helidon.common.Weighted;
import io.helidon.json.binding.JsonConverter;
import io.helidon.json.Generator;
import io.helidon.json.JsonException;
import io.helidon.json.JsonParser;
import io.helidon.service.registry.Service;

@Service.Singleton
@Weight(Weighted.DEFAULT_WEIGHT - 10)
class PeriodConverter implements JsonConverter<Period> {

    @Override
    public void serialize(Generator generator, Period instance, boolean writeNulls) {
        generator.write(instance.toString());
    }

    @Override
    public boolean isMapKeySerializer() {
        return true;
    }

    @Override
    public String serializeAsMapKey(Period instance) {
        return instance.toString();
    }

    @Override
    public Period deserialize(JsonParser parser) {
        if (parser.currentByte() == '"') {
            return Period.parse(parser.readString());
        }
        throw new JsonException("Only the string format of the Period supported.");
    }

    @Override
    public GenericType<Period> type() {
        return GenericType.create(Period.class);
    }

}
