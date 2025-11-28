package io.helidon.json.binding.converters;

import java.time.LocalTime;

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
class LocalTimeConverter implements JsonConverter<LocalTime> {

    private static final GenericType<LocalTime> TYPE = GenericType.create(LocalTime.class);

    @Override
    public void serialize(Generator generator, LocalTime instance, boolean writeNulls) {
        generator.write(instance.toString());
    }

    @Override
    public boolean isMapKeySerializer() {
        return true;
    }

    @Override
    public String serializeAsMapKey(LocalTime instance) {
        return instance.toString();
    }

    @Override
    public LocalTime deserialize(JsonParser parser) {
        if (parser.currentByte() == '"') {
            return LocalTime.parse(parser.readString());
        }
        throw new JsonException("Only the string format of the LocalTime supported.");
    }

    @Override
    public GenericType<LocalTime> type() {
        return TYPE;
    }

}
