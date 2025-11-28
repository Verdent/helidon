package io.helidon.json.binding.converters;

import java.time.LocalDate;

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
class LocalDateConverter implements JsonConverter<LocalDate> {

    private static final GenericType<LocalDate> TYPE = GenericType.create(LocalDate.class);

    @Override
    public void serialize(Generator generator, LocalDate instance, boolean writeNulls) {
        generator.write(instance.toString());
    }

    @Override
    public boolean isMapKeySerializer() {
        return true;
    }

    @Override
    public String serializeAsMapKey(LocalDate instance) {
        return instance.toString();
    }

    @Override
    public LocalDate deserialize(JsonParser parser) {
        if (parser.currentByte() == '"') {
            return LocalDate.parse(parser.readString());
        }
        throw new JsonException("Only the string format of the LocalDate supported.");
    }

    @Override
    public GenericType<LocalDate> type() {
        return TYPE;
    }

}
