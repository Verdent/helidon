package io.helidon.json.binding.converters;

import java.time.LocalDateTime;

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
class LocalDateTimeConverter implements JsonConverter<LocalDateTime> {

    private static final GenericType<LocalDateTime> TYPE = GenericType.create(LocalDateTime.class);

    @Override
    public void serialize(Generator generator, LocalDateTime instance, boolean writeNulls) {
        generator.write(instance.toString());
    }

    @Override
    public boolean isMapKeySerializer() {
        return true;
    }

    @Override
    public String serializeAsMapKey(LocalDateTime instance) {
        return instance.toString();
    }

    @Override
    public LocalDateTime deserialize(JsonParser parser) {
        if (parser.currentByte() == '"') {
            return LocalDateTime.parse(parser.readString());
        }
        throw new JsonException("Only the string format of the LocalDateTime supported.");
    }

    @Override
    public GenericType<LocalDateTime> type() {
        return TYPE;
    }

}
