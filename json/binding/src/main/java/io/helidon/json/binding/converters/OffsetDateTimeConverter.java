package io.helidon.json.binding.converters;

import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;

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
class OffsetDateTimeConverter implements JsonConverter<OffsetDateTime> {

    private static final GenericType<OffsetDateTime> TYPE = GenericType.create(OffsetDateTime.class);

    @Override
    public void serialize(Generator generator, OffsetDateTime instance, boolean writeNulls) {
        generator.write(instance.toString());
    }

    @Override
    public boolean isMapKeySerializer() {
        return true;
    }

    @Override
    public String serializeAsMapKey(OffsetDateTime instance) {
        return instance.toString();
    }

    @Override
    public OffsetDateTime deserialize(JsonParser parser) {
        if (parser.currentByte() == '"') {
            return OffsetDateTime.parse(parser.readString());
        }
        throw new JsonException("Only the string format of the OffsetDateTime supported.");
    }

    @Override
    public GenericType<OffsetDateTime> type() {
        return TYPE;
    }

}
