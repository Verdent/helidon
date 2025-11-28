package io.helidon.json.binding.converters;

import java.time.ZonedDateTime;

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
class ZonedDateTimeConverter implements JsonConverter<ZonedDateTime> {

    private static final GenericType<ZonedDateTime> TYPE = GenericType.create(ZonedDateTime.class);

    @Override
    public void serialize(Generator generator, ZonedDateTime instance, boolean writeNulls) {
        generator.write(instance.toString());
    }

    @Override
    public boolean isMapKeySerializer() {
        return true;
    }

    @Override
    public String serializeAsMapKey(ZonedDateTime instance) {
        return instance.toString();
    }

    @Override
    public ZonedDateTime deserialize(JsonParser parser) {
        if (parser.currentByte() == '"') {
            return ZonedDateTime.parse(parser.readString());
        }
        throw new JsonException("Only the string format of the ZonedDateTime supported.");
    }

    @Override
    public GenericType<ZonedDateTime> type() {
        return TYPE;
    }

}
