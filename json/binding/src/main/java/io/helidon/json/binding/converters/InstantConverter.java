package io.helidon.json.binding.converters;

import java.time.Instant;

import io.helidon.common.GenericType;
import io.helidon.common.Weight;
import io.helidon.common.Weighted;
import io.helidon.json.binding.JsonConverter;
import io.helidon.json.Generator;
import io.helidon.json.JsonParser;
import io.helidon.service.registry.Service;

@Service.Singleton
@Weight(Weighted.DEFAULT_WEIGHT - 10)
class InstantConverter implements JsonConverter<Instant> {

    @Override
    public void serialize(Generator generator, Instant instance, boolean writeNulls) {
        generator.write(instance.toString());
    }

    @Override
    public boolean isMapKeySerializer() {
        return true;
    }

    @Override
    public String serializeAsMapKey(Instant instance) {
        return instance.toString();
    }

    @Override
    public Instant deserialize(JsonParser parser) {
        if (parser.currentByte() == '"') {
            return Instant.parse(parser.readString());
        }
        long value = parser.readAsLong();
        return Instant.ofEpochMilli(value);
    }

    @Override
    public GenericType<Instant> type() {
        return GenericType.create(Instant.class);
    }

}
