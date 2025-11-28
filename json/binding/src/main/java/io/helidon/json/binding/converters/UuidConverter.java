package io.helidon.json.binding.converters;

import java.util.UUID;

import io.helidon.common.GenericType;
import io.helidon.common.Weight;
import io.helidon.common.Weighted;
import io.helidon.json.binding.JsonConverter;
import io.helidon.json.Generator;
import io.helidon.json.JsonParser;
import io.helidon.service.registry.Service;

@Service.Singleton
@Weight(Weighted.DEFAULT_WEIGHT - 10)
class UuidConverter implements JsonConverter<UUID> {

    private static final GenericType<UUID> TYPE = GenericType.create(UUID.class);

    @Override
    public GenericType<UUID> type() {
        return TYPE;
    }

    @Override
    public void serialize(Generator generator, UUID instance, boolean writeNulls) {
        generator.write(instance.toString());
    }

    @Override
    public boolean isMapKeySerializer() {
        return true;
    }

    @Override
    public String serializeAsMapKey(UUID instance) {
        return instance.toString();
    }

    @Override
    public UUID deserialize(JsonParser parser) {
        return UUID.fromString(parser.readString());
    }

}
