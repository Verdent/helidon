package io.helidon.json.binding.converters;

import java.util.UUID;

import io.helidon.common.GenericType;
import io.helidon.common.Weight;
import io.helidon.common.Weighted;
import io.helidon.json.binding.TypedJsonConverter;
import io.helidon.json.processor.Generator;
import io.helidon.json.processor.JsonParser;
import io.helidon.service.registry.Service;

@Service.Singleton
@Weight(Weighted.DEFAULT_WEIGHT - 10)
final class UuidConverter implements TypedJsonConverter<UUID> {

    private static final GenericType<UUID> TYPE = GenericType.create(UUID.class);

    @Override
    public GenericType<UUID> type() {
        return TYPE;
    }

    @Override
    public void toJson(Generator generator, UUID instance, boolean writeNulls) {
        generator.writeQuoted(instance.toString());
    }

    @Override
    public UUID fromJsonValue(JsonParser parser) {
        return UUID.fromString(parser.readString());
    }

}
