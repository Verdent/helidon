package io.helidon.json.binding.converters;

import io.helidon.common.GenericType;
import io.helidon.common.Weight;
import io.helidon.common.Weighted;
import io.helidon.json.binding.JsonConverter;
import io.helidon.json.binding.TypedJsonConverter;
import io.helidon.json.processor.Generator;
import io.helidon.json.processor.JsonParser;
import io.helidon.service.registry.Service;

@Service.Singleton
@Weight(Weighted.DEFAULT_WEIGHT - 10)
final class IntConverter implements TypedJsonConverter<Integer> {

    private static final GenericType<Integer> TYPE = GenericType.create(int.class);

    @Override
    public GenericType<Integer> type() {
        return TYPE;
    }

    @Override
    public void toJson(Generator generator, Integer instance) {
        generator.writeValue(instance);
    }

    @Override
    public Integer fromJson(JsonParser parser) {
        if (parser.checkNull()) {
            return 0;
        }
        return parser.readInt();
    }

}
