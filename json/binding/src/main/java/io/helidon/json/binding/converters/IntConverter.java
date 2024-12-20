package io.helidon.json.binding.converters;

import io.helidon.common.Weight;
import io.helidon.common.Weighted;
import io.helidon.json.binding.JsonConverter;
import io.helidon.json.processor.Generator;
import io.helidon.json.processor.JsonParser;

//@Service.Singleton
//Weight -> Weighted.DE
@Weight(Weighted.DEFAULT_WEIGHT - 10)
public final class IntConverter implements JsonConverter<Integer> {

    public static final IntConverter INSTANCE = new IntConverter();

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
