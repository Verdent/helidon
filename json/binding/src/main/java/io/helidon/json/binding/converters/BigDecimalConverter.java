package io.helidon.json.binding.converters;

import java.math.BigDecimal;

import io.helidon.common.GenericType;
import io.helidon.common.Weight;
import io.helidon.common.Weighted;
import io.helidon.json.binding.JsonConverter;
import io.helidon.json.processor.Generator;
import io.helidon.json.processor.JsonParser;
import io.helidon.service.registry.Service;

@Service.Singleton
@Weight(Weighted.DEFAULT_WEIGHT - 10)
class BigDecimalConverter implements JsonConverter<BigDecimal> {

    private static final GenericType<BigDecimal> TYPE = GenericType.create(BigDecimal.class);

    @Override
    public BigDecimal deserialize(JsonParser parser) {
        if (parser.currentByte() == '\"') {
            return new BigDecimal(parser.readString());
        } else {
            return new BigDecimal(parser.readNumberAsArray());
        }
    }

    @Override
    public void serialize(Generator generator, BigDecimal instance, boolean writeNulls) {
        generator.write(instance.toString());
    }

    @Override
    public GenericType<BigDecimal> type() {
        return TYPE;
    }
}
