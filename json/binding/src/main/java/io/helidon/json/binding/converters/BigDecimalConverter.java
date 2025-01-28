package io.helidon.json.binding.converters;

import java.math.BigDecimal;

import io.helidon.common.GenericType;
import io.helidon.common.Weight;
import io.helidon.common.Weighted;
import io.helidon.json.binding.TypedJsonConverter;
import io.helidon.json.processor.Generator;
import io.helidon.json.processor.JsonParser;
import io.helidon.service.registry.Service;

@Service.Singleton
@Weight(Weighted.DEFAULT_WEIGHT - 10)
class BigDecimalConverter implements TypedJsonConverter<BigDecimal> {

    @Override
    public BigDecimal fromJson(JsonParser parser) {
        return new BigDecimal(parser.readString());
    }

    @Override
    public void toJson(Generator generator, BigDecimal instance) {
        generator.writeValue(instance.toString());
    }

    @Override
    public GenericType<BigDecimal> type() {
        return new GenericType<>() {};
    }
}
