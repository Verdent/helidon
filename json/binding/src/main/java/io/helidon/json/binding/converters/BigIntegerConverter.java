package io.helidon.json.binding.converters;

import java.math.BigInteger;

import io.helidon.common.GenericType;
import io.helidon.common.Weight;
import io.helidon.common.Weighted;
import io.helidon.json.binding.JsonConverter;
import io.helidon.json.Generator;
import io.helidon.json.JsonParser;
import io.helidon.service.registry.Service;

@Service.Singleton
@Weight(Weighted.DEFAULT_WEIGHT - 10)
class BigIntegerConverter implements JsonConverter<BigInteger> {

    private static final GenericType<BigInteger> TYPE = GenericType.create(BigInteger.class);

    @Override
    public BigInteger deserialize(JsonParser parser) {
        if (parser.currentByte() == '\"') {
            return new BigInteger(parser.readString());
        } else {
            char[] numberAsArray = parser.readNumberAsArray();
            return new BigInteger(new String(numberAsArray));
        }
    }

    @Override
    public void serialize(Generator generator, BigInteger instance, boolean writeNulls) {
        generator.write(instance.toString());
    }

    @Override
    public GenericType<BigInteger> type() {
        return TYPE;
    }
}
