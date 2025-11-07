package io.helidon.json.binding.converters;

import java.time.Instant;

import io.helidon.common.Weight;
import io.helidon.common.Weighted;
import io.helidon.json.binding.JsonConverter;
import io.helidon.json.processor.Generator;
import io.helidon.json.processor.JsonException;
import io.helidon.json.processor.JsonParser;
import io.helidon.service.registry.Service;

@Service.Singleton
@Weight(Weighted.DEFAULT_WEIGHT - 10)
class InstantConverter implements JsonConverter<Instant> {

    @Override
    public Instant deserialize(JsonParser parser) {
        boolean isString = parser.lastByte() == '"';
        if (isString) {
            parser.readNextByte();
        }
        long value = parser.readAsLong();
        Instant instant = Instant.ofEpochMilli(value);
        if (isString) {
            byte nextByte = parser.readNextByte();
            if (parser.lastByte() != '"') {
                throw new JsonException("End of the string expected, but found " + (char) nextByte);
            }
        }
        return instant;
    }

    @Override
    public void serialize(Generator generator, Instant instance, boolean writeNulls) {
        generator.write(instance.toEpochMilli());
    }

}
