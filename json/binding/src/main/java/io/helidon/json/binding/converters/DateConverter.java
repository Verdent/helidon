package io.helidon.json.binding.converters;

import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Date;

import io.helidon.common.GenericType;
import io.helidon.common.Weight;
import io.helidon.common.Weighted;
import io.helidon.json.binding.JsonConverter;
import io.helidon.json.Generator;
import io.helidon.json.JsonException;
import io.helidon.json.JsonParser;
import io.helidon.service.registry.Service;

@Service.Singleton
@Weight(Weighted.DEFAULT_WEIGHT - 10)
class DateConverter implements JsonConverter<Date> {

    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ISO_DATE_TIME.withZone(ZoneId.of("UTC"));

    @Override
    public void serialize(Generator generator, Date instance, boolean writeNulls) {
        generator.write(FORMATTER.format(instance.toInstant()));
    }

    @Override
    public boolean isMapKeySerializer() {
        return true;
    }

    @Override
    public String serializeAsMapKey(Date instance) {
        return FORMATTER.format(instance.toInstant());
    }

    @Override
    public Date deserialize(JsonParser parser) {
        if (parser.currentByte() == '"') {
            return Date.from(ZonedDateTime.parse(parser.readString()).toInstant());
        }
        throw new JsonException("Only the string format of the Date is supported.");
    }

    @Override
    public GenericType<Date> type() {
        return GenericType.create(Date.class);
    }

}
