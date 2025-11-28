package io.helidon.json.binding.converters;

import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.TemporalAccessor;
import java.time.temporal.TemporalQueries;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.TimeZone;

import io.helidon.common.GenericType;
import io.helidon.common.Weight;
import io.helidon.common.Weighted;
import io.helidon.json.binding.JsonConverter;
import io.helidon.json.processor.Generator;
import io.helidon.json.processor.JsonException;
import io.helidon.json.processor.JsonParser;
import io.helidon.service.registry.Service;

import static java.time.ZoneOffset.UTC;

@Service.Singleton
@Weight(Weighted.DEFAULT_WEIGHT - 10)
class CalendarConverter implements JsonConverter<Calendar> {

    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ISO_DATE_TIME;
    private static final LocalTime ZERO_LOCAL_TIME = LocalTime.parse("00:00:00");

    @Override
    public void serialize(Generator generator, Calendar instance, boolean writeNulls) {
        generator.write(serializeAsMapKey(instance));
    }

    @Override
    public boolean isMapKeySerializer() {
        return true;
    }

    @Override
    public String serializeAsMapKey(Calendar instance) {
        DateTimeFormatter formatter = instance.isSet(Calendar.HOUR) || instance.isSet(Calendar.HOUR_OF_DAY)
                ? DateTimeFormatter.ISO_DATE_TIME
                : DateTimeFormatter.ISO_DATE;
        return formatter.withZone(instance.getTimeZone().toZoneId())
                .format(ZonedDateTime.ofInstant(Instant.ofEpochMilli(instance.getTimeInMillis()),
                                                instance.getTimeZone().toZoneId()));
    }

    @Override
    public Calendar deserialize(JsonParser parser) {
        if (parser.currentByte() == '"') {
            String value = parser.readString();
            DateTimeFormatter formatter = value.contains("T")
                    ? DateTimeFormatter.ISO_DATE_TIME
                    : DateTimeFormatter.ISO_DATE;
            final TemporalAccessor parsed = formatter.parse(value);
            LocalTime time = parsed.query(TemporalQueries.localTime());
            ZoneId zone = parsed.query(TemporalQueries.zone());
            if (zone == null) {
                zone = UTC;
            }
            if (time == null) {
                time = ZERO_LOCAL_TIME;
            }
            ZonedDateTime result = LocalDate.from(parsed).atTime(time).atZone(zone);
            return GregorianCalendar.from(result);
        }
        throw new JsonException("Only the string format of the Calendar is supported.");
    }

    @Override
    public GenericType<Calendar> type() {
        return GenericType.create(Calendar.class);
    }

}
