package io.helidon.json.binding.factories;

import java.lang.reflect.Type;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import java.util.Optional;

import io.helidon.common.Weight;
import io.helidon.common.Weighted;
import io.helidon.json.binding.BindingFactoryConverter;
import io.helidon.json.binding.BindingFactoryDeserializer;
import io.helidon.json.binding.BindingFactorySerializer;
import io.helidon.json.binding.Formatter;
import io.helidon.json.binding.JsonBindingConfigurer;
import io.helidon.json.binding.JsonContext;
import io.helidon.json.binding.TypedJsonBindingFactory;
import io.helidon.json.processor.Generator;
import io.helidon.json.processor.JsonParser;
import io.helidon.service.registry.Service;

import static java.time.ZoneOffset.UTC;

@Service.Singleton
@Weight(Weighted.DEFAULT_WEIGHT - 10)
class InstantBindingFactory implements TypedJsonBindingFactory<Instant> {

    @Override
    public Class<?> type() {
        return Instant.class;
    }

    @Override
    public BindingFactoryDeserializer<Instant> createDeserializer(Type type) {
        return new InstantConverter();
    }

    @Override
    public BindingFactorySerializer<Instant> createSerializer(Type type) {
        return new InstantConverter();
    }

    private static final class InstantConverter implements BindingFactoryConverter<Instant> {

        private static final DateTimeFormatter DEFAULT_FORMATTER = DateTimeFormatter.ISO_INSTANT.withZone(UTC);

        private DateTimeFormatter formatter;
        private boolean useFormatter;

        @Override
        public Instant fromJsonValue(JsonParser parser) {
            if (parser.lastByte() == '"') {
                String value = parser.readString();
                return Instant.from(formatter.parse(value));
            } else {
                long value = parser.readLong();
                return Instant.ofEpochMilli(value);
            }
        }

        @Override
        public void toJson(Generator generator, Instant instance, boolean writeNulls) {
            if (useFormatter) {
                generator.writeQuoted(formatter.format(instance));
            } else {
                generator.writeValue(instance.toEpochMilli());
            }
        }

        @Override
        public void configure(JsonBindingConfigurer jsonBindingConfigurer, JsonContext jsonContext) {
            Optional<Formatter> dateFormatter = jsonContext.dateFormat();
            this.useFormatter = dateFormatter.isPresent();
            this.formatter = dateFormatter.map(this::createFormatter).orElse(DEFAULT_FORMATTER);
        }

        private DateTimeFormatter createFormatter(Formatter format) {
            DateTimeFormatter toReturn = format.format()
                    .map(DateTimeFormatter::ofPattern)
                    .orElse(DEFAULT_FORMATTER);
            format.locale().ifPresent(locale -> toReturn.withLocale(Locale.of(locale)));
            return toReturn;
        }
    }
}
