package io.helidon.json.binding;

import io.helidon.builder.api.Prototype;
import io.helidon.common.GenericType;

class JsonBindingConfigCustomMethods {

    private JsonBindingConfigCustomMethods() {
    }

    @Prototype.BuilderMethod
    static <T> void addConverter(JsonBindingConfig.BuilderBase<?, ?> builder, JsonConverter<T> converter) {
        builder.addSerializer(converter)
                .addDeserializer(converter);
    }

}
