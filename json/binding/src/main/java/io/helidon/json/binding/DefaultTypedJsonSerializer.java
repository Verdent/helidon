package io.helidon.json.binding;

import io.helidon.common.GenericType;
import io.helidon.json.processor.Generator;

class DefaultTypedJsonSerializer<T> implements TypedJsonSerializer<T> {

    private final GenericType<T> type;
    private final JsonSerializer<T> serializer;

    DefaultTypedJsonSerializer(GenericType<T> type, JsonSerializer<T> serializer) {
        this.type = type;
        this.serializer = serializer;
    }

    @Override
    public GenericType<T> type() {
        return type;
    }

    @Override
    public void toJson(Generator generator, T instance, boolean writeNulls) {
        serializer.toJson(generator, instance, writeNulls);
    }
}
