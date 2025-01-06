package io.helidon.json.binding;

import io.helidon.common.GenericType;

public interface TypedJsonDeserializer<T> extends JsonDeserializer<T> {

    GenericType<T> type();

}
