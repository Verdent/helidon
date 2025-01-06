package io.helidon.json.binding;

import io.helidon.common.GenericType;

public interface TypedJsonSerializer<T> extends JsonSerializer<T> {

    GenericType<T> type();

}
