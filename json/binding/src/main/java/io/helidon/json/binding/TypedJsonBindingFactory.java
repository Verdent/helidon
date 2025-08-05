package io.helidon.json.binding;

import java.util.Set;

public interface TypedJsonBindingFactory<T> extends JsonBindingFactory<T> {

    Set<Class<?>> supportedTypes();

}