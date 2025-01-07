package io.helidon.json.binding;

public interface TypedJsonBindingFactory<T> extends JsonBindingFactory<T> {

    Class<?> type();

}