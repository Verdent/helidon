package io.helidon.json.binding;

public interface TypedGenericTypeBindingFactory<T> extends JsonGenericTypeBindingFactory<T> {

    Class<?> type();

}