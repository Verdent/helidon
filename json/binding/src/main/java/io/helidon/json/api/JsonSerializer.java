package io.helidon.json.api;

public interface JsonSerializer<T> {

    void toJson(Generator generator, T instance);

}
