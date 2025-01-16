package io.helidon.json.binding;

public interface JsonBindingFactory<T> {

    BindingFactoryDeserializer<T>  createDeserializer();
    BindingFactorySerializer<T>  createSerializer();

}