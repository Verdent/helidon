package io.helidon.json.codegen;

import io.helidon.common.types.TypeName;

final class Types {

    //Annotations
    static final TypeName JSON_AS_JSON = TypeName.create("io.helidon.json.binding.Json.AsJson");
    static final TypeName JSON_DESERIALIZER = TypeName.create("io.helidon.json.binding.Json.Deserializer");
    static final TypeName JSON_SERIALIZER = TypeName.create("io.helidon.json.binding.Json.Serializer");
    static final TypeName JSON_CONVERTER = TypeName.create("io.helidon.json.binding.Json.Converter");
    static final TypeName JSON_PROPERTY = TypeName.create("io.helidon.json.binding.Json.Property");
    static final TypeName JSON_IGNORE = TypeName.create("io.helidon.json.binding.Json.Ignore");
    static final TypeName JSON_CREATOR = TypeName.create("io.helidon.json.binding.Json.Creator");

    //Types
    static final TypeName JSON_CONVERTER_TYPE = TypeName.create("io.helidon.json.binding.JsonConverter");
    static final TypeName JSON_BINDING_FACTORY = TypeName.create("io.helidon.json.binding.JsonBindingFactory");

    static final TypeName JSON_GENERATOR = TypeName.create("io.helidon.json.processor.Generator");
    static final TypeName JSON_PARSER = TypeName.create("io.helidon.json.processor.JsonParser");

    private Types() {
    }

}
