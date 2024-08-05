package io.helidon.json.codegen;

import io.helidon.common.types.TypeName;

final class Types {

    static final TypeName JSON_AS_JSON = TypeName.create("io.helidon.json.binding.Json.AsJson");
    static final TypeName JSON_DESERIALIZER = TypeName.create("io.helidon.json.binding.Json.Deserializer");
    static final TypeName JSON_SERIALIZER = TypeName.create("io.helidon.json.binding.Json.Serializer");
    static final TypeName JSON_CONVERTER = TypeName.create("io.helidon.json.binding.Json.Converter");
    static final TypeName JSON_PROPERTY = TypeName.create("io.helidon.json.binding.Json.Property");
    static final TypeName JSON_IGNORE = TypeName.create("io.helidon.json.binding.Json.Ignore");
    static final TypeName JSON_CREATOR = TypeName.create("io.helidon.json.binding.Json.Creator");

    private Types() {
    }

}
