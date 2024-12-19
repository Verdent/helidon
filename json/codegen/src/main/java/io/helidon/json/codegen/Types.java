package io.helidon.json.codegen;

import java.util.Map;

import io.helidon.common.types.TypeName;
import io.helidon.common.types.TypeNames;

import static io.helidon.common.types.TypeNames.BOXED_BOOLEAN;
import static io.helidon.common.types.TypeNames.BOXED_BYTE;
import static io.helidon.common.types.TypeNames.BOXED_CHAR;
import static io.helidon.common.types.TypeNames.BOXED_DOUBLE;
import static io.helidon.common.types.TypeNames.BOXED_FLOAT;
import static io.helidon.common.types.TypeNames.BOXED_INT;
import static io.helidon.common.types.TypeNames.BOXED_LONG;
import static io.helidon.common.types.TypeNames.BOXED_SHORT;
import static io.helidon.common.types.TypeNames.BOXED_VOID;
import static io.helidon.common.types.TypeNames.PRIMITIVE_BOOLEAN;
import static io.helidon.common.types.TypeNames.PRIMITIVE_BYTE;
import static io.helidon.common.types.TypeNames.PRIMITIVE_CHAR;
import static io.helidon.common.types.TypeNames.PRIMITIVE_DOUBLE;
import static io.helidon.common.types.TypeNames.PRIMITIVE_FLOAT;
import static io.helidon.common.types.TypeNames.PRIMITIVE_INT;
import static io.helidon.common.types.TypeNames.PRIMITIVE_LONG;
import static io.helidon.common.types.TypeNames.PRIMITIVE_SHORT;
import static io.helidon.common.types.TypeNames.PRIMITIVE_VOID;

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
    static final TypeName JSON_DESERIALIZER_TYPE = TypeName.create("io.helidon.json.binding.JsonDeserializer");
    static final TypeName JSON_SERIALIZER_TYPE = TypeName.create("io.helidon.json.binding.JsonSerializer");
    static final TypeName JSON_CONVERTER_TYPE = TypeName.create("io.helidon.json.binding.JsonConverter");
    static final TypeName JSON_BINDING = TypeName.create("io.helidon.json.binding.JsonBinding");
    static final TypeName JSON_BINDING_FACTORY = TypeName.create("io.helidon.json.binding.JsonBindingFactory");
    static final TypeName JSON_CONFIGURABLE = TypeName.create("io.helidon.json.binding.JsonConfigurable");

    static final TypeName JSON_GENERATOR = TypeName.create("io.helidon.json.processor.Generator");
    static final TypeName JSON_PARSER = TypeName.create("io.helidon.json.processor.JsonParser");
    static final TypeName JSON_EXCEPTION = TypeName.create("io.helidon.json.processor.JsonException");

    static final Map<TypeName, TypeName> PRIMITIVE_TO_BOXED = Map.of(
            PRIMITIVE_BOOLEAN, BOXED_BOOLEAN,
            PRIMITIVE_BYTE, BOXED_BYTE,
            PRIMITIVE_SHORT,BOXED_SHORT,
            PRIMITIVE_INT,BOXED_INT,
            PRIMITIVE_LONG, BOXED_LONG,
            PRIMITIVE_CHAR, BOXED_CHAR,
            PRIMITIVE_FLOAT, BOXED_FLOAT,
            PRIMITIVE_DOUBLE, BOXED_DOUBLE,
            PRIMITIVE_VOID, BOXED_VOID
    );

    private Types() {
    }

}
