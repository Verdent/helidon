package io.helidon.json.codegen;

import io.helidon.codegen.Option;

public interface CodegenOptions {

    Option<Boolean> CODEGEN_JSON_NULL = Option.create("helidon.codegen.json.nulls",
                                                      "Sets the default for whether generated type "
                                                              + "serializers should write nulls or not.",
                                                      false);

    Option<Boolean> CODEGEN_JSON_UNKNOWN = Option.create("helidon.codegen.json.unknown",
                                                         "Sets the default for whether generated type "
                                                                 + "deserializers should fail when unknow property is "
                                                                 + "encountered.",
                                                         false);

    Option<String> CODEGEN_JSON_ORDER = Option.create("helidon.codegen.json.order",
                                                      "Sets the default for default ordering of the "
                                                              + "properties in the JSON document. "
                                                              + "Available values are: ALPHABETICAL, REVERSE_ALPHABETICAL, ANY",
                                                      "ALL");

}
