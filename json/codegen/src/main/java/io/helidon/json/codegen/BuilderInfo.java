package io.helidon.json.codegen;

import java.util.List;
import java.util.Optional;

import io.helidon.common.types.TypeName;

record BuilderInfo(TypeName builderType,
                   Optional<String> builderMethodName,
                   String buildMethodName,
                   List<String> builderProperties) {
}
