package io.helidon.json.codegen;

import java.util.List;

import io.helidon.common.types.TypeName;

record BuilderInfo(TypeName builderType, String method, List<String> parameters) {
}
