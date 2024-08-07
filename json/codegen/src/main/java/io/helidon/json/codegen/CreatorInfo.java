package io.helidon.json.codegen;

import java.util.List;

import io.helidon.common.types.ElementKind;

record CreatorInfo(ElementKind creatorKind, String method, List<String> parameters) {
}
