package io.helidon.jsonschema.generator;

import java.util.Set;

import io.helidon.codegen.CodegenContext;
import io.helidon.codegen.spi.CodegenExtension;
import io.helidon.codegen.spi.CodegenExtensionProvider;
import io.helidon.common.types.TypeName;

public class SchemaCodegenProvider implements CodegenExtensionProvider {
    @Override
    public CodegenExtension create(CodegenContext ctx, TypeName generatorType) {
        return new SchemaCodegen(ctx, generatorType);
    }

    @Override
    public Set<TypeName> supportedAnnotations() {
        return Set.of(Types.JSON_SCHEMA_SCHEMA);
    }

}
