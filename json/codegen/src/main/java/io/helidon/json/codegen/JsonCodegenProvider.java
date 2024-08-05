package io.helidon.json.codegen;

import java.util.Set;

import io.helidon.codegen.CodegenContext;
import io.helidon.codegen.spi.CodegenExtension;
import io.helidon.codegen.spi.CodegenExtensionProvider;
import io.helidon.common.types.TypeName;

public class JsonCodegenProvider implements CodegenExtensionProvider {
    @Override
    public CodegenExtension create(CodegenContext ctx, TypeName generatorType) {
        return new JsonCodegen();
    }

    @Override
    public Set<TypeName> supportedAnnotations() {
        return Set.of(Types.JSON_AS_JSON);
    }
}
