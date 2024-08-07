package io.helidon.json.codegen;

import java.util.Collection;

import io.helidon.codegen.CodegenContext;
import io.helidon.codegen.RoundContext;
import io.helidon.codegen.spi.CodegenExtension;
import io.helidon.common.types.TypeInfo;

class JsonCodegen implements CodegenExtension {

    private final CodegenContext ctx;

    public JsonCodegen(CodegenContext ctx) {
        this.ctx = ctx;
    }

    @Override
    public void process(RoundContext roundContext) {
        Collection<TypeInfo> typeInfos = roundContext.annotatedTypes(Types.JSON_AS_JSON);
        for (TypeInfo typeInfo : typeInfos) {
            process(typeInfo, roundContext);
        }
    }

    private void process(TypeInfo typeInfo, RoundContext roundContext) {
        ConvertedTypeInfo convertedTypeInfo = ConvertedTypeInfo.create(ctx, typeInfo);

        System.out.println();
        //        TypeName converter = TypeName.create(typeInfo.typeName().)
    }

}
