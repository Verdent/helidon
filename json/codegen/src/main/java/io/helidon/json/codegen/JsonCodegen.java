package io.helidon.json.codegen;

import java.util.Collection;

import io.helidon.codegen.CodegenContext;
import io.helidon.codegen.RoundContext;
import io.helidon.codegen.classmodel.ClassModel;
import io.helidon.codegen.spi.CodegenExtension;
import io.helidon.common.types.TypeInfo;
import io.helidon.common.types.TypeName;

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
        TypeName annotatedTypeName = typeInfo.typeName();
        TypeName generatedType;
        ClassModel.Builder builder;
        if (annotatedTypeName.typeParameters().isEmpty()) {
            ConvertedTypeInfo convertedTypeInfo = ConvertedTypeInfo.create(typeInfo);
            generatedType = convertedTypeInfo.converterType();
            builder = ClassModel.builder().type(generatedType);
            JsonConverterGenerator.generateConverter(builder, convertedTypeInfo, typeInfo, false);
        } else {
            //We can create just regular Converter, no generics need to be resolved later
            generatedType = TypeName.builder()
                    .from(annotatedTypeName)
                    .className(annotatedTypeName.className()+"_BindingFactory")
                    .build();
            builder = ClassModel.builder().type(generatedType);
            JsonBindingFactoryGenerator.generateBindingFactory(builder, typeInfo);
        }

        roundContext.addGeneratedType(generatedType,
                                      builder,
                                      annotatedTypeName,
                                      typeInfo.originatingElement().orElse(annotatedTypeName));
    }

}
