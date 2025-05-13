package io.helidon.json.codegen;

import java.util.Collection;

import io.helidon.codegen.CodegenContext;
import io.helidon.codegen.RoundContext;
import io.helidon.codegen.classmodel.Annotation;
import io.helidon.codegen.classmodel.ClassModel;
import io.helidon.codegen.spi.CodegenExtension;
import io.helidon.common.Weighted;
import io.helidon.common.types.TypeInfo;
import io.helidon.common.types.TypeName;
import io.helidon.common.types.TypeNames;
import io.helidon.service.registry.Service;

class JsonCodegen implements CodegenExtension {

    private final CodegenContext ctx;

    public JsonCodegen(CodegenContext ctx) {
        this.ctx = ctx;
    }

    @Override
    public void process(RoundContext roundContext) {
        Collection<TypeInfo> typeInfos = roundContext.annotatedTypes(Types.JSON_ENTITY);
        for (TypeInfo typeInfo : typeInfos) {
            process(typeInfo, roundContext);
        }
    }

    private void process(TypeInfo typeInfo, RoundContext roundContext) {
        TypeName annotatedTypeName = typeInfo.typeName();
        TypeName generatedType;
        ClassModel.Builder builder;
        if (annotatedTypeName.typeArguments().isEmpty()) {
            //We can create just regular Converter, no generics need to be resolved later
            ConvertedTypeInfo convertedTypeInfo = ConvertedTypeInfo.create(typeInfo, ctx);
            generatedType = convertedTypeInfo.converterType();
            builder = ClassModel.builder()
                    .type(generatedType)
                    .addAnnotation(Annotation.create(Service.PerLookup.class))
                    .addAnnotation(Annotation.builder()
                                           .type(TypeNames.WEIGHT)
                                           .addParameter("value", Weighted.DEFAULT_WEIGHT - 5)
                                           .build());
            JsonConverterGenerator.generateConverter(builder, convertedTypeInfo, typeInfo, false, true);
        } else {
            generatedType = TypeName.builder()
                    .from(annotatedTypeName)
                    .className(annotatedTypeName.className()+"_BindingFactory")
                    .build();
            builder = ClassModel.builder().type(generatedType);
            JsonBindingFactoryGenerator.generateBindingFactory(builder, typeInfo, ctx);
        }

        roundContext.addGeneratedType(generatedType,
                                      builder,
                                      annotatedTypeName,
                                      typeInfo.originatingElement().orElse(annotatedTypeName));
    }

}
