package io.helidon.json.codegen;

import io.helidon.codegen.classmodel.ClassBase;
import io.helidon.codegen.classmodel.InnerClass;
import io.helidon.common.types.AccessModifier;
import io.helidon.common.types.TypeInfo;
import io.helidon.common.types.TypeName;

class JsonBindingFactoryGenerator {

    private JsonBindingFactoryGenerator() {
    }

    static void generateBindingFactory(ClassBase.Builder<?,?> classBuilder, TypeInfo annotatedType) {
        classBuilder.addInterface(TypeName.builder()
                              .from(Types.JSON_BINDING_FACTORY)
                              .addTypeArgument(annotatedType.typeName())
                              .build());

        ConvertedTypeInfo convertedTypeInfo = ConvertedTypeInfo.create(annotatedType);
        InnerClass.Builder converterClassBuilder = InnerClass.builder()
                .name(convertedTypeInfo.converterType().className())
                .accessModifier(AccessModifier.PRIVATE)
                .isFinal(true)
                .isStatic(true);
        JsonConverterGenerator.generateConverter(converterClassBuilder, convertedTypeInfo, annotatedType, true);
        classBuilder.addInnerClass(converterClassBuilder);
    }

}
