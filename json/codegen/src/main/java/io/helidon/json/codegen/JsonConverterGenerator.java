package io.helidon.json.codegen;

import io.helidon.codegen.classmodel.Annotation;
import io.helidon.codegen.classmodel.ClassBase;
import io.helidon.codegen.classmodel.ContentBuilder;
import io.helidon.codegen.classmodel.Executable;
import io.helidon.codegen.classmodel.Method;
import io.helidon.common.types.TypeInfo;
import io.helidon.common.types.TypeName;

class JsonConverterGenerator {

    private JsonConverterGenerator() {
    }

    static void generateConverter(ClassBase.Builder<?, ?> classBuilder,
                                  ConvertedTypeInfo converterInfo,
                                  TypeInfo annotatedType,
                                  boolean useConstructorToConfigure) {
        TypeName converterInterfaceType = TypeName.builder()
                .from(Types.JSON_CONVERTER_TYPE)
                .addTypeArgument(annotatedType.typeName())
                .build();

        ContentBuilder<?>

        classBuilder.name(converterInfo.converterType().className())
                .addInterface(converterInterfaceType)
//                .addMethod(method -> generateConfigureMethod(method, converterInfo))
                .addMethod(method -> generateToJsonMethod(method, converterInfo))
                .addMethod(method -> generateFromJsonMethod(method, converterInfo));
    }

    private static void generateToJsonMethod(Method.Builder method, ConvertedTypeInfo converterInfo) {
        method.name("toJson")
                .addParameter(param -> param.name("generator").type(Types.JSON_GENERATOR))
                .addParameter(param -> param.name("instance").type(converterInfo.originalType()))
                .addAnnotation(Annotation.create(Override.class)).content;
    }

    private static void generateFromJsonMethod(Method.Builder method, ConvertedTypeInfo converterInfo) {
        method.name("fromJson")
                .returnType(converterInfo.originalType())
                .addParameter(param -> param.name("parser").type(Types.JSON_PARSER))
                .addAnnotation(Annotation.create(Override.class))
                .addContentLine("return null;");
    }

    private static void generateConfigurationOverMethod(Method.Builder method, ConvertedTypeInfo converterInfo) {

    }

}
