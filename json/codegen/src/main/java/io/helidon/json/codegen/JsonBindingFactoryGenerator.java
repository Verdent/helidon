package io.helidon.json.codegen;

import io.helidon.codegen.CodegenContext;
import io.helidon.codegen.classmodel.Annotation;
import io.helidon.codegen.classmodel.ClassBase;
import io.helidon.codegen.classmodel.InnerClass;
import io.helidon.codegen.classmodel.Method;
import io.helidon.codegen.classmodel.TypeArgument;
import io.helidon.common.Weighted;
import io.helidon.common.types.AccessModifier;
import io.helidon.common.types.TypeInfo;
import io.helidon.common.types.TypeName;
import io.helidon.common.types.TypeNames;
import io.helidon.service.registry.Service;

import java.lang.reflect.Type;

class JsonBindingFactoryGenerator {

    private JsonBindingFactoryGenerator() {
    }

    static void generateBindingFactory(ClassBase.Builder<?,?> classBuilder, TypeInfo annotatedType, CodegenContext ctx) {
        classBuilder.addAnnotation(Annotation.create(Service.PerLookup.class))
                .addGenericArgument(TypeArgument.create("T"))
                .addAnnotation(Annotation.builder()
                                       .type(TypeNames.WEIGHT)
                                       .addParameter("value", Weighted.DEFAULT_WEIGHT - 5)
                                       .build())
                .addInterface(TypeName.builder()
                                      .from(Types.JSON_BINDING_FACTORY_TYPED)
                                      .addTypeArgument(annotatedType.typeName())
                                      .build());

        ConvertedTypeInfo convertedTypeInfo = ConvertedTypeInfo.create(annotatedType, ctx);
        InnerClass.Builder converterClassBuilder = InnerClass.builder()
                .name(convertedTypeInfo.converterType().className())
                .accessModifier(AccessModifier.PRIVATE)
                .addGenericArgument(TypeArgument.create("T"))
                .isFinal(true)
                .isStatic(true)
                .addField(builder -> builder.isFinal(true).type(Type.class).name("type"))
                .addConstructor(builder -> builder.addParameter(param -> param.type(Type.class).name("type"))
                        .addContent("this.type = type;"));
        JsonConverterGenerator.generateConverter(converterClassBuilder, convertedTypeInfo, annotatedType, true, false);
        classBuilder.addInnerClass(converterClassBuilder)
                .addMethod(method -> addCreateDeserializerMethod(method, convertedTypeInfo))
                .addMethod(method -> addCreateSerializerMethod(method, convertedTypeInfo))
                .addMethod(method -> addTypeMethod(method, convertedTypeInfo));
    }

    private static void addCreateDeserializerMethod(Method.Builder method, ConvertedTypeInfo convertedTypeInfo) {
        method.name("createDeserializer")
                .addAnnotation(Annotation.create(Override.class))
                .returnType(builder -> builder.type(TypeName.builder()
                                                            .from(Types.JSON_FACTORY_DESERIALIZER_TYPE)
                                                            .addTypeArgument(convertedTypeInfo.originalType())
                                                            .build()))
                .addParameter(builder -> builder.type(Type.class).name("type"))
                .addContent("return new ")
                .addContent(convertedTypeInfo.converterType())
                .addContentLine("<>(type);");
    }

    private static void addCreateSerializerMethod(Method.Builder method, ConvertedTypeInfo convertedTypeInfo) {
        method.name("createSerializer")
                .addAnnotation(Annotation.create(Override.class))
                .returnType(builder -> builder.type(TypeName.builder()
                                                            .from(Types.JSON_FACTORY_SERIALIZER_TYPE)
                                                            .addTypeArgument(convertedTypeInfo.originalType())
                                                            .build()))
                .addParameter(builder -> builder.type(Type.class).name("type"))
                .addContent("return new ")
                .addContent(convertedTypeInfo.converterType())
                .addContentLine("<>(type);");
    }

    private static void addTypeMethod(Method.Builder method, ConvertedTypeInfo convertedTypeInfo) {
        method.name("type")
                .addAnnotation(Annotation.create(Override.class))
                .returnType(builder -> builder.type(TypeName.builder()
                                                            .type(Class.class)
                                                            .addTypeArgument(TypeArgument.create("?"))
                                                            .build()))
                .addContent("return ")
                .addContent(convertedTypeInfo.originalType().genericTypeName())
                .addContentLine(".class;");
    }

}
