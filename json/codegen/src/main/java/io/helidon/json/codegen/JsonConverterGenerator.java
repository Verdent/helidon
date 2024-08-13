package io.helidon.json.codegen;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import io.helidon.codegen.classmodel.Annotation;
import io.helidon.codegen.classmodel.ClassBase;
import io.helidon.codegen.classmodel.Content;
import io.helidon.codegen.classmodel.Method;
import io.helidon.common.types.ElementKind;
import io.helidon.common.types.TypeInfo;
import io.helidon.common.types.TypeName;
import io.helidon.common.types.TypeNames;

import static java.util.function.Predicate.not;

import static io.helidon.json.codegen.Types.PRIMITIVE_TO_BOXED;

class JsonConverterGenerator {

    private static final String PROPERTY_NAME_SUFFIX = "_";
    private static final Supplier<?> DEFAULT_TYPE_VALUE = () -> null;
    private static final Map<TypeName, Supplier<?>> DEFAULT_TYPE_VALUES = Map.of(
            TypeNames.PRIMITIVE_BOOLEAN, () -> false,
            TypeNames.PRIMITIVE_BYTE, () -> 0,
            TypeNames.PRIMITIVE_SHORT, () -> 0,
            TypeNames.PRIMITIVE_INT, () -> 0,
            TypeNames.PRIMITIVE_LONG, () -> 0,
            TypeNames.PRIMITIVE_FLOAT, () -> "0.0F",
            TypeNames.PRIMITIVE_DOUBLE, () -> "0.0"
    );

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

        Content.Builder configBuilder = Content.builder();

        classBuilder.name(converterInfo.converterType().className())
                .addInterface(converterInterfaceType)
                .addMethod(method -> generateToJsonMethod(classBuilder, method, converterInfo, configBuilder))
                .addMethod(method -> generateFromJsonMethod(classBuilder, method, converterInfo, configBuilder));
    }

    private static void generateToJsonMethod(ClassBase.Builder<?, ?> classBuilder, Method.Builder method,
                                             ConvertedTypeInfo converterInfo,
                                             Content.Builder configBuilder) {
        method.name("toJson")
                .addParameter(param -> param.name("generator").type(Types.JSON_GENERATOR))
                .addParameter(param -> param.name("instance").type(converterInfo.originalType()))
                .addAnnotation(Annotation.create(Override.class))
                .addContentLine("generator.writeObjectStart();");
        List<JsonProperty> jsonProperties = converterInfo.jsonProperties()
                .values()
                .stream()
                .filter(not(JsonProperty::propertyIgnored))
                .filter(it -> !it.getterIgnored() || it.directFieldAccess())
                .toList();

        List<String> createdSerializers = new ArrayList<>();
        boolean first = true;
        for (JsonProperty jsonProperty : jsonProperties) {
            if (!first) {
                method.addContentLine("generator.writeComma();");
            } else {
                first = false;
            }
            TypeName type = jsonProperty.serializationType().orElseThrow();
            TypeName resolved = PRIMITIVE_TO_BOXED.getOrDefault(type, type);
            String fieldName = "serializer" + ensureUpperStart(type);
            if (!createdSerializers.contains(fieldName)) {
                createdSerializers.add(fieldName);
                TypeName converterType = TypeName.builder()
                        .from(Types.JSON_SERIALIZER_TYPE)
                        .addTypeArgument(resolved)
                        .build();
                classBuilder.addField(fieldBuilder -> fieldBuilder.name(fieldName)
                        .type(converterType)
                        .defaultValueContent("null"));
            }
            configBuilder.addContent(fieldName + " = runtimeJson.getSerializer(").addContent(type).addContentLine(".class);");
            method.addContentLine("generator.writeKey(\"" + jsonProperty.serializationName().orElseThrow() + "\");");
            String accessor = jsonProperty.getterName()
                    .filter(getterName -> !jsonProperty.getterIgnored())
                    .map(getterName -> getterName + "()")
                    .or(jsonProperty::fieldName)
                    .orElseThrow();
            method.addContentLine(fieldName + ".toJson(generator, instance." + accessor + ");");
        }
        method.addContentLine("generator.writeObjectEnd();");
    }

    private static void generateFromJsonMethod(ClassBase.Builder<?, ?> classBuilder,
                                               Method.Builder method,
                                               ConvertedTypeInfo converterInfo,
                                               Content.Builder configBuilder) {
        CreatorInfo creatorInfo = converterInfo.creatorInfo();
        boolean hasCreator = creatorInfo.creatorKind() == ElementKind.CONSTRUCTOR && !creatorInfo.parameters().isEmpty();
        List<JsonProperty> jsonProperties = converterInfo.jsonProperties()
                .values()
                .stream()
                .filter(not(JsonProperty::propertyIgnored))
                .filter(it -> !it.setterIgnored() || it.directFieldAccess())
                .toList();

        method.name("fromJson")
                .returnType(converterInfo.originalType())
                .addParameter(param -> param.name("parser").type(Types.JSON_PARSER))
                .addAnnotation(Annotation.create(Override.class))
                .addContent(byte.class).addContentLine(" lastByte = parser.lastByte();")
                .addContentLine("if (lastByte != '{') {")
                .addContent("throw new ").addContent(Types.JSON_EXCEPTION)
                .addContent("(\"Object start expected. Found: \" + ")
                .addContent(Character.class).addContentLine(".toString(lastByte));")
                .addContentLine("}")
                .addContentLine("lastByte = parser.readNextByte();")
                .addContentLine("if (lastByte != '\"') {")
                .addContentLine("parser.byteRollback();")
                .addContentLine("lastByte = parser.nextToken();")
                .addContentLine("}");
        if (hasCreator) {
            for (JsonProperty jsonProperty : jsonProperties) {
                TypeName type = jsonProperty.deserializationType().orElseThrow();
                method.addContent(type)
                        .addContent(" " + jsonProperty.deserializationName().orElseThrow() + PROPERTY_NAME_SUFFIX + " = ")
                        .addContentLine(DEFAULT_TYPE_VALUES.getOrDefault(type, DEFAULT_TYPE_VALUE).get() + ";");
            }
        } else {
            TypeName originalType = converterInfo.originalType();
            method.addContent(originalType).addContent(" generatedInstance = new ")
                    .addContent(originalType).addContentLine("();");
        }
        method.addContentLine("if (lastByte != '}') {")
                .addContentLine("parser.byteRollback();")
                .addContentLine("do {")
                .addContentLine("parser.nextToken();")
                .addContent(int.class).addContentLine(" hash = parser.readStringAsHash();")
                .addContentLine("parser.nextToken();")
                .addContentLine("parser.nextToken();")
                .addContentLine("switch(hash) {");
        Map<Integer, List<JsonProperty>> hashes = jsonProperties.stream()
                .collect(Collectors.groupingBy(jsonProperty ->
                                                       calculateNameHash(jsonProperty.deserializationName().orElseThrow())));
        for (Map.Entry<Integer, List<JsonProperty>> entry : hashes.entrySet()) {
            if (entry.getValue().size() > 1) {
                throw new UnsupportedOperationException("Naming collision, not implemented yet");
            } else {
                JsonProperty jsonProperty = entry.getValue().getFirst();
                method.addContentLine("case " + entry.getKey() + ": //" + jsonProperty.deserializationName().orElseThrow());
                method.increaseContentPadding();
                addTypeHandling(jsonProperty, method, configBuilder, classBuilder, hasCreator);
                method.decreaseContentPadding();
            }
        }
        method.addContentLine("default:")
                .padContent().addContentLine("parser.skip();");
        method.addContentLine("}")
                .addContentLine("lastByte = parser.nextToken();")
                .addContent("}").addContentLine(" while(lastByte == ',');");
        method.addContentLine("}");
        method.addContentLine("return null;");
    }

    private static void generateConfigurationOverMethod(Method.Builder method, ConvertedTypeInfo converterInfo) {

    }

    private static void addTypeHandling(JsonProperty jsonProperty,
                                        Method.Builder method,
                                        Content.Builder configBuilder,
                                        ClassBase.Builder<?, ?> classBuilder,
                                        boolean hasCreator) {
        TypeName type = jsonProperty.serializationType().orElseThrow();
        TypeName resolved = PRIMITIVE_TO_BOXED.getOrDefault(type, type);
        jsonProperty.deserializer()
                .ifPresentOrElse(deserializer -> createTypeDeserializer(jsonProperty,
                                                                        deserializer,
                                                                        method,
                                                                        classBuilder,
                                                                        hasCreator),
                                 () -> {
                });
        //        TypeName resolved = MAPPER.getOrDefault(type, type);
        //        if (property.deserializerClass() != null) {
        //            createTypeDeserializer(property, method, classBuilder, applyCreator);
        //        } else if (!resolved.typeArguments().isEmpty()) {
        //            TypeName.Builder constantType = TypeName.builder()
        //                    .type(JsonDeserializer.class);
        //            //            TypeName.Builder listTypeBuilder = TypeName.builder()
        //            //                    .className(resolved.className())
        //            //                    .packageName(resolved.packageName());
        //            String fieldName = "deserializer" + ensureUpperStart(property.deserializableName());
        //            Field.Builder fieldBuilder = Field.builder()
        //                    .name(fieldName);
        //            //            createListType(resolved.typeArguments().get(0), listTypeBuilder);
        //            //            TypeName listType = listTypeBuilder.build();
        //            if (!classArguments.isEmpty() && checkUnresolvedType(type, classArguments)) {
        //                configureMethod.addContent(fieldName + " = runtimeJson.getDeserializer(")
        //                        .addContent(GenericsHelper.class)
        //                        .addContent(".createParamType(");
        //                createUnresolvedGenericHandling(type, classArguments, configureMethod);
        //                configureMethod.addContentLine("));");
        //            } else {
        //                String helperName = "desHelper" + ensureUpperStart(property.deserializableName());
        //                //                configureMethod.addContent(ParamTypeHelper.class).addContent("<").addContent(listType)
        //                configureMethod.addContent(ParamTypeHelper.class).addContent("<").addContent(resolved)
        //                        .addContentLine("> " + helperName + " = new ParamTypeHelper<>() {};");
        //                configureMethod.addContentLine(fieldName + " = runtimeJson.getDeserializer(" + helperName + ".getType
        //                ());");
        //            }
        //            //            fieldBuilder.type(constantType.addTypeArgument(listType).build())
        //            fieldBuilder.type(constantType.addTypeArgument(resolved).build())
        //                    .defaultValueContent("null");
        //            classBuilder.addField(fieldBuilder);
        //            valueWritingMethod(property, method, applyCreator, fieldName);
        //        } else if (alreadyProcessed.contains(resolved)) {
        //            String converterFieldName = "deserializer" + ensureUpperStart(type);
        //            valueWritingMethod(property, method, applyCreator, converterFieldName);
        //        } else {
        //            alreadyProcessed.add(resolved);
        //            String fieldName = "deserializer" + ensureUpperStart(type);
        //            TypeName converterType = TypeName.builder().type(JsonDeserializer.class).addTypeArgument(resolved).build();
        //            classBuilder.addField(fieldBuilder -> fieldBuilder.name(fieldName)
        //                    .type(converterType)
        //                    .defaultValueContent("null"));
        //            Integer position = classArguments.get(type.fqName());
        //            if (position != null) {
        //                //We are creating BindingFactory
        //                configureMethod.addContentLine(fieldName + " = runtimeJson.getDeserializer(createdType
        //                .getActualTypeArguments()[" + position + "]);");
        //            } else {
        //                configureMethod.addContent(fieldName + " = runtimeJson.getDeserializer(").addContent(type)
        //                .addContentLine(".class);");
        //            }
        //            valueWritingMethod(property, method, applyCreator, fieldName);
        //        }
    }

    private static void createTypeDeserializer(JsonProperty property,
                                               TypeName deserializer,
                                               Method.Builder method,
                                               ClassBase.Builder<?, ?> classBuilder,
                                               boolean hasCreator) {
        String constantName = property.deserializationName().orElseThrow().toUpperCase() + "_DESERIALIZER";
        classBuilder.addField(field -> field.name(constantName)
                .type(deserializer)
                .isStatic(true)
                .isFinal(true)
                .addContent("new ").addContent(deserializer).addContent("()"));

        valueWritingMethod(property, method, hasCreator, constantName);
    }

    private static void valueWritingMethod(JsonProperty property,
                                           Method.Builder method,
                                           boolean hasCreator,
                                           String reference) {
        if (hasCreator) {
            method.addContentLine(property.deserializationName().orElseThrow() + PROPERTY_NAME_SUFFIX + " = "
                                          + reference + ".fromJson(parser);");
        } else {
            String writingMethod = property.setterName()
                    .map(methodName -> methodName + "(" + reference + ".fromJson(parser));")
                    .orElseGet(() -> property.fieldName()
                            .filter(it -> !property.directFieldAccess())
                            .map(fieldName -> "generatedInstance." + fieldName + " = " + reference + ".fromJson(parser);")
                            .orElseThrow());
            method.addContentLine(writingMethod);
        }
        method.addContentLine("break;");
    }

    private static String ensureUpperStart(TypeName typeName) {
        String str = typeName.className().replaceAll("\\[]", "Array");
        if (Character.isUpperCase(str.charAt(0))) {
            return str;
        } else if (str.length() == 1) {
            return str.toUpperCase();
        } else {
            return Character.toUpperCase(str.charAt(0)) + str.substring(1);
        }
    }

    private static String removeArraySigns(String className) {
        int index = className.indexOf("[");
        if (index > -1) {
            className = className.substring(0, index) + "Array";
        }
        return className;
    }

    private static int calculateNameHash(String name) {
        long fnvHash = 2166136261L;
        byte[] array = name.getBytes(StandardCharsets.UTF_8);
        for (byte b : array) {
            fnvHash ^= b;
            fnvHash *= 16777619;
        }
        return (int) fnvHash;
    }

}
