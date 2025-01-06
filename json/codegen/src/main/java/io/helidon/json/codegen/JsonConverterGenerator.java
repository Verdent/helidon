package io.helidon.json.codegen;

import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import io.helidon.codegen.classmodel.Annotation;
import io.helidon.codegen.classmodel.ClassBase;
import io.helidon.codegen.classmodel.Content;
import io.helidon.codegen.classmodel.Method;
import io.helidon.codegen.classmodel.Returns;
import io.helidon.common.GenericType;
import io.helidon.common.Weighted;
import io.helidon.common.types.ElementKind;
import io.helidon.common.types.ResolvedType;
import io.helidon.common.types.TypeInfo;
import io.helidon.common.types.TypeName;
import io.helidon.common.types.TypeNames;
import io.helidon.service.registry.Service;

import static java.util.function.Predicate.not;

import static io.helidon.json.codegen.Types.PRIMITIVE_TO_BOXED;

class JsonConverterGenerator {

    private static final String PROPERTY_NAME_SUFFIX = "_";
    private static final String CONFIGURE_PARAM = "jsonBinding";
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
                .from(Types.TYPED_JSON_CONVERTER_TYPE)
                .addTypeArgument(annotatedType.typeName())
                .build();

        Content.Builder configBuilder = Content.builder();

        classBuilder.name(converterInfo.converterType().className())
                .addInterface(converterInterfaceType)
                .addAnnotation(Annotation.create(Service.Singleton.class))
                .addAnnotation(Annotation.builder()
                                       .type(TypeName.create("io.helidon.common.Weight"))
                                       .addParameter("value", Weighted.DEFAULT_WEIGHT - 5)
                                       .build())
                .addInterface(Types.JSON_CONFIGURABLE)
                .addMethod(method -> generateToJsonMethod(classBuilder, method, converterInfo, configBuilder))
                .addMethod(method -> generateFromJsonMethod(classBuilder, method, converterInfo, configBuilder))
                .addMethod(method -> addConfigureMethod(method, configBuilder))
                .addMethod(method -> addTypeMethod(method, converterInfo));
    }

    private static void generateToJsonMethod(ClassBase.Builder<?, ?> classBuilder,
                                             Method.Builder method,
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

        Set<String> createdSerializers = new HashSet<>();
        boolean first = true;
        for (JsonProperty jsonProperty : jsonProperties) {
            if (!first) {
                method.addContentLine("generator.writeComma();");
            } else {
                first = false;
            }
            TypeName type = jsonProperty.serializationType().orElseThrow();
            TypeName resolved = PRIMITIVE_TO_BOXED.getOrDefault(type, type);
            String fieldName;
            if (!resolved.typeArguments().isEmpty()) {
                fieldName = "serializer" + ensureUpperStart(jsonProperty.serializationName().orElseThrow());
            } else {
                fieldName = "serializer" + ensureUpperStart(type);
            }
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
            //            if (!resolved.typeArguments().isEmpty()) {
            //                String helperName = "serType" + ensureUpperStart(jsonProperty.serializationName().orElseThrow());
            //                //Creates for example: TypeName serTypeName = TypeName.create("java.util.List<java.lang.String>");
            //                configBuilder.addContent(TypeName.class)
            //                        .addContent(" " + helperName + " = ")
            //                        .addContent(TypeName.class)
            //                        .addContentLine(".create(\"" + resolved.resolvedName() + "\");");
            //                configBuilder.addContentLine(fieldName + " = " + CONFIGURE_PARAM + ".getSerializer(" + helperName
            //                + ");");
            //            } else {
            //                configBuilder.addContent(fieldName + " = " + CONFIGURE_PARAM + ".getSerializer(")
            //                        .addContent(type)
            //                        .addContentLine(".class);");
            //            }

            if (!resolved.typeArguments().isEmpty()) {
                configBuilder.addContent(fieldName + " = " + CONFIGURE_PARAM + ".getSerializer(new ")
                        .addContent(GenericType.class)
                        .addContent("<")
                        .addContent(resolved)
                        .addContentLine(">() {});");
            } else {
                configBuilder.addContent(fieldName + " = " + CONFIGURE_PARAM + ".getSerializer(")
                        .addContent(type)
                        .addContentLine(".class);");
            }

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
        Set<TypeName> processedTypes = new HashSet<>(); //Used to identify already configured type deserializers
        for (Map.Entry<Integer, List<JsonProperty>> entry : hashes.entrySet()) {
            if (entry.getValue().size() > 1) {
                throw new UnsupportedOperationException("Naming collision, not implemented yet");
            } else {
                JsonProperty jsonProperty = entry.getValue().getFirst();
                method.addContentLine("case " + entry.getKey() + ": //" + jsonProperty.deserializationName().orElseThrow());
                method.increaseContentPadding();
                addTypeHandling(jsonProperty, method, configBuilder, classBuilder, hasCreator, processedTypes);
                method.decreaseContentPadding();
            }
        }
        method.addContentLine("default:")
                .padContent().addContentLine("parser.skip();");
        method.addContentLine("}")
                .addContentLine("lastByte = parser.nextToken();")
                .addContent("}").addContentLine(" while(lastByte == ',');");
        method.addContentLine("}");
        if (hasCreator) {
            TypeName originalType = converterInfo.originalType();
            method.addContent(originalType).addContent(" generatedInstance = new ")
                    .addContent(originalType).addContent("(");
            boolean first = true;
            for (JsonProperty property : jsonProperties) {
                if (property.usedInCreator()) {
                    if (first) {
                        first = false;
                    } else {
                        method.addContent(", ");
                    }
                    method.addContent(property.deserializationName().orElseThrow() + PROPERTY_NAME_SUFFIX);
                }
            }
            method.addContentLine(");");
            for (JsonProperty property : jsonProperties) {
                if (!property.usedInCreator()) {
                    if (property.directFieldAccess()) {
                        method.addContentLine("generatedInstance." + property.fieldName().orElseThrow() + " = "
                                                      + property.deserializationName()
                                .orElseThrow() + PROPERTY_NAME_SUFFIX + ";");
                    } else {
                        method.addContentLine("generatedInstance." + property.setterName().orElseThrow() + "("
                                                      + property.deserializationName()
                                .orElseThrow() + PROPERTY_NAME_SUFFIX + ");");
                    }
                }
            }
        }
        method.addContentLine("return generatedInstance;");
    }

    private static void addConfigureMethod(Method.Builder method, Content.Builder configBuilder) {
        method.name("configure")
                .addAnnotation(Annotation.create(Override.class))
                .addParameter(param -> param.type(Types.JSON_BINDING).name(CONFIGURE_PARAM))
                .content(configBuilder.build().toString());
    }

    private static void addTypeMethod(Method.Builder method, ConvertedTypeInfo converterInfo) {
        method.name("type")
                .returnType(builder -> builder.type(TypeName.builder()
                                                            .type(GenericType.class)
                                                            .addTypeArgument(converterInfo.originalType())
                                                            .build()))
                .addAnnotation(Annotation.create(Override.class))
                .addContent("return ")
                .addContent(GenericType.class)
                .addContent(".create(")
                .addContent(converterInfo.originalType())
                .addContentLine(".class);");
    }

    private static void addTypeHandling(JsonProperty jsonProperty,
                                        Method.Builder method,
                                        Content.Builder configBuilder,
                                        ClassBase.Builder<?, ?> classBuilder,
                                        boolean hasCreator,
                                        Set<TypeName> processedTypes) {
        jsonProperty.deserializer()
                .ifPresentOrElse(deserializer -> addUserDeserializer(jsonProperty,
                                                                     deserializer,
                                                                     method,
                                                                     classBuilder,
                                                                     hasCreator),
                                 () -> {
                                     TypeName type = jsonProperty.deserializationType().orElseThrow();
                                     TypeName resolvedType = PRIMITIVE_TO_BOXED.getOrDefault(type, type);
                                     createTypeDeserializer(jsonProperty,
                                                            resolvedType,
                                                            method,
                                                            classBuilder,
                                                            hasCreator,
                                                            configBuilder,
                                                            processedTypes);
                                 });
    }

    private static void createTypeDeserializer(JsonProperty jsonProperty,
                                               TypeName deserializationType,
                                               Method.Builder method,
                                               ClassBase.Builder<?, ?> classBuilder,
                                               boolean hasCreator,
                                               Content.Builder configMethod,
                                               Set<TypeName> processedTypes) {
        if (!deserializationType.typeArguments().isEmpty()) {
            //Type contains generics
            String fieldName = "deserializer" + ensureUpperStart(jsonProperty.deserializationName().orElseThrow());
            classBuilder.addField(builder -> builder.name(fieldName)
                    .type(TypeName.builder(Types.JSON_DESERIALIZER_TYPE).addTypeArgument(deserializationType).build())
                    .defaultValue("null"));
            configMethod.addContent(fieldName + " = " + CONFIGURE_PARAM + ".getDeserializer(new ")
                    .addContent(GenericType.class)
                    .addContent("<")
                    .addContent(deserializationType)
                    .addContentLine(">() {});");
            valueWritingMethod(jsonProperty, method, hasCreator, fieldName);
        } else {
            String converterFieldName = "deserializer" + ensureUpperStart(deserializationType);
            if (!processedTypes.contains(deserializationType)) {
                //Deserializer for this type has not been created yet.
                processedTypes.add(deserializationType); //To ensure deserializer reusability
                classBuilder.addField(builder -> builder.name(converterFieldName)
                        .type(TypeName.builder(Types.JSON_DESERIALIZER_TYPE).addTypeArgument(deserializationType).build())
                        .defaultValue("null"));
                String configLine = converterFieldName + " = "
                        + CONFIGURE_PARAM + ".getDeserializer(" + deserializationType.resolvedName() + ".class);";
                configMethod.addContentLine(configLine);
            }
            valueWritingMethod(jsonProperty, method, hasCreator, converterFieldName);
        }
    }

    private static void addUserDeserializer(JsonProperty property,
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
                    .map(methodName -> "generatedInstance." + methodName + "(" + reference + ".fromJson(parser));")
                    .orElseGet(() -> property.fieldName()
                            .filter(it -> property.directFieldAccess())
                            .map(fieldName -> "generatedInstance." + fieldName + " = " + reference + ".fromJson(parser);")
                            .orElseThrow());
            method.addContentLine(writingMethod);
        }
        method.addContentLine("break;");
    }

    private static String ensureUpperStart(TypeName typeName) {
        String str = typeName.className().replaceAll("\\[]", "Array");
        return ensureUpperStart(str);
    }

    private static String ensureUpperStart(String str) {
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
