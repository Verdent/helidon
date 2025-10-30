package io.helidon.json.codegen;

import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import io.helidon.codegen.classmodel.Annotation;
import io.helidon.codegen.classmodel.ClassBase;
import io.helidon.codegen.classmodel.Executable;
import io.helidon.codegen.classmodel.Method;
import io.helidon.common.types.ElementKind;
import io.helidon.common.types.TypeInfo;
import io.helidon.common.types.TypeName;
import io.helidon.common.types.TypeNames;

import static java.util.function.Predicate.not;

import static io.helidon.json.codegen.ConvertedTypeInfo.needsResolving;
import static io.helidon.json.codegen.Types.PRIMITIVE_TO_BOXED;

class JsonConverterGenerator {

    static final String CONFIGURE_PARAM = "jsonBindingConfigurer";
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
    private static final String WRITE_NULLS = "writeNulls";

    private JsonConverterGenerator() {
    }

    static void generateConverter(ClassBase.Builder<?, ?> classBuilder,
                                  ConvertedTypeInfo converterInfo,
                                  TypeInfo annotatedType,
                                  boolean factoryConfiguration,
                                  boolean typedConverter) {
        TypeName converterInterfaceType = TypeName.builder()
                .from(typedConverter ? Types.TYPED_JSON_CONVERTER_TYPE : Types.JSON_FACTORY_CONVERTER_TYPE)
                .addTypeArgument(annotatedType.typeName())
                .build();

        Map<String, TypeToConfigure> toConfigure = new HashMap<>();
        classBuilder.name(converterInfo.converterType().className())
                .addInterface(converterInterfaceType)
                .addMethod(method -> generateToJsonMethod(classBuilder,
                                                          method,
                                                          converterInfo,
                                                          factoryConfiguration,
                                                          toConfigure))
                .addMethod(method -> generateFromJsonMethod(classBuilder,
                                                            method,
                                                            converterInfo,
                                                            factoryConfiguration,
                                                            toConfigure));

        if (factoryConfiguration) {
            classBuilder.addMethod(method -> addConfigurationFactory(method, toConfigure));
        } else {
            classBuilder.addInterface(Types.JSON_CONFIGURABLE)
                    .addMethod(method -> addConfigurationMethod(method, toConfigure));
        }
        if (typedConverter) {
            classBuilder.addMethod(method -> addTypeMethod(method, converterInfo));
        }
    }

    private static void addConfigurationMethod(Method.Builder method, Map<String, TypeToConfigure> toConfigure) {
        method.name("configure")
                .addAnnotation(Annotation.create(Override.class))
                .addParameter(param -> param.type(Types.JSON_BINDING_CONFIGURER).name(CONFIGURE_PARAM));

        initializeNoRuntimeResolving(method, toConfigure);
    }

    private static void addConfigurationFactory(Method.Builder method, Map<String, TypeToConfigure> toConfigure) {
        method.name("configure")
                .addAnnotation(Annotation.create(Override.class))
                .addParameter(builder -> builder.type(Types.JSON_BINDING_CONFIGURER).name(CONFIGURE_PARAM))
                .addParameter(builder -> builder.type(Types.JSON_CONTEXT).name("jsonContext"));

        initializeNoRuntimeResolving(method, toConfigure);

        List<TypeToConfigure> needsRuntimeResolving = toConfigure.values()
                .stream()
                .filter(it -> needsResolving(it.resolved))
                .toList();

        method.addContent("if (type instanceof ")
                .addContent(ParameterizedType.class)
                .addContentLine(" parameterizedType) {");

        Map<String, Consumer<Method.Builder>> createdTypeSetters = new HashMap<>();
        MethodNameCounter counter = new MethodNameCounter();
        for (TypeToConfigure typeToConfigure : needsRuntimeResolving) {
            String fieldName = typeToConfigure.fieldName();
            TypeName typeName = typeToConfigure.resolved;
            String obtainMethod = typeToConfigure.mode.method;
            if (typeName.typeArguments().isEmpty()) {
                method.addContent(fieldName + " = " + CONFIGURE_PARAM + "." + obtainMethod + "(")
                        .addContentLine("parameterizedType.getActualTypeArguments()[0]);");
            } else {
                Consumer<Method.Builder> builderConsumer;
                if (createdTypeSetters.containsKey(typeName.resolvedName())) {
                    builderConsumer = createdTypeSetters.get(typeName.resolvedName());
                } else {
                    builderConsumer = constructComplexGenericType(method, typeName, createdTypeSetters, counter);
                    createdTypeSetters.put(typeName.resolvedName(), builderConsumer);
                }
                method.addContent(fieldName + " = " + CONFIGURE_PARAM + "." + obtainMethod + "(");
                builderConsumer.accept(method);
                method.addContentLine(");");
            }
        }
        method.addContent("}").addContentLine(" else {");
        for (TypeToConfigure typeToConfigure : needsRuntimeResolving) {
            String fieldName = typeToConfigure.fieldName();
            TypeName typeName = typeToConfigure.resolved;
            String obtainMethod = typeToConfigure.mode.method;
            if (typeName.typeArguments().isEmpty()) {
                method.addContent(fieldName + " = (")
                        .addContent(typeToConfigure.fieldType)
                        .addContent(") " + CONFIGURE_PARAM + "." + obtainMethod + "(")
                        .addContent(Object.class)
                        .addContentLine(".class);");
            } else {
                method.addContent(fieldName + " = " + CONFIGURE_PARAM + "." + obtainMethod + "(")
                        .addContent("new ").addContent(TypeNames.GENERIC_TYPE).addContent("<");
                buildSimpleGenericTypeWithObject(method, typeName);
                method.addContentLine(">() {});");
            }
        }
        method.addContentLine("}");
    }

    private static void buildSimpleGenericTypeWithObject(Method.Builder method, TypeName typeName) {
        if (typeName.typeArguments().isEmpty()) {
            //We have no more generics available
            if (needsResolving(typeName)) {
                method.addContent(Object.class);
            } else {
                method.addContent(typeName);
            }
        } else {
            boolean first = true;
            method.addContent(typeName.genericTypeName()).addContent("<");
            for (TypeName typeArgument : typeName.typeArguments()) {
                if (first) {
                    first = false;
                } else {
                    method.addContent(",");
                }
                buildSimpleGenericTypeWithObject(method, typeArgument);
            }
            method.addContent(">");
        }
    }

    private static Consumer<Method.Builder> constructComplexGenericType(Method.Builder method,
                                                                        TypeName typeName,
                                                                        Map<String, Consumer<Method.Builder>> createdTypeSetters,
                                                                        MethodNameCounter counter) {
        if (typeName.typeArguments().isEmpty()) {
            if (needsResolving(typeName)) {
                return builder -> builder.addContent(TypeNames.GENERIC_TYPE)
                                .addContent(".create(parameterizedType.getActualTypeArguments()[0])");
            } else {
                return builder -> builder.addContent(TypeNames.GENERIC_TYPE)
                        .addContent(".create(").addContent(typeName).addContent(")");
            }
        } else {
            List<Consumer<Method.Builder>> parameterValueSetters = new ArrayList<>();
            for (TypeName typeArgument : typeName.typeArguments()) {
                if (createdTypeSetters.containsKey(typeArgument.resolvedName())) {
                    parameterValueSetters.add(createdTypeSetters.get(typeArgument.resolvedName()));
                } else {
                    Consumer<Method.Builder> parameterValue = constructComplexGenericType(method,
                                                                                          typeArgument,
                                                                                          createdTypeSetters,
                                                                                          counter);
                    parameterValueSetters.add(parameterValue);
                    createdTypeSetters.putIfAbsent(typeArgument.resolvedName(), parameterValue);
                }
            }
            String variableName = "genericType" + counter.count++;
            method.addContent("var " + variableName + " = ")
                    .addContent(TypeNames.GENERIC_TYPE)
                    .addContent(".<").addContent(TypeNames.OBJECT).addContentLine(">builder()")
                    .increaseContentPadding()
                    .increaseContentPadding()
                    .addContent(".baseType(").addContent(typeName.genericTypeName()).addContentLine(".class)");
            for (Consumer<Method.Builder> parameterValue : parameterValueSetters) {
                method.addContent(".addGenericParameter(");
                parameterValue.accept(method);
                method.addContentLine(")");
            }
            method.addContentLine(".build();")
                    .decreaseContentPadding()
                    .decreaseContentPadding();

            return builder -> builder.addContent(variableName);
        }
    }

    private static void initializeNoRuntimeResolving(Executable.Builder<?, ?> method, Map<String, TypeToConfigure> toConfigure) {
        List<TypeToConfigure> doNotNeedRuntimeResolving = toConfigure.values()
                .stream()
                .filter(not(it -> needsResolving(it.resolved)))
                .toList();

        for (TypeToConfigure typeToConfigure : doNotNeedRuntimeResolving) {
            TypeName typeName = typeToConfigure.original;
            String fieldName = typeToConfigure.fieldName();
            String obtainMethod = typeToConfigure.mode.method;
            if (typeName.typeArguments().isEmpty()) {
                method.addContent(fieldName + " = " + CONFIGURE_PARAM + "." + obtainMethod + "(")
                        .addContent(typeName)
                        .addContentLine(".class);");
            } else {
                method.addContent(fieldName + " = " + CONFIGURE_PARAM + "." + obtainMethod + "(new ")
                        .addContent(TypeNames.GENERIC_TYPE)
                        .addContent("<")
                        .addContent(typeName)
                        .addContentLine(">() {});");
            }
        }
    }

    private static void generateToJsonMethod(ClassBase.Builder<?, ?> classBuilder,
                                             Method.Builder method,
                                             ConvertedTypeInfo converterInfo,
                                             boolean useConstructorToConfigure,
                                             Map<String, TypeToConfigure> toConfigure) {
        method.name("serialize")
                .addParameter(param -> param.name("generator").type(Types.JSON_GENERATOR))
                .addParameter(param -> param.name("instance").type(converterInfo.originalType()))
                .addParameter(param -> param.name(WRITE_NULLS).type(boolean.class))
                .addAnnotation(Annotation.create(Override.class))
                .addContentLine("generator.writeObjectStart();");
        List<JsonProperty> jsonProperties = converterInfo.jsonProperties()
                .values()
                .stream()
                .filter(not(JsonProperty::propertyIgnored))
                .filter(it -> !it.getterIgnored() || it.directFieldAccess())
                .sorted((o1, o2) -> converterInfo.orderedProperties()
                        .compare(o1.serializationName().orElseThrow(),
                                 o2.serializationName().orElseThrow()))
                .toList();

        Set<String> createdSerializers = new HashSet<>();
        boolean first = true;
        for (JsonProperty jsonProperty : jsonProperties) {
            if (first) {
                method.addContentLine("boolean isFirst = true;");
                first = false;
            }
            method.addContent("isFirst = ");

            String fieldName = jsonProperty.serializer()
                    .map(serializer -> {
                        String constantName = constantName(jsonProperty.serializationName().orElseThrow()) + "_SERIALIZER";
                        classBuilder.addField(field -> field.name(constantName)
                                .type(serializer)
                                .isStatic(true)
                                .isFinal(true)
                                .addContent("new ").addContent(serializer).addContent("()"));
                        return constantName;
                    })
                    .orElseGet(() -> {
                        TypeName type = jsonProperty.serializationType().orElseThrow();
                        TypeName resolved = PRIMITIVE_TO_BOXED.getOrDefault(type, type);
                        String fn;
                        if (!resolved.typeArguments().isEmpty()) {
                            fn = "serializer" + ensureUpperStart(jsonProperty.serializationName().orElseThrow());
                        } else {
                            fn = "serializer" + ensureUpperStart(type);
                        }
                        if (!createdSerializers.contains(fn)) {
                            createdSerializers.add(fn);
                            TypeName converterType = TypeName.builder()
                                    .from(Types.JSON_SERIALIZER_TYPE)
                                    .addTypeArgument(resolved)
                                    .build();
                            classBuilder.addField(fieldBuilder -> fieldBuilder.name(fn)
                                    .isVolatile(true)
                                    .type(converterType));
                            toConfigure.putIfAbsent(fn,
                                                    new TypeToConfigure(TypeConfigMode.SERIALIZATION,
                                                                        fn,
                                                                        resolved,
                                                                        type,
                                                                        converterType));
                        }
                        return fn;
                    });

            String accessor = jsonProperty.getterName()
                    .filter(getterName -> !jsonProperty.getterIgnored())
                    .map(getterName -> getterName + "()")
                    .or(jsonProperty::fieldName)
                    .orElseThrow();

            String key = jsonProperty.serializationName().orElseThrow();
            method.addContent(Types.JSON_SERIALIZERS)
                    .addContentLine(".serialize(generator, " + fieldName + ", "
                                            + "instance." + accessor + ", "
                                            + "\"" + key + "\", "
                                            + "isFirst, "
                                            + jsonProperty.nullable() + ");");
        }
        method.addContentLine("generator.writeObjectEnd();");
    }

    private static void generateFromJsonMethod(ClassBase.Builder<?, ?> classBuilder,
                                               Method.Builder method,
                                               ConvertedTypeInfo converterInfo,
                                               boolean useConstructorToConfigure,
                                               Map<String, TypeToConfigure> toConfigure) {
        CreatorInfo creatorInfo = converterInfo.creatorInfo();
        ElementKind creatorKind = creatorInfo.creatorKind();
        boolean hasCreator = creatorKind != null && !creatorInfo.parameters().isEmpty();
        List<JsonProperty> jsonProperties = converterInfo.jsonProperties()
                .values()
                .stream()
                .filter(not(JsonProperty::propertyIgnored))
                .filter(it -> !it.setterIgnored() || it.directFieldAccess())
                .toList();

        method.name("deserialize")
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
        } else if (creatorKind == ElementKind.METHOD) {
            TypeName originalType = converterInfo.originalType();
            method.addContent(originalType).addContent(" generatedInstance = ")
                    .addContent(originalType).addContent("." + creatorInfo.method() + "();");
        } else {
            TypeName originalType = converterInfo.originalType();
            method.addContent(originalType).addContent(" generatedInstance = new ")
                    .addContent(originalType).addContentLine("();");
        }
        method.addContentLine("if (lastByte != '}') {")
                .addContentLine("while(true) {")
                .addContentLine("if (lastByte != '\"') {")
                .addContent("throw new ").addContent(Types.JSON_EXCEPTION)
                .addContent("(\"Key start expected. Found: \" + ")
                .addContent(Character.class).addContentLine(".toString(lastByte));")
                .addContentLine("}")
                .addContent(int.class).addContentLine(" hash = parser.readStringAsHash();")
                .addContentLine("lastByte = parser.nextToken();")
                .addContentLine("if (lastByte != ':') {")
                .addContent("throw new ").addContent(Types.JSON_EXCEPTION)
                .addContent("(\"Colon expected. Found: \" + ")
                .addContent(Character.class).addContentLine(".toString(lastByte));")
                .addContentLine("}")
                .addContentLine("parser.nextToken();")
                .addContentLine("switch(hash) {");
        Map<Integer, List<JsonProperty>> hashes = jsonProperties.stream()
                .collect(Collectors.groupingBy(jsonProperty ->
                                                       calculateNameHash(jsonProperty.deserializationName().orElseThrow())));
        Set<String> processedTypes = new HashSet<>(); //Used to identify already configured type deserializers
        for (Map.Entry<Integer, List<JsonProperty>> entry : hashes.entrySet()) {
            if (entry.getValue().size() > 1) {
                throw new UnsupportedOperationException("Naming collision, not implemented yet");
            } else {
                JsonProperty jsonProperty = entry.getValue().getFirst();
                String constantName = constantName(jsonProperty.deserializationName().orElseThrow());
                classBuilder.addField(builder -> builder.isFinal(true)
                        .isStatic(true)
                        .type(int.class)
                        .name(constantName)
                        .defaultValue(String.valueOf(entry.getKey())));
                method.addContentLine("case " + constantName + ":");
                method.increaseContentPadding();
                addTypeHandling(jsonProperty,
                                method,
                                classBuilder,
                                hasCreator,
                                processedTypes,
                                useConstructorToConfigure,
                                toConfigure);
                method.decreaseContentPadding();
            }
        }
        method.addContentLine("default:")
                .padContent().addContentLine("parser.skip();");
        method.addContentLine("}")
                .addContentLine("lastByte = parser.nextToken();")
                .addContentLine("if (lastByte == ',') {")
                .addContentLine("lastByte = parser.nextToken();")
                .addContentLine("continue;")
                .decreaseContentPadding()
                .addContentLine("} else if (lastByte == '}') {")
                .addContentLine("break;")
                .decreaseContentPadding()
                .addContentLine("} else {")
                .addContent("throw new ").addContent(Types.JSON_EXCEPTION)
                .addContent("(\"Comma or end of object expected. Found: \" + ")
                .addContent(Character.class).addContentLine(".toString(lastByte));")
                .addContentLine("}")
                .addContentLine("}");
        method.addContentLine("}");
        if (hasCreator) {
            TypeName originalType = converterInfo.originalType();
            if (creatorKind == ElementKind.METHOD) {
                method.addContent(originalType).addContent(" generatedInstance = ")
                        .addContent(originalType).addContent("." + creatorInfo.method() + "(");
            } else {
                method.addContent(originalType).addContent(" generatedInstance = new ")
                        .addContent(originalType).addContent("(");
            }
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

    private static String constantName(String propertyName) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < propertyName.length(); i++) {
            char c = propertyName.charAt(i);
            if (Character.isUpperCase(c)) {
                result.append('_');
            }
            result.append(Character.toUpperCase(c));
        }
        return result.toString();
    }

    private static void addTypeMethod(Method.Builder method, ConvertedTypeInfo converterInfo) {
        method.name("type")
                .returnType(builder -> builder.type(TypeName.builder()
                                                            .from(TypeNames.GENERIC_TYPE)
                                                            .addTypeArgument(converterInfo.originalType())
                                                            .build()))
                .addAnnotation(Annotation.create(Override.class))
                .addContent("return ")
                .addContent(TypeNames.GENERIC_TYPE)
                .addContent(".create(")
                .addContent(converterInfo.originalType())
                .addContentLine(".class);");
    }

    private static void addTypeHandling(JsonProperty jsonProperty,
                                        Method.Builder method,
                                        ClassBase.Builder<?, ?> classBuilder,
                                        boolean hasCreator,
                                        Set<String> processedTypes,
                                        boolean useConstructorToConfigure,
                                        Map<String, TypeToConfigure> toConfigure) {
        jsonProperty.deserializer()
                .ifPresentOrElse(deserializer -> addUserDeserializer(jsonProperty,
                                                                     deserializer,
                                                                     method,
                                                                     classBuilder,
                                                                     hasCreator),
                                 () -> {
                                     TypeName type = jsonProperty.deserializationType().orElseThrow();
                                     createTypeDeserializer(jsonProperty,
                                                            type,
                                                            method,
                                                            classBuilder,
                                                            hasCreator,
                                                            processedTypes,
                                                            useConstructorToConfigure,
                                                            toConfigure);
                                 });
    }

    private static void createTypeDeserializer(JsonProperty jsonProperty,
                                               TypeName type,
                                               Method.Builder method,
                                               ClassBase.Builder<?, ?> classBuilder,
                                               boolean hasCreator,
                                               Set<String> processedTypes,
                                               boolean useConstructorToConfigure,
                                               Map<String, TypeToConfigure> toConfigure) {
        TypeName resolvedType = PRIMITIVE_TO_BOXED.getOrDefault(type, type);
        if (!type.typeArguments().isEmpty()) {
            //Type contains generics
            String fieldName = "deserializer" + ensureUpperStart(jsonProperty.deserializationName().orElseThrow());
            TypeName fieldType = TypeName.builder(Types.JSON_DESERIALIZER_TYPE).addTypeArgument(resolvedType).build();
            classBuilder.addField(builder -> builder.name(fieldName)
                    .isVolatile(true)
                    .type(fieldType));
            toConfigure.putIfAbsent(fieldName, new TypeToConfigure(TypeConfigMode.DESERIALIZATION,
                                                                   fieldName,
                                                                   resolvedType,
                                                                   type,
                                                                   fieldType));
            valueWritingMethod(jsonProperty, method, hasCreator, fieldName);
        } else {
            String converterFieldName = "deserializer" + ensureUpperStart(type);
            if (!processedTypes.contains(converterFieldName)) {
                //Deserializer for this type has not been created yet.
                processedTypes.add(converterFieldName); //To ensure deserializer reusability
                TypeName fieldType = TypeName.builder(Types.JSON_DESERIALIZER_TYPE).addTypeArgument(resolvedType).build();
                classBuilder.addField(builder -> builder.name(converterFieldName)
                        .isVolatile(true)
                        .type(fieldType));
                toConfigure.putIfAbsent(converterFieldName, new TypeToConfigure(TypeConfigMode.DESERIALIZATION,
                                                                                converterFieldName,
                                                                                resolvedType,
                                                                                type,
                                                                                fieldType));
            }
            valueWritingMethod(jsonProperty, method, hasCreator, converterFieldName);
        }
    }

    private static void addUserDeserializer(JsonProperty property,
                                            TypeName deserializer,
                                            Method.Builder method,
                                            ClassBase.Builder<?, ?> classBuilder,
                                            boolean hasCreator) {
        String constantName = constantName(property.deserializationName().orElseThrow()) + "_DESERIALIZER";
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
            method.addContent(property.deserializationName().orElseThrow() + PROPERTY_NAME_SUFFIX + " = ")
                    .addContentLine("parser.checkNull() ? " + reference + ".deserializeNull() : "
                                            + reference + ".deserialize(parser);");
        } else {
            String writingMethod = property.setterName()
                    .map(methodName -> "generatedInstance." + methodName
                            + "(parser.checkNull() ? " + reference + ".deserializeNull() : "
                            + reference + ".deserialize(parser));")
                    .orElseGet(() -> property.fieldName()
                            .filter(it -> property.directFieldAccess())
                            .map(fieldName -> "generatedInstance." + fieldName
                                    + " = parser.checkNull() ? " + reference + ".deserializeNull() : "
                                    + reference + ".deserialize(parser);")
                            .orElseThrow());
            method.addContentLine(writingMethod);
        }
        method.addContentLine("break;");
    }

    private static String ensureUpperStart(TypeName typeName) {
        String className = typeName.toString();
        int index = className.lastIndexOf(".");
        if (index > -1) {
            className = className.substring(index + 1);
        }
        return ensureUpperStart(className.replaceAll("\\[]", "Array"));
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

    private static int calculateNameHash(String name) {
        long fnvHash = 2166136261L;
        byte[] array = name.getBytes(StandardCharsets.UTF_8);
        for (byte b : array) {
            fnvHash ^= b;
            fnvHash *= 16777619;
        }
        return (int) fnvHash;
    }

    private record TypeToConfigure(TypeConfigMode mode,
                                   String fieldName,
                                   TypeName resolved,
                                   TypeName original,
                                   TypeName fieldType) {
    }

    private enum TypeConfigMode {
        SERIALIZATION("getSerializer"),
        DESERIALIZATION("getDeserializer");

        private final String method;

        TypeConfigMode(String method) {
            this.method = method;
        }
    }

    private static final class MethodNameCounter {

        private int count = 0;

    }

}
