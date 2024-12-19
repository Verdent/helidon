package io.helidon.json.codegen;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import io.helidon.codegen.CodegenContext;
import io.helidon.codegen.ElementInfoPredicates;
import io.helidon.common.types.AccessModifier;
import io.helidon.common.types.ElementKind;
import io.helidon.common.types.Modifier;
import io.helidon.common.types.TypeInfo;
import io.helidon.common.types.TypeName;
import io.helidon.common.types.TypedElementInfo;

import static java.util.function.Predicate.not;

import static io.helidon.common.types.TypeNames.OBJECT;
import static io.helidon.common.types.TypeNames.PRIMITIVE_BOOLEAN;
import static io.helidon.common.types.TypeNames.PRIMITIVE_INT;
import static io.helidon.common.types.TypeNames.PRIMITIVE_VOID;
import static io.helidon.common.types.TypeNames.STRING;

record ConvertedTypeInfo(TypeName converterType,
                         TypeName originalType,
                         Map<String, JsonProperty> jsonProperties,
                         CreatorInfo creatorInfo) {

    private static final Set<MethodSignature> IGNORED_METHODS = Set.of(
            // equals, hash code and toString
            new MethodSignature(PRIMITIVE_BOOLEAN, "equals", List.of(OBJECT)),
            new MethodSignature(PRIMITIVE_INT, "hashCode", List.of()),
            new MethodSignature(STRING, "toString", List.of())
    );

    public static ConvertedTypeInfo create(TypeInfo typeInfo) {
        TypeName converterTypeName = TypeName.create(typeInfo.typeName().fqName() + "_GeneratedConverter");
        boolean recordAccessors = typeInfo.annotation(Types.JSON_AS_JSON)
                .booleanValue("recordAccessors")
                .orElse(false);
        if (typeInfo.kind() == ElementKind.RECORD) {
            recordAccessors = true;
        }
        Map<String, JsonProperty.Builder> properties = new LinkedHashMap<>();
        discoverFields(properties, typeInfo);
        discoverGetAndSetMethods(properties, typeInfo, recordAccessors);
        CreatorInfo creatorInfo = discoverCreator(properties, typeInfo);
        Map<String, JsonProperty> jsonProperties = finalizeJsonProperties(properties);
        return new ConvertedTypeInfo(converterTypeName, typeInfo.typeName(), jsonProperties, creatorInfo);
    }

    private static void discoverFields(Map<String, JsonProperty.Builder> properties, TypeInfo typeInfo) {
        typeInfo.superTypeInfo()
                .ifPresent(superType -> discoverFields(properties, superType));

        List<TypedElementInfo> fields = typeInfo.elementInfo()
                .stream()
                .filter(ElementInfoPredicates::isField)
                .filter(not(ElementInfoPredicates::isStatic))
                .toList();

        for (TypedElementInfo field : fields) {
            String fieldName = field.elementName();
            TypeName fieldType = resolveGenerics(field.typeName(), typeInfo);
            JsonProperty.Builder builder = JsonProperty.builder()
                    .fieldName(fieldName)
                    .deserializationName(fieldName)
                    .serializationName(fieldName)
                    .deserializationType(fieldType)
                    .serializationType(fieldType)
                    .directFieldAccess(field.accessModifier() != AccessModifier.PRIVATE);

            obtainStringFromAnnotation(field, Types.JSON_PROPERTY, "value")
                    .ifPresent(value -> builder.serializationName(value).deserializationName(value));
            obtainTypeNameFromAnnotation(field, Types.JSON_CONVERTER, "value")
                    .ifPresent(value -> builder.serializer(value).deserializer(value));
            obtainTypeNameFromAnnotation(field, Types.JSON_SERIALIZER, "value")
                    .ifPresent(builder::serializer);
            obtainTypeNameFromAnnotation(field, Types.JSON_DESERIALIZER, "value")
                    .ifPresent(builder::deserializer);
            field.findAnnotation(Types.JSON_IGNORE)
                    .ifPresent(annotation -> builder.propertyIgnored(true));

            properties.put(fieldName, builder);
        }
    }

    private static void discoverGetAndSetMethods(Map<String, JsonProperty.Builder> properties,
                                                 TypeInfo typeInfo,
                                                 boolean record) {
        typeInfo.superTypeInfo()
                .ifPresent(superType -> discoverGetAndSetMethods(properties, superType, record));

        List<TypedElementInfo> methods = typeInfo.elementInfo()
                .stream()
                .filter(ElementInfoPredicates::isMethod)
                .filter(not(ElementInfoPredicates::isPrivate))
                .filter(not(ElementInfoPredicates::isStatic))
                .filter(not(ConvertedTypeInfo::isIgnored))
                .toList();
        for (TypedElementInfo method : methods) {
            String methodName = method.elementName();
            if (isGetter(method, record)) {
                String prefix = record ? "" : (method.typeName().equals(PRIMITIVE_BOOLEAN) ? "is" : "get");
                String propertyName = methodToFieldName(prefix, methodName, record);
                properties.computeIfAbsent(propertyName, name -> JsonProperty.builder())
                        .getterName(methodName)
                        .deserializationName(propertyName)
                        .deserializationType(resolveGenerics(method.typeName(), typeInfo))
                        .deserializationName(obtainStringFromAnnotation(method, Types.JSON_PROPERTY, "value"))
                        .deserializer(obtainTypeNameFromAnnotation(method, Types.JSON_CONVERTER, "value"))
                        .deserializer(obtainTypeNameFromAnnotation(method, Types.JSON_DESERIALIZER, "value"))
                        .getterIgnored(method.hasAnnotation(Types.JSON_IGNORE));
            } else if (typeInfo.kind() != ElementKind.RECORD && isSetter(method, record)) {
                String prefix = record ? "" : "set"; //setter style getters in regular classes
                String propertyName = methodToFieldName(prefix, methodName, record);
                properties.computeIfAbsent(propertyName, name -> JsonProperty.builder())
                        .setterName(methodName)
                        .serializationName(propertyName)
                        .serializationType(resolveGenerics(method.parameterArguments().getFirst().typeName(), typeInfo))
                        .serializationName(obtainStringFromAnnotation(method, Types.JSON_PROPERTY, "value"))
                        .serializer(obtainTypeNameFromAnnotation(method, Types.JSON_CONVERTER, "value"))
                        .serializer(obtainTypeNameFromAnnotation(method, Types.JSON_SERIALIZER, "value"))
                        .setterIgnored(method.hasAnnotation(Types.JSON_IGNORE));
            }
            //Not valid getter or setter
        }

    }

    private static CreatorInfo discoverCreator(Map<String, JsonProperty.Builder> properties, TypeInfo typeInfo) {
        List<TypedElementInfo> creators = typeInfo.elementInfo()
                .stream()
                .filter(info -> info.hasAnnotation(Types.JSON_CREATOR))
                .toList();
        if (creators.isEmpty()) {
            if (typeInfo.kind() == ElementKind.RECORD) {
                //Handle record constructor as creator if none is explicitly selected
                creators = typeInfo.elementInfo()
                        .stream()
                        .filter(ElementInfoPredicates::isConstructor)
                        .toList();
                if (creators.size() > 1) {
                    throw new IllegalStateException("Only one record constructor is allowed. "
                                                            + "If multiple is needed, one has to be annotated with "
                                                            + Types.JSON_CREATOR); //TODO UPRAVIT ne exceptiona
                }
            } else {
                return new CreatorInfo(ElementKind.CONSTRUCTOR, "", List.of());
            }
        } else if (creators.size() > 1) {
            throw new IllegalStateException("Only one Creator is allowed to be set"); //TODO UPRAVIT ne exceptiona
        }
        TypedElementInfo creator = creators.getFirst();
        ElementKind creatorKind = creator.kind();
        if (creatorKind == ElementKind.METHOD && !creator.elementModifiers().contains(Modifier.STATIC)) {
            throw new IllegalStateException("Creator has to be either on constructor or static method"); //TODO UPRAVIT ne exceptiona
        } else if (creator.accessModifier() == AccessModifier.PRIVATE) {
            throw new IllegalStateException("Creator has to be non-private"); //TODO UPRAVIT ne exceptiona
        }
        String creatorMethod = creator.elementName();
        List<String> parameterNames = new ArrayList<>();
        for (TypedElementInfo parameter : creator.parameterArguments()) {
            String parameterName = parameter.elementName();
            parameterNames.add(parameterName);
            properties.computeIfAbsent(parameterName, name -> JsonProperty.builder())
                    .usedInCreator(true)
                    .deserializationName(parameterName)
                    .deserializationType(resolveGenerics(parameter.typeName(), typeInfo))
                    .deserializationName(obtainStringFromAnnotation(parameter, Types.JSON_PROPERTY, "value"))
                    .deserializer(obtainTypeNameFromAnnotation(parameter, Types.JSON_CONVERTER, "value"))
                    .deserializer(obtainTypeNameFromAnnotation(parameter, Types.JSON_DESERIALIZER, "value"));
        }
        return new CreatorInfo(creatorKind, creatorMethod, parameterNames);
    }

    private static TypeName resolveGenerics(TypeName elementTypeName, TypeInfo typeInfo) {
        if (needsResolving(elementTypeName)) {
            if (elementTypeName.generic()) {
                int index = typeInfo.typeName().typeParameters().indexOf(elementTypeName.className());
                return typeInfo.typeName().typeArguments().get(index);
            }
            TypeName.Builder builder = TypeName.builder()
                    .from(elementTypeName)
                    .typeArguments(List.of());
            elementTypeName.typeArguments().forEach(arg -> builder.addTypeArgument(resolveGenerics(arg, typeInfo)));
            return builder.build();
        }
        return elementTypeName;
    }

    private static boolean needsResolving(TypeName typeName) {
        for (TypeName typeArgument : typeName.typeArguments()) {
            if (needsResolving(typeArgument)) {
                return true;
            }
        }
        return typeName.generic();
    }

    private static boolean isGetter(TypedElementInfo typedElementInfo, boolean recordStyle) {
        if (recordStyle) {
            return typedElementInfo.parameterArguments().isEmpty()
                    && !typedElementInfo.typeName().equals(PRIMITIVE_VOID);
        }
        String methodName = typedElementInfo.elementName();
        int length = -1;
        if (methodName.startsWith("get")) {
            length = 3;
        } else if (methodName.startsWith("is")) {
            length = 2;
        }
        return length > -1
                && methodName.length() > length
                && Character.isUpperCase(methodName.charAt(length))
                && typedElementInfo.parameterArguments().isEmpty()
                && !typedElementInfo.typeName().equals(PRIMITIVE_VOID);
    }

    private static boolean isSetter(TypedElementInfo typedElementInfo, boolean recordStyle) {
        if (recordStyle) {
            return typedElementInfo.parameterArguments().size() == 1
                    && typedElementInfo.typeName().equals(PRIMITIVE_VOID);
        }
        String methodName = typedElementInfo.elementName();
        return methodName.startsWith("set")
                && methodName.length() > 3
                && Character.isUpperCase(methodName.charAt(3))
                && typedElementInfo.parameterArguments().size() == 1
                && typedElementInfo.typeName().equals(PRIMITIVE_VOID);
    }

    private static String methodToFieldName(String prefix, String methodName, boolean record) {
        if (methodName.startsWith(prefix)) {
            String str = methodName.substring(prefix.length());
            if (str.isEmpty()) {
                return methodName;
            } else if (Character.isLowerCase(str.charAt(0)) && !record) {
                throw new IllegalStateException(methodName + " is not valid getter or setter method");
            } else if (str.length() == 1) {
                return str.toLowerCase();
            } else {
                return Character.toLowerCase(str.charAt(0)) + str.substring(1);
            }
        }
        return methodName;
    }

    private static boolean isIgnored(TypedElementInfo elementInfo) {
        return IGNORED_METHODS.contains(MethodSignature.create(elementInfo));
    }

    private static Optional<String> obtainStringFromAnnotation(TypedElementInfo elementInfo,
                                                               TypeName annotationType,
                                                               String attributeName) {
        return elementInfo.findAnnotation(annotationType)
                .flatMap(annotation -> annotation.stringValue(attributeName));
    }

    private static Optional<TypeName> obtainTypeNameFromAnnotation(TypedElementInfo elementInfo,
                                                                   TypeName annotationType,
                                                                   String attributeName) {
        return elementInfo.findAnnotation(annotationType)
                .flatMap(annotation -> annotation.typeValue(attributeName));
    }

    private static Map<String, JsonProperty> finalizeJsonProperties(Map<String, JsonProperty.Builder> properties) {
        Map<String, JsonProperty> finalProperties = new LinkedHashMap<>(properties.size());
        for (Map.Entry<String, JsonProperty.Builder> entry : properties.entrySet()) {
            finalProperties.put(entry.getKey(), entry.getValue().build());
        }
        return finalProperties;
    }

}
