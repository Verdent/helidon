package io.helidon.jsonschema.generator;

import java.util.List;
import java.util.Map;
import java.util.Set;

import io.helidon.codegen.CodegenContext;
import io.helidon.codegen.ElementInfoPredicates;
import io.helidon.common.types.Annotated;
import io.helidon.common.types.TypeInfo;
import io.helidon.common.types.TypeName;
import io.helidon.common.types.TypeNames;
import io.helidon.common.types.TypedElementInfo;
import io.helidon.jsonschema.schema.Schema;
import io.helidon.jsonschema.schema.SchemaArray;
import io.helidon.jsonschema.schema.SchemaInteger;
import io.helidon.jsonschema.schema.SchemaItem;
import io.helidon.jsonschema.schema.SchemaNumber;
import io.helidon.jsonschema.schema.SchemaObject;
import io.helidon.jsonschema.schema.SchemaString;

import static java.util.function.Predicate.not;

import static io.helidon.common.types.TypeNames.BOXED_BOOLEAN;
import static io.helidon.common.types.TypeNames.BOXED_BYTE;
import static io.helidon.common.types.TypeNames.BOXED_CHAR;
import static io.helidon.common.types.TypeNames.BOXED_DOUBLE;
import static io.helidon.common.types.TypeNames.BOXED_FLOAT;
import static io.helidon.common.types.TypeNames.BOXED_INT;
import static io.helidon.common.types.TypeNames.BOXED_LONG;
import static io.helidon.common.types.TypeNames.BOXED_SHORT;
import static io.helidon.common.types.TypeNames.BOXED_VOID;
import static io.helidon.common.types.TypeNames.OBJECT;
import static io.helidon.common.types.TypeNames.PRIMITIVE_BOOLEAN;
import static io.helidon.common.types.TypeNames.PRIMITIVE_BYTE;
import static io.helidon.common.types.TypeNames.PRIMITIVE_CHAR;
import static io.helidon.common.types.TypeNames.PRIMITIVE_DOUBLE;
import static io.helidon.common.types.TypeNames.PRIMITIVE_FLOAT;
import static io.helidon.common.types.TypeNames.PRIMITIVE_INT;
import static io.helidon.common.types.TypeNames.PRIMITIVE_LONG;
import static io.helidon.common.types.TypeNames.PRIMITIVE_SHORT;
import static io.helidon.common.types.TypeNames.PRIMITIVE_VOID;

record SchemaInfo(TypeName generatedSchema, Schema schema) {

    private static final Map<TypeName, TypeName> BOXED_TO_PRIMITIVE = Map.of(
            BOXED_BOOLEAN, PRIMITIVE_BOOLEAN,
            BOXED_BYTE, PRIMITIVE_BYTE,
            BOXED_SHORT, PRIMITIVE_SHORT,
            BOXED_INT, PRIMITIVE_INT,
            BOXED_LONG, PRIMITIVE_LONG,
            BOXED_CHAR, PRIMITIVE_CHAR,
            BOXED_FLOAT, PRIMITIVE_FLOAT,
            BOXED_DOUBLE, PRIMITIVE_DOUBLE,
            BOXED_VOID, PRIMITIVE_VOID
    );

    private static final Set<TypeName> INTEGERS = Set.of(PRIMITIVE_BYTE,
                                                         PRIMITIVE_SHORT,
                                                         PRIMITIVE_INT,
                                                         PRIMITIVE_LONG,
                                                         Types.BIG_INTEGER);

    private static final Set<TypeName> NUMBERS = Set.of(PRIMITIVE_FLOAT,
                                                        PRIMITIVE_DOUBLE,
                                                        Types.BIG_DECIMAL,
                                                        Types.NUMBER);

    public static SchemaInfo create(TypeInfo annotatedType, CodegenContext ctx) {
        TypeName annotatedTypeName = annotatedType.typeName();
        TypeName generatedTypeName = TypeName.builder()
                .from(annotatedTypeName)
                .className(annotatedTypeName.className() + "__JsonSchema")
                .build();

        Schema.Builder builder = Schema.builder();
        builder.rootObject(objectBuilder -> processObject(objectBuilder, annotatedType, ctx));
        return new SchemaInfo(generatedTypeName, builder.build());
    }

    private static void processCommonAnnotations(SchemaItem.BuilderBase<?, ?> builderBase, Annotated annotatedType) {
        annotatedType.findAnnotation(Types.JSON_SCHEMA_TITLE)
                .flatMap(it -> it.stringValue())
                .ifPresent(builderBase::title);
        annotatedType.findAnnotation(Types.JSON_SCHEMA_DESCRIPTION)
                .flatMap(it -> it.stringValue())
                .ifPresent(builderBase::description);
        annotatedType.findAnnotation(Types.JSON_SCHEMA_REQUIRED).ifPresent(it -> builderBase.required(true));
    }

    private static void processIntegerAnnotations(SchemaInteger.Builder integerBuilder,
                                                  TypeName annotatedTypeName,
                                                  Annotated annotatedType) {
        processCommonAnnotations(integerBuilder, annotatedType);
        annotatedType.findAnnotation(Types.JSON_SCHEMA_INTEGER_MINIMUM)
                .flatMap(it -> it.longValue())
                .ifPresent(integerBuilder::minimum);
        annotatedType.findAnnotation(Types.JSON_SCHEMA_INTEGER_MAXIMUM)
                .flatMap(it -> it.longValue())
                .ifPresent(integerBuilder::maximum);
        annotatedType.findAnnotation(Types.JSON_SCHEMA_INTEGER_MULTIPLE_OF)
                .flatMap(it -> it.longValue())
                .ifPresent(integerBuilder::multipleOf);
        annotatedType.findAnnotation(Types.JSON_SCHEMA_INTEGER_EXCLUSIVE_MINIMUM)
                .flatMap(it -> it.longValue())
                .ifPresent(integerBuilder::exclusiveMinimum);
        annotatedType.findAnnotation(Types.JSON_SCHEMA_INTEGER_EXCLUSIVE_MAXIMUM)
                .flatMap(it -> it.longValue())
                .ifPresent(integerBuilder::exclusiveMaximum);
    }

    private static void processStringAnnotations(SchemaString.Builder builder, Annotated annotated) {
        processCommonAnnotations(builder, annotated);
        annotated.findAnnotation(Types.JSON_SCHEMA_STRING_MIN_LENGTH)
                .flatMap(it -> it.longValue())
                .ifPresent(builder::minLength);
        annotated.findAnnotation(Types.JSON_SCHEMA_STRING_MAX_LENGTH)
                .flatMap(it -> it.longValue())
                .ifPresent(builder::maxLength);
        annotated.findAnnotation(Types.JSON_SCHEMA_STRING_PATTERN)
                .flatMap(it -> it.stringValue())
                .ifPresent(builder::pattern);
    }

    private static void processObject(SchemaObject.Builder builder,
                                      TypeInfo annotatedType,
                                      CodegenContext ctx) {
        processObjectAnnotations(builder, annotatedType);
        List<TypedElementInfo> fields = annotatedType.elementInfo()
                .stream()
                .filter(ElementInfoPredicates::isField)
                .filter(not(ElementInfoPredicates::isStatic))
                .toList();

        for (TypedElementInfo field : fields) {
            if (field.hasAnnotation(Types.JSON_SCHEMA_IGNORE)
                    || field.hasAnnotation(Types.JSONB_TRANSIENT)) {
                continue;
            }
            processObjectElement(builder, ctx, field, field.typeName(), field.elementName());
        }

        List<TypedElementInfo> methods = annotatedType.elementInfo()
                .stream()
                .filter(ElementInfoPredicates::isMethod)
                .filter(not(ElementInfoPredicates::isPrivate))
                .filter(not(ElementInfoPredicates::isStatic))
                .toList();

        for (TypedElementInfo method : methods) {
            if (method.hasAnnotation(Types.JSON_SCHEMA_IGNORE)
                    || method.hasAnnotation(Types.JSONB_TRANSIENT)) {
                continue;
            }
            if (method.elementName().startsWith("set")) {
                String name = Character.toLowerCase(method.elementName().charAt(3))
                        + method.elementName().substring(4);
                TypedElementInfo parameter = method.parameterArguments().getFirst();
                processObjectElement(builder, ctx, method, parameter.typeName(), name);
            }
            processCommonAnnotations(builder, annotatedType);
        }
    }

    private static void processObjectElement(SchemaObject.Builder builder,
                                             CodegenContext ctx,
                                             TypedElementInfo element,
                                             TypeName elementTypeName,
                                             String name) {
        TypeName parameterTypeName = BOXED_TO_PRIMITIVE.getOrDefault(elementTypeName, elementTypeName);
        if (INTEGERS.contains(parameterTypeName)) {
            builder.putIntegerProperty(name,
                                       integerBuilder -> processIntegerAnnotations(integerBuilder,
                                                                                   parameterTypeName,
                                                                                   element));
        } else if (NUMBERS.contains(parameterTypeName)) {
            builder.putNumberProperty(name, numberBuilder -> processNumberAnnotations(numberBuilder, element));
        } else if (parameterTypeName.primitive()) {
            if (parameterTypeName.equals(TypeNames.PRIMITIVE_BOOLEAN)) {
                builder.putBooleanProperty(name, booleanBuilder -> processCommonAnnotations(booleanBuilder, element));
            } else {
                builder.putStringProperty(name, stringBuilder -> processStringAnnotations(stringBuilder, element));
            }
        } else if (parameterTypeName.equals(TypeNames.STRING)) {
            builder.putStringProperty(name, stringBuilder -> processStringAnnotations(stringBuilder, element));
        } else if (parameterTypeName.array()
                || parameterTypeName.isList()
                || parameterTypeName.isSet()) {
            builder.putArrayProperty(name, arrayBuilder -> processArray(arrayBuilder, ctx, element, parameterTypeName));
        } else {
            if (parameterTypeName.packageName().startsWith("java")
                    || element.hasAnnotation(Types.JSON_SCHEMA_DO_NOT_INSPECT)) {
                //Do not inspect java and javax package classes
                //Only the annotations on the element should be processed
                builder.putObjectProperty(name, objectBuilder -> processObjectAnnotations(objectBuilder, element));
                return;
            }
            TypeInfo typeInfo = ctx.typeInfo(parameterTypeName)
                    .orElseThrow(() -> new IllegalStateException("Could not process required type: " + parameterTypeName));

            builder.putObjectProperty(name, objectBuilder -> {
                processObject(objectBuilder, typeInfo, ctx);
                //process annotations on the method so they override the defaults from the type
                processObjectAnnotations(objectBuilder, element);
            });
        }
    }

    private static void processNumberAnnotations(SchemaNumber.Builder numberBuilder, Annotated annotatedType) {
        processCommonAnnotations(numberBuilder, annotatedType);
        annotatedType.findAnnotation(Types.JSON_SCHEMA_NUMBER_MINIMUM)
                .flatMap(it -> it.doubleValue())
                .ifPresent(numberBuilder::minimum);
        annotatedType.findAnnotation(Types.JSON_SCHEMA_NUMBER_MAXIMUM)
                .flatMap(it -> it.doubleValue())
                .ifPresent(numberBuilder::maximum);
        annotatedType.findAnnotation(Types.JSON_SCHEMA_NUMBER_MULTIPLE_OF)
                .flatMap(it -> it.doubleValue())
                .ifPresent(numberBuilder::multipleOf);
        annotatedType.findAnnotation(Types.JSON_SCHEMA_NUMBER_EXCLUSIVE_MINIMUM)
                .flatMap(it -> it.doubleValue())
                .ifPresent(numberBuilder::exclusiveMinimum);
        annotatedType.findAnnotation(Types.JSON_SCHEMA_NUMBER_EXCLUSIVE_MAXIMUM)
                .flatMap(it -> it.doubleValue())
                .ifPresent(numberBuilder::exclusiveMaximum);
    }

    private static void processObjectAnnotations(SchemaObject.Builder builder, Annotated annotated) {
        processCommonAnnotations(builder, annotated);
        annotated.findAnnotation(Types.JSON_SCHEMA_OBJECT_MIN_PROPERTIES)
                .flatMap(it -> it.intValue())
                .ifPresent(builder::minProperties);
        annotated.findAnnotation(Types.JSON_SCHEMA_OBJECT_MAX_PROPERTIES)
                .flatMap(it -> it.intValue())
                .ifPresent(builder::maxProperties);
    }

    private static void processArray(SchemaArray.Builder builder,
                                     CodegenContext ctx,
                                     TypedElementInfo element,
                                     TypeName elementTypeName) {
        processArrayAnnotations(builder, ctx, element);
        TypeName typeName = elementTypeName;
        if (typeName.array()) {
            typeName = typeName.componentType().orElse(OBJECT);
        } else if (typeName.isList() || typeName.isSet()) {
            typeName = typeName.typeArguments().getFirst();
        }
        TypeName finalTypeName = BOXED_TO_PRIMITIVE.getOrDefault(typeName, typeName);
        if (INTEGERS.contains(finalTypeName)) {
            builder.itemsInteger(integerBuilder -> processIntegerAnnotations(integerBuilder, finalTypeName, element));
        } else if (NUMBERS.contains(finalTypeName)) {
            builder.itemsNumber(numberBuilder -> processNumberAnnotations(numberBuilder, element));
        } else if (finalTypeName.primitive()) {
            if (finalTypeName.equals(TypeNames.PRIMITIVE_BOOLEAN)) {
                builder.itemsBoolean(booleanBuilder -> processCommonAnnotations(booleanBuilder, element));
            } else {
                builder.itemsString(stringBuilder -> processStringAnnotations(stringBuilder, element));
            }
        } else if (finalTypeName.equals(TypeNames.STRING)) {
            builder.itemsString(stringBuilder -> processStringAnnotations(stringBuilder, element));
        } else if (finalTypeName.array()
                || finalTypeName.isList()
                || finalTypeName.isSet()) {
            builder.itemsArray(arrayBuilder -> processArray(arrayBuilder, ctx, element, finalTypeName));
        } else {
            if (finalTypeName.packageName().startsWith("java")
                    || element.hasAnnotation(Types.JSON_SCHEMA_DO_NOT_INSPECT)) {
                //Do not inspect java and javax package classes
                //Only the annotations on the element should be processed
                builder.itemsObject(objectBuilder -> processObjectAnnotations(objectBuilder, element));
                return;
            }
            TypeInfo typeInfo = ctx.typeInfo(finalTypeName)
                    .orElseThrow(() -> new IllegalStateException("Could not process required type: " + finalTypeName));

            builder.itemsObject(objectBuilder -> processObject(objectBuilder, typeInfo, ctx));
        }
    }

    private static void processArrayAnnotations(SchemaArray.Builder arrayBuilder,
                                                CodegenContext ctx,
                                                Annotated annotated) {
        processCommonAnnotations(arrayBuilder, annotated);
        annotated.findAnnotation(Types.JSON_SCHEMA_ARRAY_MIN_ITEMS)
                .flatMap(it -> it.intValue())
                .ifPresent(arrayBuilder::minItems);
        annotated.findAnnotation(Types.JSON_SCHEMA_ARRAY_MAX_ITEMS)
                .flatMap(it -> it.intValue())
                .ifPresent(arrayBuilder::maxItems);
        annotated.findAnnotation(Types.JSON_SCHEMA_ARRAY_MIN_CONTAINS)
                .flatMap(it -> it.intValue())
                .ifPresent(arrayBuilder::minContains);
        annotated.findAnnotation(Types.JSON_SCHEMA_ARRAY_MAX_CONTAINS)
                .flatMap(it -> it.intValue())
                .ifPresent(arrayBuilder::maxContains);
        annotated.findAnnotation(Types.JSON_SCHEMA_ARRAY_UNIQUE_ITEMS)
                .flatMap(it -> it.booleanValue())
                .ifPresent(arrayBuilder::uniqueItems);
    }

}
