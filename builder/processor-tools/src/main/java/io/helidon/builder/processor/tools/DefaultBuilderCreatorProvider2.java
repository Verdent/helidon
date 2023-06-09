/*
 * Copyright (c) 2022, 2023 Oracle and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.helidon.builder.processor.tools;

import java.lang.annotation.Annotation;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import io.helidon.builder.Annotated;
import io.helidon.builder.AttributeVisitor;
import io.helidon.builder.Builder;
import io.helidon.builder.BuilderInterceptor;
import io.helidon.builder.RequiredAttributeVisitor;
import io.helidon.builder.Singular;
import io.helidon.builder.model.AbstractClass;
import io.helidon.builder.model.AccessModifier;
import io.helidon.builder.model.ClassModel;
import io.helidon.builder.model.Constructor;
import io.helidon.builder.model.Field;
import io.helidon.builder.model.GenericType;
import io.helidon.builder.model.InnerClass;
import io.helidon.builder.model.Method;
import io.helidon.builder.model.Parameter;
import io.helidon.builder.model.Token;
import io.helidon.builder.model.Type;
import io.helidon.builder.processor.spi.BuilderCreatorProvider;
import io.helidon.builder.processor.spi.TypeAndBody;
import io.helidon.builder.processor.spi.TypeAndBodyDefault;
import io.helidon.common.Weight;
import io.helidon.common.Weighted;
import io.helidon.common.types.AnnotationAndValue;
import io.helidon.common.types.AnnotationAndValueDefault;
import io.helidon.common.types.TypeInfo;
import io.helidon.common.types.TypeName;
import io.helidon.common.types.TypeNameDefault;
import io.helidon.common.types.TypedElementInfo;
import io.helidon.config.metadata.ConfiguredOption;

import static io.helidon.builder.processor.tools.BodyContext.TAG_META_PROPS;
import static io.helidon.builder.processor.tools.BodyContext.toBeanAttributeName;
import static io.helidon.builder.processor.tools.BuilderTypeTools.copyrightHeaderFor;
import static io.helidon.builder.processor.tools.BuilderTypeTools.hasNonBlankValue;
import static io.helidon.builder.processor.tools.GenerateMethod.SINGULAR_PREFIX;

/**
 * Default implementation for {@link BuilderCreatorProvider}.
 */
@Weight(Weighted.DEFAULT_WEIGHT - 2)
public class DefaultBuilderCreatorProvider2 implements BuilderCreatorProvider {
    static final boolean DEFAULT_INCLUDE_META_ATTRIBUTES = true;
    static final boolean DEFAULT_REQUIRE_LIBRARY_DEPENDENCIES = true;
    static final String DEFAULT_IMPL_PREFIX = Builder.DEFAULT_IMPL_PREFIX;
    static final String DEFAULT_ABSTRACT_IMPL_PREFIX = Builder.DEFAULT_ABSTRACT_IMPL_PREFIX;
    static final String DEFAULT_ABSTRACT_IMPL_SUFFIX = Builder.DEFAULT_ABSTRACT_IMPL_SUFFIX;
    static final String DEFAULT_SUFFIX = Builder.DEFAULT_SUFFIX;
    static final String DEFAULT_LIST_TYPE = Builder.DEFAULT_LIST_TYPE.getName();
    static final String DEFAULT_MAP_TYPE = Builder.DEFAULT_MAP_TYPE.getName();
    static final String DEFAULT_SET_TYPE = Builder.DEFAULT_SET_TYPE.getName();
    static final TypeName BUILDER_ANNO_TYPE_NAME = TypeNameDefault.create(Builder.class);
    static final boolean SUPPORT_STREAMS_ON_IMPL = false;
    static final boolean SUPPORT_STREAMS_ON_BUILDER = true;

    /**
     * Default constructor.
     */
    // note: this needs to remain public since it will be resolved via service loader ...
    @Deprecated
    public DefaultBuilderCreatorProvider2() {
    }

    @Override
    public Set<Class<? extends Annotation>> supportedAnnotationTypes() {
        return Set.of(Builder.class);
    }

    @Override
    public List<TypeAndBody> create(TypeInfo typeInfo, AnnotationAndValue builderAnnotation) {
        try {
            TypeName abstractImplTypeName = toAbstractImplTypeName(typeInfo.typeName(), builderAnnotation);
            TypeName implTypeName = toBuilderImplTypeName(typeInfo.typeName(), builderAnnotation);
            preValidate(implTypeName, typeInfo, builderAnnotation);

            List<TypeAndBody> builds = new ArrayList<>();
            builds.add(TypeAndBodyDefault.builder()
                               .typeName(abstractImplTypeName)
                               .body(toBody(createBodyContext(false, abstractImplTypeName, typeInfo, builderAnnotation)))
                               .build());
            builds.add(TypeAndBodyDefault.builder()
                               .typeName(implTypeName)
                               .body(toBody(createBodyContext(true, implTypeName, typeInfo, builderAnnotation)))
                               .build());

            return postValidate(builds);
        } catch (Exception e) {
            throw new RuntimeException("Failed while processing " + typeInfo, e);
        }
    }

    /**
     * Validates the integrity of the provided arguments in the context of what is being code generated.
     *
     * @param implTypeName      the implementation type name
     * @param typeInfo          the type info
     * @param builderAnnotation the builder annotation triggering the code generation
     */
    protected void preValidate(TypeName implTypeName,
                               TypeInfo typeInfo,
                               AnnotationAndValue builderAnnotation) {
        assertNoDuplicateSingularNames(typeInfo);
    }

    private void assertNoDuplicateSingularNames(TypeInfo typeInfo) {
        Set<String> names = new LinkedHashSet<>();
        Set<String> duplicateNames = new LinkedHashSet<>();

        typeInfo.interestingElementInfo().stream()
                .map(DefaultBuilderCreatorProvider2::nameOf)
                .forEach(name -> {
                    if (!names.add(name)) {
                        duplicateNames.add(name);
                    }
                });

        if (!duplicateNames.isEmpty()) {
            throw new IllegalStateException("Duplicate methods are using the same names " + duplicateNames + " for: "
                                                    + typeInfo.typeName());
        }
    }

    /**
     * Can be overridden to validate the result before it is returned to the framework.
     *
     * @param builds the builds of the TypeAndBody that will be code generated by this creator
     * @return the validated list
     */
    protected List<TypeAndBody> postValidate(List<TypeAndBody> builds) {
        return builds;
    }

    /**
     * Constructs the abstract implementation type name for what is code generated.
     *
     * @param typeName          the target interface that the builder applies to
     * @param builderAnnotation the builder annotation triggering the build
     * @return the abstract type name of the implementation
     */
    protected TypeName toAbstractImplTypeName(TypeName typeName,
                                              AnnotationAndValue builderAnnotation) {
        String toPackageName = toPackageName(typeName.packageName(), builderAnnotation);
        String prefix = toAbstractImplTypePrefix(builderAnnotation);
        String suffix = toAbstractImplTypeSuffix(builderAnnotation);
        return TypeNameDefault.create(toPackageName, prefix + typeName.className() + suffix);
    }

    /**
     * Returns the default implementation Builder's class name for what is code generated.
     *
     * @param typeName          the target interface that the builder applies to
     * @param builderAnnotation the builder annotation triggering the build
     * @return the type name of the implementation
     */
    public static TypeName toBuilderImplTypeName(TypeName typeName,
                                                 AnnotationAndValue builderAnnotation) {
        String toPackageName = toPackageName(typeName.packageName(), builderAnnotation);
        String prefix = toImplTypePrefix(builderAnnotation);
        String suffix = toImplTypeSuffix(builderAnnotation);
        return TypeNameDefault.create(toPackageName, prefix + typeName.className() + suffix);
    }

    /**
     * Creates the context for the class being built.
     *
     * @param doingConcreteType true if the concrete type is being generated, otherwise the abstract class
     * @param typeName          the type name that will be code generated
     * @param typeInfo          the type info describing the target interface
     * @param builderAnnotation the builder annotation that triggered the builder being created
     * @return the context describing what is being built
     */
    protected BodyContext createBodyContext(boolean doingConcreteType,
                                            TypeName typeName,
                                            TypeInfo typeInfo,
                                            AnnotationAndValue builderAnnotation) {
        try {
            return new BodyContext(doingConcreteType, typeName, typeInfo, builderAnnotation);
        } catch (Throwable t) {
            throw new IllegalStateException("Failed while processing: " + typeName, t);
        }
    }

    /**
     * Generates the body of the generated builder class.
     *
     * @param ctx the context for what is being built
     * @return the string representation of the class being built
     */
    protected String toBody(BodyContext ctx) {
        ClassModel.Builder classBuilder = createClassModelBuilder(ctx);
        appendHeader(classBuilder, ctx);
        appendExtraFields(classBuilder, ctx);
        appendFields(classBuilder, ctx);
        appendCtor(classBuilder, ctx);
        appendInterfaceBasedGetters(classBuilder, ctx);
        appendBasicGetters(classBuilder, ctx);
        appendMetaAttributes(classBuilder, ctx);
        appendToStringMethod(classBuilder, ctx);
        appendInnerToStringMethod(classBuilder, ctx);
        appendHashCodeAndEquals(classBuilder, ctx);
        appendExtraMethods(classBuilder, ctx);
        appendToBuilderMethods(classBuilder, ctx);
        appendInnerClass(classBuilder, ctx);
        appendClassComponents(classBuilder, ctx);
//        appendExtraInnerClasses(builder, ctx);


        return classBuilder.build().toString();
    }

    private ClassModel.Builder createClassModelBuilder(BodyContext ctx) {
        TypeName typeName = ctx.implTypeName();
        return ClassModel.builder(typeName.packageName(), typeName.className());
    }

    private static Type toType(TypeName typeName, boolean asTopContainer) {
        return toType(typeName, asTopContainer, false);
    }

    private static Type toType(TypeName typeName, boolean asTopContainer, boolean ignoreTopWildcard) {
        if (typeName.typeArguments().isEmpty()) {
            if (typeName.array()
                    || Optional.class.getName().equals(typeName.declaredName())) {
                return Type.exact(typeName.declaredName());
            } else if (typeName.wildcard() && !ignoreTopWildcard) {
                boolean isObject = typeName.name().equals("?") || Object.class.getName().equals(typeName.name());
                if (isObject) {
                    return Type.token("?");
                } else {
                    return Type.tokenBuilder()
                            .token("?")
                            .bound(toType(TypeNameDefault.create(typeName.packageName(), typeName.className()), false))
                            .build();
                }
            }
            return Type.exact(typeName.declaredName());
        }
        GenericType.Builder typeBuilder;
        if (asTopContainer) {
            if (typeName.isList() || typeName.isSet()) {
                typeBuilder = Type.generic()
                        .type(Collection.class);
            } else if (typeName.isMap()) {
                typeBuilder = Type.generic()
                        .type(Map.class);
            } else {
                throw new IllegalStateException("Unsupported type: " + typeName.declaredName());
            }
        } else {
            typeBuilder = Type.generic()
                    .type(typeName.declaredName());
        }
        typeName.typeArguments().stream()
                .map(type -> toType(type, false))
                .forEach(typeBuilder::addParam);
        return typeBuilder.build();
    }

    protected void appendClassComponents(ClassModel.Builder builder, BodyContext ctx) {
    }

    protected void appendBuilderClassComponents(InnerClass.Builder builder, BodyContext ctx) {
    }

    /**
     * Appends any interceptor on the builder.
     *
     * @param builder       the builder
     * @param ctx           the context
     * @param builderTag    the tag (variable name) used for the builder arg
     */
    protected void maybeAppendInterceptor(Method.Builder builder, BodyContext ctx, String builderTag) {
        assert (!builderTag.equals("interceptor"));
        if (ctx.interceptorTypeName().isPresent()) {
            String impl = ctx.interceptorTypeName().get().declaredName();
            builder.add("@" + impl + "@ interceptor = ");
            if (ctx.interceptorCreateMethod().isEmpty()) {
                builder.addLine("new @" + impl + "@();");
            } else {
                builder.addLine(ctx.interceptorTypeName().get() + "." + ctx.interceptorCreateMethod().get() + "();");
            }
            builder.addLine(builderTag + " = (Builder) interceptor.intercept(" + builderTag + ");");
        }
    }

    /**
     * Appends the simple {@link ConfiguredOption#required()} validation inside the build() method.
     *
     * @param classModel the class model
     * @param builder    the builder
     * @param ctx        the context
     * @param builderTag the tag (variable name) used for the builder arg
     */
    protected void appendRequiredVisitor(ClassModel.Builder classModel,
                                         Method.Builder builder,
                                         BodyContext ctx,
                                         String builderTag) {
        assert (!builderTag.equals("visitor"));
        if (ctx.includeMetaAttributes()) {
            classModel.addImport(RequiredAttributeVisitor.class);
            builder.addLine("RequiredAttributeVisitor visitor = new RequiredAttributeVisitor(" + ctx.allowNulls() + ");")
                    .addLine(builderTag + ".visitAttributes(visitor, null);")
                    .addLine("visitor.validate();");
        }
    }

    /**
     * Adds the basic getters to the generated builder output.
     *
     * @param builder the builder
     * @param ctx     the context
     */
    protected void appendBasicGetters(ClassModel.Builder builder, BodyContext ctx) {
        if (ctx.doingConcreteType()) {
            return;
        }

        if (!ctx.hasParent() && ctx.hasStreamSupportOnImpl()) {
            builder.addMethod(methodBuilder -> methodBuilder.name("get")
                                      .generateJavadoc(false)
                                      .returnType(Type.token("T"))
                                      .addLine("return (T) this;"));
        }
    }

    /**
     * Appends meta attribute related methods.
     *
     * @param builder the builder
     * @param ctx     the context
     */
    protected void appendMetaAttributes(ClassModel.Builder builder, BodyContext ctx) {
        if (!ctx.doingConcreteType() && ctx.includeMetaAttributes()) {
            builder.addImport(LinkedHashMap.class);
            Type calcReturnType = Type.generic()
                    .type(Map.class)
                    .addParam(String.class)
                    .addParam(Type.generic()
                                      .type(Map.class)
                                      .addParam(String.class)
                                      .addParam(Object.class).build())
                    .build();
            Method.Builder methodBuilder = Method.builder()
                    .name("__calcMeta")
                    .returnType(calcReturnType)
                    .accessModifier(AccessModifier.PRIVATE)
                    .isStatic(true)
                    .addLine("Map<String, Map<String, Object>> metaProps = new LinkedHashMap<>();");

            AtomicBoolean needsCustomMapOf = new AtomicBoolean();
            appendMetaProps(methodBuilder, ctx, "metaProps", needsCustomMapOf);
            methodBuilder.addLine("return metaProps;");
            builder.addMethod(methodBuilder);

            if (needsCustomMapOf.get()) {
                appendCustomMapOf(builder);
            }

            Type returnType = Type.generic()
                    .type(Map.class)
                    .addParam(String.class)
                    .addParam(Type.generic()
                                      .type(Map.class)
                                      .addParam(String.class)
                                      .addParam(Object.class)
                                      .build())
                    .build();
            builder.addMethod(metaAttBuilder -> metaAttBuilder.name("__metaAttributes")
                    .isStatic(true)
                    .returnType(returnType, "the map of meta attributes using the key being the attribute name")
                    .description("The map of meta attributes describing each element of this type.")
                    .addLine("return " + BodyContext.TAG_META_PROPS + ";"));

            builder.addMethod(metaPropsBuilder -> metaPropsBuilder.name("__metaProps")
                    .returnType(returnType, "the map of meta attributes using the key being the attribute name")
                    .description("The map of meta attributes describing each element of this type.")
                    .addLine("return __metaAttributes();"));
        }
    }

    /**
     * Adds the fields part of the generated builder.
     *
     * @param builder the builder
     * @param ctx     the context
     */
    protected void appendFields(ClassModel.Builder builder, BodyContext ctx) {
        if (ctx.doingConcreteType()) {
            return;
        }

        for (int i = 0; i < ctx.allTypeInfos().size(); i++) {
            TypeName fieldTypeName = ctx.allTypeInfos().get(i).typeName();
            String beanAttributeName = ctx.allAttributeNames().get(i);
            Type typeBuilder = toType(fieldTypeName, false);
            builder.addField(fieldBuilder -> fieldBuilder.name(beanAttributeName)
                    .type(typeBuilder)
                    .isFinal(true));
        }
    }

    /**
     * Adds the header part of the generated builder.
     *
     * @param builder the builder
     * @param ctx     the context
     */
    protected void appendHeader(ClassModel.Builder builder, BodyContext ctx) {
        String type = (ctx.doingConcreteType()) ? "Concrete" : "Abstract";
        builder.licenseHeader(generatedCopyrightHeaderFor(ctx))
                .description(type + " implementation w/ builder for {@link " + ctx.typeInfo().typeName() + "}.")
                .addAnnotation(annotationBuilder -> annotationBuilder.type(SuppressWarnings.class)
                                       .addParameter("value", "unchecked"))
                .accessModifier(ctx.publicOrPackagePrivateDecl().equals("public ")
                                        ? AccessModifier.PUBLIC
                                        : AccessModifier.PACKAGE_PRIVATE)
                .isAbstract(!ctx.doingConcreteType());

        if (ctx.includeGeneratedAnnotation()) {
            builder.addAnnotation(annotationBuilder -> annotationBuilder.type("jakarta.annotation.Generated")
                                          .addParameter("value", getClass().getName())
                                          .addParameter("comments", generatedVersionFor(ctx)));
        }
        if (ctx.doingConcreteType()) {
            builder.inheritance(toAbstractImplTypeName(ctx.typeInfo().typeName(),
                                                       ctx.builderTriggerAnnotation()).declaredName());
        } else {
            if (ctx.hasParent()) {
                builder.inheritance(toAbstractImplTypeName(ctx.parentTypeName().orElseThrow(),
                                                           ctx.builderTriggerAnnotation()).declaredName());
            } else {
                Optional<TypeName> baseExtendsTypeName = baseExtendsTypeName(ctx);
                if (baseExtendsTypeName.isEmpty() && ctx.isExtendingAnAbstractClass()) {
                    baseExtendsTypeName = Optional.of(ctx.typeInfo().typeName());
                }
                baseExtendsTypeName.ifPresent(typeName -> builder.inheritance(typeName.declaredName()));
            }
            if (!ctx.isExtendingAnAbstractClass()) {
                builder.addInterface(ctx.typeInfo().typeName().declaredName());
            }
            if (!ctx.hasParent() && ctx.hasStreamSupportOnImpl()) {
                builder.addInterface(Type.generic()
                                             .type(Supplier.class)
                                             .addParam(ctx.genericBuilderAcceptAliasDecl())
                                             .build());
            }
            List<TypeName> extraImplementContracts = extraImplementedTypeNames(ctx);
            extraImplementContracts.forEach(t -> builder.addInterface(t.declaredName()));
        }
    }

    /**
     * Returns the copyright level header comment.
     *
     * @param ctx   the context
     * @return the copyright level header
     */
    protected String generatedCopyrightHeaderFor(BodyContext ctx) {
        return copyrightHeaderFor(getClass().getName());
    }

    /**
     * Returns the {@code Generated} sticker to be added.
     *
     * @param ctx   the context
     * @return the generated sticker
     */
    protected String generatedStickerFor(BodyContext ctx) {
        return BuilderTypeTools.generatedStickerFor(getClass().getName(), generatedVersionFor(ctx));
    }

    /**
     * Returns the {@code Generated} version identifier.
     *
     * @param ctx   the context
     * @return the generated version identifier
     */
    protected String generatedVersionFor(BodyContext ctx) {
        return Versions.CURRENT_BUILDER_VERSION;
    }

    /**
     * Returns any extra 'extends' type name that should be on the main generated type at the base level.
     *
     * @param ctx   the context
     * @return extra contracts implemented
     */
    protected Optional<TypeName> baseExtendsTypeName(BodyContext ctx) {
        return Optional.empty();
    }

    /**
     * Returns any extra 'extends' type name that should be on the main generated builder type at the base level.
     *
     * @param ctx   the context
     * @return extra contracts implemented
     */
    protected Optional<TypeName> baseExtendsBuilderTypeName(BodyContext ctx) {
        return Optional.empty();
    }

    /**
     * Returns any extra 'implements' contract types that should be on the main generated type.
     *
     * @param ctx   the context
     * @return extra contracts implemented
     */
    protected List<TypeName> extraImplementedTypeNames(BodyContext ctx) {
        return List.of();
    }

    /**
     * Returns any extra 'implements' contract types that should be on the main generated builder type.
     *
     * @param ctx   the context
     * @return extra contracts implemented
     */
    protected List<TypeName> extraImplementedBuilderContracts(BodyContext ctx) {
        return List.of();
    }

    /**
     * Adds extra imports to the generated builder.
     *
     * @param builder the builder
     * @param ctx     the context
     */
    protected void appendExtraImports(StringBuilder builder,
                                      BodyContext ctx) {
        if (!ctx.doingConcreteType()) {
            builder.append("import java.util.function.Consumer;\n");
            builder.append("import java.util.function.Supplier;\n");
            builder.append("\n");
        }

        if (ctx.requireLibraryDependencies()) {
            builder.append("import ").append(AttributeVisitor.class.getName()).append(";\n");
            if (ctx.doingConcreteType()) {
                builder.append("import ").append(RequiredAttributeVisitor.class.getName()).append(";\n");
            }
            builder.append("import ").append(BuilderInterceptor.class.getName()).append(";\n");
            builder.append("\n");
        }
    }

    /**
     * Generated the toString method on the generated builder.
     *
     * @param builder the builder
     * @param ctx     the context
     */
    protected void appendToStringMethod(ClassModel.Builder builder,
                                        BodyContext ctx) {
        if (ctx.doingConcreteType()) {
            return;
        }

        if (!ctx.hasOtherMethod("toString", ctx.typeInfo())) {
            Method.Builder methodBuilder = Method.builder()
                    .name("toString")
                    .returnType(String.class)
                    .addAnnotation(annotationBuilder -> annotationBuilder.type(Override.class))
                    .add("return \"" + ctx.typeInfo().typeName().className() + "\" + ");

            String instanceIdRef = instanceIdRef(ctx);
            if (!instanceIdRef.isBlank()) {
                methodBuilder.addLine("\"{\" + " + instanceIdRef + " + \"}\"")
                        .padding().add("+ ");;
            }
            methodBuilder.addLine("\"(\" + toStringInner() + \")\";");
            builder.addMethod(methodBuilder);
        }
    }

    /**
     * The nuanced instance id for the {@link #appendToStringMethod(ClassModel.Builder, BodyContext)}.
     *
     * @param ctx the context
     * @return the instance id
     */
    protected String instanceIdRef(BodyContext ctx) {
        return "";
    }

    /**
     * Adds extra methods to the generated builder. This base implementation will generate the visitAttributes() for the main
     * generated class.
     *
     * @param builder the builder
     * @param ctx     the context
     */
    protected void appendExtraMethods(ClassModel.Builder builder,
                                      BodyContext ctx) {
        if (ctx.includeMetaAttributes()) {
            appendVisitAttributes(builder, ctx, false);
        }
    }

    /**
     * Adds extra inner classes to write on the builder. This default implementation will write the {@code AttributeVisitor} and
     * {@code RequiredAttributeVisitor} inner classes on the base abstract parent (ie, hasParent is false).
     *
     * @param builder the builder
     * @param ctx     the context
     */
    protected void appendExtraInnerClasses(StringBuilder builder,
                                           BodyContext ctx) {
        GenerateVisitorSupport.appendExtraInnerClasses(builder, ctx);
    }

    /**
     * Returns the "final" field modifier by default.
     *
     * @return the field modifier
     */
    protected String fieldModifier() {
        return "final ";
    }

    /**
     * Appends the visitAttributes() method on the generated class.
     *
     * @param builder     the builder
     * @param ctx         the context
     * @param beanNameRef refer to bean name? otherwise refer to the element name
     */
    protected void appendVisitAttributes(AbstractClass.Builder<?, ?> builder, BodyContext ctx, boolean beanNameRef) {
        if (ctx.doingConcreteType()) {
            return;
        }
        builder.addImport(AttributeVisitor.class);
        Token tokenT = Type.tokenBuilder()
                .token("T")
                .description("type of the user defined context")
                .build();
        Method.Builder methodBuilder = Method.builder()
                .name("visitAttributes")
                .description("Visits all attributes of " + ctx.typeInfo().typeName() + ", "
                                     + "calling the {@link AttributeVisitor} for each.")
                .addTokenDeclaration(tokenT)
                .addParameter(paramBuilder -> paramBuilder.name("visitor")
                        .type(Type.generic()
                                      .type(AttributeVisitor.class)
                                      .addParam(tokenT)
                                      .build())
                        .description("the visitor called for each attribute"))
                .addParameter(paramBuilder -> paramBuilder.name("userDefinedCtx")
                        .type(tokenT)
                        .description("any object you wish to pass to each visit call"));
        if (overridesVisitAttributes(ctx)) {
            methodBuilder.generateJavadoc(false)
                    .addAnnotation(annotationBuilder -> annotationBuilder.type(Override.class));
        }
        if (ctx.hasParent()) {
            methodBuilder.addLine("super.visitAttributes(visitor, userDefinedCtx);");
        }

        int i = 0;
        for (String attrName : ctx.allAttributeNames()) {
            TypedElementInfo method = ctx.allTypeInfos().get(i);
            TypeName typeName = method.typeName();
            List<String> typeArgs = method.typeName().typeArguments().stream()
                    .map(this::normalize)
                    .toList();
            String typeArgsStr = String.join(", ", typeArgs);

            methodBuilder.add("visitor.visit(\"").add(attrName).add("\", () -> this.");
            if (beanNameRef) {
                methodBuilder.add(attrName).add(", ");
            } else {
                methodBuilder.add(method.elementName()).add("(), ");
            }
            methodBuilder.add(TAG_META_PROPS).add(".get(\"").add(attrName).add("\"), userDefinedCtx, ");
            methodBuilder.add(normalize(typeName));
            if (!typeArgsStr.isBlank()) {
                methodBuilder.add(", ").add(typeArgsStr);
            }
            methodBuilder.addLine(");");

            i++;
        }

        builder.addMethod(methodBuilder);
    }

    /**
     * Return true if the visitAttributes() methods is being overridden.
     *
     * @param ctx   the context
     * @return true if overriding visitAttributes();
     */
    protected boolean overridesVisitAttributes(BodyContext ctx) {
        return ctx.hasParent();
    }

    /**
     * Adds extra default ctor code.
     *
     * @param builder    the builder
     * @param ctx        the context
     * @param builderTag the tag (variable name) used for the builder arg
     */
    protected void appendExtraCtorCode(StringBuilder builder,
                                       BodyContext ctx,
                                       String builderTag) {
    }

    /**
     * Adds extra fields on the main generated class.
     *
     * @param builder the builder
     * @param ctx     the context
     */
    protected void appendExtraFields(ClassModel.Builder builder, BodyContext ctx) {
        if (!ctx.doingConcreteType() && ctx.includeMetaAttributes()) {
            builder.addImport(Collections.class);
            Type fieldType = Type.generic()
                    .type(Map.class)
                    .addParam(String.class)
                    .addParam(Type.generic()
                                      .type(Map.class)
                                      .addParam(String.class)
                                      .addParam(Object.class)
                                      .build())
                    .build();
            builder.addField(fieldBuilder -> fieldBuilder.name(TAG_META_PROPS)
                    .type(fieldType)
                    .accessModifier(AccessModifier.PRIVATE)
                    .isFinal(true)
                    .isStatic(true)
                    .description("Meta properties, statically cached.")
                    .defaultValue("Collections.unmodifiableMap(__calcMeta())"));
        }
    }

    /**
     * Adds extra builder methods.
     *
     * @param builder the builder
     * @param ctx     the context
     */
    protected void appendExtraBuilderFields(InnerClass.Builder builder, BodyContext ctx) {
    }

    /**
     * Adds extra builder build() method pre-steps prior to the builder being built into the target.
     *
     * @param classModel the class model
     * @param builder    the builder
     * @param ctx        the context
     * @param builderTag the tag (variable name) used for the builder arg
     */
    protected void appendBuilderBuildPreSteps(ClassModel.Builder classModel,
                                              Method.Builder builder,
                                              BodyContext ctx,
                                              String builderTag) {
        maybeAppendInterceptor(builder, ctx, builderTag);
        appendRequiredVisitor(classModel, builder, ctx, builderTag);
    }

    /**
     * Adds extra builder methods. This base implementation will write the visitAttributes() method on the
     * generated builder class.
     *
     * @param builder the builder
     * @param ctx     the context
     */
    protected void appendExtraBuilderMethods(AbstractClass.Builder<?, ?> builder, BodyContext ctx) {
        if (!ctx.doingConcreteType() && ctx.includeMetaAttributes()) {
            appendVisitAttributes(builder, ctx, true);
        }
    }

    /**
     * Adds extra meta properties to the generated code.
     *
     * @param builder           the builder
     * @param ctx               the context
     * @param tag               the tag used to represent the meta props variable on the generated code
     * @param needsCustomMapOf  will be set to true if a custom map.of() function needs to be generated (i.e., if over 9 tuples)
     */
    protected void appendMetaProps(Method.Builder builder,
                                   BodyContext ctx,
                                   String tag,
                                   AtomicBoolean needsCustomMapOf) {
        builder.add(tag)
                .add(".put(\"__generated\", Map.of(\"version\", \"")
                .add(Versions.BUILDER_VERSION_1)
                .addLine("\"));");

        ctx.map().forEach((attrName, method) ->
                            builder.add(tag)
                                    .add(".put(\"")
                                    .add(attrName)
                                    .add("\", ")
                                    .add(mapOf(attrName, method, needsCustomMapOf))
                                    .addLine(");"));
    }

    /**
     * Normalize the configured option key.
     *
     * @param key           the key attribute
     * @param name          the name
     * @param isAttribute   if the name represents an attribute value (otherwise is a config bean name)
     * @return the key to write on the generated output
     */
    protected String normalizeConfiguredOptionKey(String key,
                                                  String name,
                                                  boolean isAttribute) {
        return hasNonBlankValue(key) ? key : toConfigKey(name, isAttribute);
    }

    /**
     * Applicable if this builder is intended for config beans.
     *
     * @param name          the name
     * @param isAttribute   if the name represents an attribute value (otherwise is a config bean name)
     * @return the config key
     */
    protected String toConfigKey(String name,
                                 boolean isAttribute) {
        return "";
    }

    /**
     * Appends the singular setter methods on the builder.
     *
     * @param builder           the builder
     * @param ctx               the context
     * @param method            the method
     * @param beanAttributeName the bean attribute name
     * @param isList            true if the output involves List type
     * @param isMap             true if the output involves Map type
     * @param isSet             true if the output involves Set type
     */
    protected void maybeAppendSingularSetter(AbstractClass.Builder<?, ?> builder,
                                             BodyContext ctx,
                                             TypedElementInfo method,
                                             String beanAttributeName,
                                             boolean isList, boolean isMap, boolean isSet) {
        String singularVal = toValue(Singular.class, method, false, false).orElse(null);
        if ((singularVal != null) && (isList || isMap || isSet)) {
            String methodName = reverseBeanName(beanAttributeName);
            appendSetter(builder, ctx, beanAttributeName, methodName, method, false, SINGULAR_PREFIX);

            methodName = reverseBeanName(singularVal.isBlank() ? maybeSingularFormOf(beanAttributeName) : singularVal);
            singularSetter(builder, ctx, method, beanAttributeName, methodName);
        }
    }

    //TODO taken from GeneratedMethod class to prevent even more changes
    static void singularSetter(AbstractClass.Builder<?, ?> builder,
                               BodyContext ctx,
                               TypedElementInfo method,
                               String beanAttributeName,
                               String methodName) {
        TypeName typeName = method.typeName();
        TypeName mapValueType = mapValueTypeNameOf(typeName);
        builder.addMethod(oneSingularSetter(ctx,
                                            typeName,
                                            typeName,
                                            beanAttributeName,
                                            methodName,
                                            false,
                                            mapValueType));

        // check if the values of the map are collection types, and overload that style method as well for singular usage
        if (mapValueType != null && !mapValueType.typeArguments().isEmpty()) {
            if (mapValueType.isSet() || mapValueType.isList()) {
                TypeName singularMapValueType = mapValueType.typeArguments().get(0);
                builder.addMethod(oneSingularSetter(ctx,
                                                    typeName,
                                                    singularMapValueType,
                                                    beanAttributeName,
                                                    methodName,
                                                    true,
                                                    mapValueType));
            }
        }
    }

    //TODO taken from GeneratedMethod class to prevent even more changes
    private static Method oneSingularSetter(BodyContext ctx,
                                            TypeName typeName,
                                            TypeName valueParameter,
                                            String beanAttributeName,
                                            String methodName,
                                            boolean forceUseComputeStyle,
                                            TypeName mapValueType) {

        Method.Builder methodBuilder = Method.builder()
                .name(SINGULAR_PREFIX + methodName)
                .description("Setter for '" + beanAttributeName + "'.")
                .returnType(Type.token(ctx.genericBuilderAliasDecl()), "this fluent builder");

        int paramNumber = 0;
        if (typeName.isMap()) {
            methodBuilder.addParameter(Parameter.builder()
                                               .name("key")
                                               .type(toMethodParameterType(typeName, paramNumber++))
                                               .description("the key")
                                               .build());
        }
        //This comparison is intentional. If valueParameter is not the same as typeName, we are processing singular setter
        //of the collection or map value.
        Type vylueType;
        if (!typeName.equals(valueParameter)) {
            vylueType = toType(valueParameter, false, true);
        } else {
            vylueType = toMethodParameterType(typeName, paramNumber);
        }
        methodBuilder.addParameter(paramBuilder -> paramBuilder.name("val")
                .type(vylueType)
                .description("the new value")
                .build());

        // body of the method
        if (typeName.isMap()) {
            methodBuilder.addLine("Objects.requireNonNull(key);");
        }
        methodBuilder.addLine("Objects.requireNonNull(val);");

        methodBuilder.add("this." + beanAttributeName);
        if (typeName.isList() || typeName.isSet()) {
            methodBuilder.addLine(".add(val);");
        } else { // isMap
            boolean useComputeStyle = forceUseComputeStyle
                    || (mapValueType != null && (mapValueType.isSet() || mapValueType.isList() || mapValueType.isMap()));
            if (useComputeStyle) {
                methodBuilder.addLine(".compute(key, (k, v) -> {");
                methodBuilder.padding().addLine("if (v == null) {");
                methodBuilder.padding().padding().add("v = new ");
                if (mapValueType.isSet()) {
                    methodBuilder.add(ctx.setType());
                } else if (mapValueType.isList()) {
                    methodBuilder.add(ctx.listType());
                } else if (mapValueType.isMap()) {
                    methodBuilder.add(ctx.mapType());
                } else {
                    throw new IllegalStateException("Unhandled singular type: " + mapValueType);
                }
                methodBuilder.addLine("<>();");
                methodBuilder.padding().addLine("}");
                methodBuilder.padding();
                if (forceUseComputeStyle) {
                    if (mapValueType.isSet() || mapValueType.isList()) {
                        methodBuilder.addLine("((java.util.Collection) v).add(val);");
                    } else if (mapValueType.isMap()) {
                        methodBuilder.addLine("((java.util.Map) v).put(k, val);");
                    } else {
                        throw new IllegalStateException("Unhandled singular type: " + mapValueType);
                    }
                } else {
                    if (mapValueType.isSet() || mapValueType.isList()) {
                        methodBuilder.addLine("((java.util.Collection) v).addAll(val);");
                    } else if (mapValueType.isMap()) {
                        methodBuilder.addLine("((java.util.Map) v).putAll(val);");
                    } else {
                        methodBuilder.addLine("((java.util.Map) v).put(k, val);");
                    }
                }
                methodBuilder.padding().addLine("return v;");
                methodBuilder.addLine("});");
            } else {
                methodBuilder.addLine(".put(key, val);");
            }
        }
        methodBuilder.addLine("return identity();");

        return methodBuilder.build();
    }

    private static Type toMethodParameterType(TypeName typeName, int paramNumber) {
        TypeName parameterTypeName = typeName.typeArguments().get(paramNumber);
        if (parameterTypeName.name().equals(Object.class.getName())) {
            return Type.exact(Object.class);
        } else {
            return toType(parameterTypeName, false, parameterTypeName.wildcard());
        }
    }

    //TODO taken from GeneratedMethod class to prevent even more changes
    private static TypeName mapValueTypeNameOf(TypeName typeName) {
        return (typeName.isMap() && typeName.typeArguments().size() > 1) ? typeName.typeArguments().get(1) : null;
    }

    /**
     * If the provided name ends in an "s" then this will return the base name with the s stripped off.
     *
     * @param beanAttributeName the name
     * @return the name stripped with any "s" suffix
     */
    protected static String maybeSingularFormOf(String beanAttributeName) {
        if (beanAttributeName.endsWith("s") && beanAttributeName.length() > 1) {
            beanAttributeName = beanAttributeName.substring(0, beanAttributeName.length() - 1);
        }

        return beanAttributeName;
    }

    /**
     * Attempts to use the singular name of the element, defaulting to the element name if no singular annotation exists.
     *
     * @param elem the element
     * @return the (singular) name of the element
     */
    protected static String nameOf(TypedElementInfo elem) {
        return AnnotationAndValueDefault.findFirst(Singular.class, elem.annotations())
                .flatMap(AnnotationAndValue::value)
                .filter(BuilderTypeTools::hasNonBlankValue)
                .orElseGet(elem::elementName);
    }

    /**
     * Append the setters for the given bean attribute name.
     *
     * @param builder       the builder
     * @param ctx               the body context
     * @param beanAttributeName the bean attribute name
     * @param methodName        the method name
     * @param method            the method
     */
    protected void appendSetter(AbstractClass.Builder<?, ?> builder,
                                BodyContext ctx,
                                String beanAttributeName,
                                String methodName,
                                TypedElementInfo method) {
        appendSetter(builder, ctx, beanAttributeName, methodName, method, true, "");
    }

    private void appendSetter(AbstractClass.Builder<?, ?> builder,
                              BodyContext ctx,
                              String beanAttributeName,
                              String methodName,
                              TypedElementInfo method,
                              boolean doClear,
                              String prefixName) {
        TypeName typeName = method.typeName();
        boolean isList = typeName.isList();
        boolean isMap = !isList && typeName.isMap();
        boolean isSet = !isMap && typeName.isSet();
        AccessModifier accessModifier = (!typeName.isOptional() || ctx.allowPublicOptionals())
                ? AccessModifier.PUBLIC
                : AccessModifier.PROTECTED;
        boolean upLevel = isSet || isList;

        builder.addImport(Objects.class);
        Method.Builder methodBuilder = Method.builder()
                .name(prefixName + methodName)
                .accessModifier(accessModifier)
                .description("Setter for '" + beanAttributeName + "'.")
                .returnType(ctx.genericBuilderAliasDecl(), "this fluent builder")
                .addParameter(paramBuilder -> paramBuilder.name("val")
                        .type(toType(method.typeName(), upLevel))
                        .description("the new value"));

        /*
         Assign field, or update collection
         */
        if (isList || isSet) {
            if (doClear) {
                methodBuilder.addLine("this." + beanAttributeName + ".clear();");
            }
            methodBuilder.addLine("this." + beanAttributeName + ".addAll(" + maybeRequireNonNull(ctx, "val") + ");");
        } else if (isMap) {
            if (doClear) {
                methodBuilder.addLine("this." + beanAttributeName + ".clear();");
            }
            methodBuilder.addLine("this." + beanAttributeName + ".putAll(" + maybeRequireNonNull(ctx, "val") + ");");
        } else if (typeName.array()) {
            methodBuilder.add("this." + beanAttributeName);
            if (ctx.allowNulls()) {
                methodBuilder.addLine(" = (val == null) ? null : val.clone();");
            } else {
                methodBuilder.addLine(" = val.clone();");
            }
        } else {
            methodBuilder.addLine("this." + beanAttributeName + " = " + maybeRequireNonNull(ctx, "val") + ";");
        }
        methodBuilder.addLine("return identity();");
        builder.addMethod(methodBuilder);

        if (typeName.declaredName().equals("char[]")) {
            stringToCharSetter(builder, ctx, beanAttributeName, method, methodName);
        }

        if (prefixName.isBlank() && typeName.isOptional() && !typeName.typeArguments().isEmpty()) {
            TypeName genericType = typeName.typeArguments().get(0);
            appendDirectNonOptionalSetter(builder, ctx, beanAttributeName, method, methodName, genericType);
        }
    }

    //TODO taken from GeneratedMethod class to prevent even more changes
    static void stringToCharSetter(AbstractClass.Builder<?, ?> builder,
                                   BodyContext ctx,
                                   String beanAttributeName,
                                   TypedElementInfo method,
                                   String methodName) {
        builder.addMethod(methodBuilder -> methodBuilder.name(methodName)
                                  .description("Setter for '" + beanAttributeName + ".")
                                  .returnType(Type.token(ctx.genericBuilderAliasDecl()), "this fluent builder")
                                  .description("Setter for '" + beanAttributeName + ".")
                                  .addParameter(param -> param.name("val")
                                          .type(String.class)
                                          .description("the new value"))
                                  .addLine("Objects.requireNonNull(val);")
                                  .addLine("return this." + methodName + "(val.toCharArray());"));
    }

    /**
     * Append the setters for the given bean attribute name.
     *
     * @param builder           the builder
     * @param ctx               the body context
     * @param beanAttributeName the bean attribute name
     * @param method            the method
     * @param methodName        the method name
     * @param genericType       the generic return type name of the method
     */
    protected void appendDirectNonOptionalSetter(AbstractClass.Builder<?, ?> builder,
                                                 BodyContext ctx,
                                                 String beanAttributeName,
                                                 TypedElementInfo method,
                                                 String methodName,
                                                 TypeName genericType) {
        nonOptionalSetter(builder, ctx, beanAttributeName, method, methodName, genericType);
    }


    //TODO taken from GeneratedMethod class to prevent even more changes
    static void nonOptionalSetter(AbstractClass.Builder<?, ?> builder,
                                  BodyContext ctx,
                                  String beanAttributeName,
                                  TypedElementInfo method,
                                  String methodName,
                                  TypeName genericType) {
        builder.addImport(Optional.class);
        //TODO create common method out of this. It is used several times in this class
        builder.addMethod(methodBuilder -> methodBuilder.name(methodName)
                                  .description("Setter for '" + beanAttributeName + ".")
                                  .returnType(Type.token(ctx.genericBuilderAliasDecl()), "this fluent builder")
                                  .addParameter(param -> param.name("val")
                                          .type(genericType)
                                          .description("the new value")
                                          .build())
                                  .addLine("Objects.requireNonNull(val);")
                                  .addLine("return " + beanAttributeName + "(" + Optional.class.getSimpleName() + ".of(val));"));

        if ("char[]".equals(genericType.declaredName())) {
            stringToCharSetter(builder, ctx, beanAttributeName, method, methodName);
        }
    }

    /**
     * Append {@link Annotated} annotations if any.
     *
     * @param builder     the builder
     * @param annotations the list of annotations
     */
    protected void appendAnnotations(Method.Builder builder, List<AnnotationAndValue> annotations) {
        for (AnnotationAndValue methodAnno : annotations) {
            if (methodAnno.typeName().declaredName().equals(Annotated.class.getName())) {
                String val = methodAnno.value().orElse("");
                if (!hasNonBlankValue(val)) {
                    continue;
                }
                if (val.startsWith("@")) {
                    val = val.substring(1);
                }
                String finalValue = val;
                builder.addAnnotation(annotation -> annotation.type(finalValue));
            }
        }
    }

    /**
     * Walk the collection to build a separator-delimited string value.
     *
     * @param coll the collection
     * @return the string representation
     */
    protected static String toString(Collection<?> coll) {
        return toString(coll, Optional.empty(), Optional.empty());
    }

    /**
     * Walk the collection to build a separator-delimited string value.
     *
     * @param coll         the collection
     * @param optFnc       the optional function to apply, defaulting to {@link String#valueOf(Object)}
     * @param optSeparator the optional separator, defaulting to ", "
     * @param <T>          the types held by the collection
     * @return the string representation
     */
    protected static <T> String toString(Collection<T> coll,
                                         Optional<Function<T, String>> optFnc,
                                         Optional<String> optSeparator) {
        Function<T, String> fn = optFnc.orElse(String::valueOf);
        String separator = optSeparator.orElse(", ");
        return coll.stream().map(fn).collect(Collectors.joining(separator));
    }

    /**
     * Extracts the value from the method, ignoring {@link ConfiguredOption#UNCONFIGURED}.
     *
     * @param method                  the method
     * @param wantTypeElementDefaults flag indicating whether the method passed can be used to obtain the default values
     * @param avoidBlanks             flag indicating whether blank values should be ignored
     * @return the default value, or empty if there is no default value applicable for the given arguments
     */
    protected static Optional<String> toConfiguredOptionValue(TypedElementInfo method,
                                                              boolean wantTypeElementDefaults,
                                                              boolean avoidBlanks) {
        String val = toValue(ConfiguredOption.class, method, wantTypeElementDefaults, avoidBlanks).orElse(null);
        return ConfiguredOption.UNCONFIGURED.equals(val) ? Optional.empty() : Optional.ofNullable(val);
    }

    /**
     * Retrieves the default value of the method to a string value.
     *
     * @param annoType                the annotation that is being applied, that might have the default value
     * @param method                  the method
     * @param wantTypeElementDefaults flag indicating whether the method passed can be used to obtain the default values
     * @param avoidBlanks             flag indicating whether blank values should be ignored
     * @return the default value, or empty if there is no default value applicable for the given arguments
     */
    protected static Optional<String> toValue(Class<? extends Annotation> annoType,
                                              TypedElementInfo method,
                                              boolean wantTypeElementDefaults,
                                              boolean avoidBlanks) {
        if (wantTypeElementDefaults && method.defaultValue().isPresent()) {
            if (!avoidBlanks || hasNonBlankValue(method.defaultValue().orElse(null))) {
                return method.defaultValue();
            }
        }

        TypeName searchFor = TypeNameDefault.create(annoType);
        for (AnnotationAndValue anno : method.annotations()) {
            if (anno.typeName().equals(searchFor)) {
                Optional<String> val = anno.value();
                if (!avoidBlanks) {
                    return val;
                }
                return hasNonBlankValue(val.orElse(null)) ? val : Optional.empty();
            }
        }

        return Optional.empty();
    }

    private static String avoidWildcard(TypeName typeName) {
        return typeName.wildcard() ? typeName.name() : typeName.fqName();
    }

    private static String reverseBeanName(String beanName) {
        return beanName.substring(0, 1).toUpperCase() + beanName.substring(1);
    }

    /**
     * In support of {@link Builder#packageName()}.
     */
    private static String toPackageName(String packageName,
                                        AnnotationAndValue builderAnnotation) {
        String packageNameFromAnno = builderAnnotation.value("packageName").orElse(null);
        if (packageNameFromAnno == null || packageNameFromAnno.isBlank()) {
            return packageName;
        } else if (packageNameFromAnno.startsWith(".")) {
            return packageName + packageNameFromAnno;
        } else {
            return packageNameFromAnno;
        }
    }

    /**
     * In support of {@link Builder#abstractImplPrefix()}.
     */
    private String toAbstractImplTypePrefix(AnnotationAndValue builderAnnotation) {
        return builderAnnotation.value("abstractImplPrefix").orElse(DEFAULT_ABSTRACT_IMPL_PREFIX);
    }

    /**
     * In support of {@link io.helidon.builder.Builder#abstractImplSuffix()}.
     */
    private String toAbstractImplTypeSuffix(AnnotationAndValue builderAnnotation) {
        return builderAnnotation.value("abstractImplSuffix").orElse(DEFAULT_ABSTRACT_IMPL_SUFFIX);
    }

    /**
     * In support of {@link Builder#implPrefix()}.
     */
    private static String toImplTypePrefix(AnnotationAndValue builderAnnotation) {
        return builderAnnotation.value("implPrefix").orElse(DEFAULT_IMPL_PREFIX);
    }

    /**
     * In support of {@link Builder#implSuffix()}.
     */
    private static String toImplTypeSuffix(AnnotationAndValue builderAnnotation) {
        return builderAnnotation.value("implSuffix").orElse(DEFAULT_SUFFIX);
    }

    private void appendBuilderBody(InnerClass.Builder builder, BodyContext ctx) {
        if (!ctx.doingConcreteType()) {
            // prepare builder fields, starting with final (list, map, set)
            for (int i = 0; i < ctx.allAttributeNames().size(); i++) {
                String beanAttributeName = ctx.allAttributeNames().get(i);
                TypedElementInfo method = ctx.allTypeInfos().get(i);
                TypeName typeName = method.typeName();
                if (typeName.isList() || typeName.isMap() || typeName.isSet()) {
                    addCollectionField(builder, ctx, method, typeName, beanAttributeName);
                }
            }
            // then any other field
            for (int i = 0; i < ctx.allAttributeNames().size(); i++) {
                String beanAttributeName = ctx.allAttributeNames().get(i);
                TypedElementInfo method = ctx.allTypeInfos().get(i);
                TypeName typeName = method.typeName();
                if (typeName.isList() || typeName.isMap() || typeName.isSet()) {
                    continue;
                }
                addBuilderField(builder, ctx, method, typeName, beanAttributeName);
            }
        }

        builder.addConstructor(constructorBuilder -> {
            constructorBuilder.description("Fluent API builder constructor.")
                    .accessModifier(AccessModifier.PROTECTED);
            if (ctx.doingConcreteType()) {
                constructorBuilder.addLine("super();");
            } else {
                if (ctx.hasParent()) {
                    constructorBuilder.addLine("super();");
                }
                appendOverridesOfDefaultValues(builder, constructorBuilder, ctx);
            }
        });
    }

    private void addBuilderField(InnerClass.Builder builder,
                                 BodyContext ctx,
                                 TypedElementInfo method,
                                 TypeName type,
                                 String beanAttributeName) {
        Field.Builder fieldBuilder = Field.builder()
                .name(beanAttributeName)
                .type(type.declaredName())
                .description("Field value for {@code " + method + "()}.")
                .accessModifier(AccessModifier.PRIVATE);
        toConfiguredOptionValue(method, true, true)
                .ifPresentOrElse(defaultValue -> fieldBuilder.defaultValue(constructDefaultValue(builder, method, defaultValue)),
                                 () -> {
                                     if (type.isOptional()) {
                                         fieldBuilder.defaultValue("java.util.Optional.empty()");
                                     }
                                 });
        builder.addField(fieldBuilder);
    }

    private void addCollectionField(InnerClass.Builder builder,
                                    BodyContext ctx,
                                    TypedElementInfo method,
                                    TypeName typeName,
                                    String beanAttributeName) {
        builder.addField(field -> field.name(beanAttributeName)
                .type(typeName.declaredName())
                .isFinal(true)
                .accessModifier(AccessModifier.PROTECTED)
                .defaultValue("new " + collectionType(ctx, typeName) + "<>();")
                .description("Field value for {@code " + method + "()}."));
    }

    private String collectionType(BodyContext ctx, TypeName type) {
        if (type.isList()) {
            return ctx.listType();
        }
        if (type.isMap()) {
            return ctx.mapType();
        }
        if (type.isSet()) {
            return ctx.setType();
        }
        throw new IllegalStateException("Type is not a known collection: " + type);
    }

    private void appendInnerClass(ClassModel.Builder outerClassBuilder, BodyContext ctx) {
        outerClassBuilder.addInnerClass(builder -> {
            initializeInnerClass(builder, ctx);
            extendedInnerClassSetup(builder, outerClassBuilder, ctx);
        });
    }

    private void initializeInnerClass(InnerClass.Builder builder, BodyContext ctx) {
        builder.name(ctx.genericBuilderClassDecl())
                .description("Fluent API builder for {@code " + ctx.genericBuilderAcceptAliasDecl() + "}.")
                .accessModifier(ctx.publicOrPackagePrivateDecl().equals("public ")
                                        ? AccessModifier.PUBLIC
                                        : AccessModifier.PACKAGE_PRIVATE)
                .isStatic(true);
        if (!ctx.doingConcreteType()) {
            builder.isAbstract(true);
        }

        Type builderToken = Type.token(ctx.genericBuilderAliasDecl());

        Type builtTypeToken = Type.token(ctx.genericBuilderAcceptAliasDecl());

        if (ctx.doingConcreteType()) {
            TypeName parentType = toAbstractImplTypeName(ctx.typeInfo().typeName(), ctx.builderTriggerAnnotation());
            Type extendsType = Type.generic()
                    .type(parentType.declaredName() + "." + ctx.genericBuilderClassDecl())
                    .addParam(ctx.genericBuilderClassDecl())
                    .addParam(ctx.ctorBuilderAcceptTypeName().declaredName())
                    .build();
            builder.inheritance(extendsType);
        } else {
            builder.addGenericParameter(Type.tokenBuilder()
                                                .token(ctx.genericBuilderAliasDecl())
                                                .bound(Type.generic()
                                                               .type(ctx.genericBuilderClassDecl())
                                                               .addParam(builderToken)
                                                               .addParam(builtTypeToken)
                                                               .build())
                                                .description("Type of the builder")
                                                .build());
            builder.addGenericParameter(Type.tokenBuilder()
                                                .token(ctx.genericBuilderAcceptAliasDecl())
                                                .bound(Type.exact(ctx.ctorBuilderAcceptTypeName().declaredName()))
                                                .description("Type of the built instance")
                                                .build());

            if (ctx.hasParent()) {
                TypeName parentType = toAbstractImplTypeName(ctx.parentTypeName().orElseThrow(),
                                                             ctx.builderTriggerAnnotation());
                Type extendsType = Type.generic()
                        .type(parentType.declaredName() + "." + ctx.genericBuilderClassDecl())
                        .addParam(builderToken)
                        .addParam(builtTypeToken)
                        .build();
                builder.inheritance(extendsType);
            } else {
                Optional<TypeName> baseExtendsTypeName = baseExtendsBuilderTypeName(ctx);
                if (baseExtendsTypeName.isEmpty() && ctx.isExtendingAnAbstractClass()) {
                    baseExtendsTypeName = Optional.of(ctx.typeInfo().typeName());
                }
                baseExtendsTypeName.ifPresent(typeName -> builder.inheritance(typeName.declaredName()));
            }

            if (!ctx.isExtendingAnAbstractClass() && !ctx.hasAnyBuilderClashingMethodNames()) {
                builder.addInterface(ctx.typeInfo().typeName().declaredName());
            }
            if (!ctx.hasParent()) {
                if (ctx.hasStreamSupportOnBuilder() && !ctx.requireLibraryDependencies()) {
                    builder.addInterface(Type.generic()
                                                 .type(Supplier.class)
                                                 .addParam(Type.token(ctx.genericBuilderAcceptAliasDecl()))
                                                 .build());
                }

                if (ctx.requireLibraryDependencies()) {
                    builder.addInterface(Type.generic()
                                                 .type(io.helidon.common.Builder.class)
                                                 .addParam(builderToken)
                                                 .addParam(builtTypeToken)
                                                 .build());
                }
                extraImplementedBuilderContracts(ctx).forEach(t -> builder.addInterface(t.declaredName()));
            }
        }
    }

    private void extendedInnerClassSetup(InnerClass.Builder innerClassBuilder,
                                         ClassModel.Builder outerClassBuilder,
                                         BodyContext ctx) {
        appendExtraBuilderFields(innerClassBuilder, ctx);
        appendBuilderBody(innerClassBuilder, ctx);

        if (ctx.hasAnyBuilderClashingMethodNames()) {
            //TODO should we have this there? (currently model does not have any support for making comments)
            //            builder.append("\t\t// *** IMPORTANT NOTE: There are getter methods that clash with the base Builder methods ***\n");
            //            appendInterfaceBasedGetters(innerClassBuilder, ctx);
        } else {
        }
        appendInterfaceBasedGetters(innerClassBuilder, ctx);

        if (ctx.doingConcreteType()) {
            innerClassBuilder.addMethod(methodBuilder -> {
                methodBuilder.name("build")
                        .description("Builds the instance.")
                        .returnType(ctx.implTypeName().declaredName(), "the built instance")
                        .addThrows(IllegalArgumentException.class, "if any required attributes are missing");
                if (ctx.hasParent()) {
                    methodBuilder.generateJavadoc(false)
                            .addAnnotation(annotation -> annotation.type(Override.class));
                }
                methodBuilder.addLine("Builder b = this;");
                appendBuilderBuildPreSteps(outerClassBuilder, methodBuilder, ctx, "b");
                methodBuilder.addLine("return new " + ctx.implTypeName().className() + "(b);");
            });
        } else {
            int i = 0;
            for (String beanAttributeName : ctx.allAttributeNames()) {
                TypedElementInfo method = ctx.allTypeInfos().get(i);
                TypeName typeName = method.typeName();
                boolean isList = typeName.isList();
                boolean isMap = !isList && typeName.isMap();
                boolean isSet = !isMap && typeName.isSet();
                boolean ignoredUpLevel = isSet || isList;
                appendSetter(innerClassBuilder, ctx, beanAttributeName, beanAttributeName, method);
                if (!isList && !isMap && !isSet) {
                    boolean isBoolean = BeanUtils.isBooleanType(typeName.declaredName());
                    if (isBoolean && beanAttributeName.startsWith("is")) {
                        // possibly overload setter to strip the "is"...
                        String basicAttributeName = Character.toLowerCase(beanAttributeName.charAt(2))
                                + beanAttributeName.substring(3);
                        if (!BeanUtils.isReservedWord(basicAttributeName)
                                && !ctx.allAttributeNames().contains(basicAttributeName)) {
                            appendSetter(innerClassBuilder, ctx, beanAttributeName, basicAttributeName, method);
                        }
                    }
                }

                maybeAppendSingularSetter(innerClassBuilder, ctx, method, beanAttributeName, isList, isMap, isSet);
                i++;
            }

            if (!ctx.hasParent() && !ctx.requireLibraryDependencies()) {
                String acceptAliasDecl = ctx.genericBuilderAcceptAliasDecl();
                innerClassBuilder.addMethod(methodBuilder -> methodBuilder.name("build")
                        .description("Builds the instance.")
                        .returnType(Type.token(acceptAliasDecl), "the built instance")
                        .addThrows(IllegalArgumentException.class,
                                   "if any required attributes are missing")
                        .isAbstract(true));

                if (ctx.hasStreamSupportOnBuilder()) {
                    innerClassBuilder.addMethod(methodBuilder -> methodBuilder.name("update")
                            .description("Update the builder in a fluent API way.")
                            .returnType(Type.token(ctx.genericBuilderAliasDecl()), "updated builder instance")
                            .addParameter(param -> param.name("consumer")
                                    .type(Type.generic()
                                                  .type(Consumer.class)
                                                  .addParam(Type.token(acceptAliasDecl))
                                                  .build())
                                    .description("consumer of the builder instance"))
                            .addLine("consumer.accept(get());")
                            .addLine("return identity();"));
                }

                if (!ctx.requireLibraryDependencies()) {
                    innerClassBuilder.addMethod(methodBuilder -> methodBuilder.name("identity")
                            .description("Instance of this builder as the correct type.")
                            .returnType(Type.token(ctx.genericBuilderAliasDecl()), "this instance typed to correct type")
                            .accessModifier(AccessModifier.PROTECTED)
                            .addAnnotation(annotBuilder -> annotBuilder.type(SuppressWarnings.class)
                                    .addParameter("value", "unchecked")
                                    .build())
                            .addLine("return (" + ctx.genericBuilderAliasDecl() + ") this;"));

                    innerClassBuilder.addMethod(methodBuilder -> methodBuilder.name("get")
                            .generateJavadoc(false)
                            .returnType(Type.token(acceptAliasDecl))
                            .addAnnotation(annotBuilder -> annotBuilder.type(Override.class))
                            .addLine("return (" + acceptAliasDecl + ") build();"));
                }
            }

            innerClassBuilder.addImport(Objects.class);
            Method.Builder acceptMethodBuilder = Method.builder()
                    .name("accept")
                    .returnType(Type.token(ctx.genericBuilderAliasDecl()), "this instance typed to correct type")
                    .description("Accept and update from the provided value object.")
                    .addParameter(paramBuilder -> paramBuilder.name("val")
                            .type(Type.token(ctx.genericBuilderAcceptAliasDecl()))
                            .description("the value object to copy from"));
            if (ctx.hasParent()) {
                acceptMethodBuilder.generateJavadoc(false)
                        .addAnnotation(annotation -> annotation.type(Override.class));
            }

            if (!ctx.allowNulls()) {
                acceptMethodBuilder.addLine("Objects.requireNonNull(val);");
            }
            if (ctx.hasParent()) {
                acceptMethodBuilder.addLine("super.accept(val);");
            }
            acceptMethodBuilder.addLine("__acceptThis(val);")
                    .addLine("return identity();");
            innerClassBuilder.addMethod(acceptMethodBuilder);

            Method.Builder acceptThisBuilder = Method.builder()
                    .name("__acceptThis")
                    .accessModifier(AccessModifier.PRIVATE)
                    .addParameter(Parameter.create("val", Type.token(ctx.genericBuilderAcceptAliasDecl())));
            if (!ctx.allowNulls()) {
                acceptThisBuilder.addLine("Objects.requireNonNull(val);");
            }
            i = 0;
            for (String beanAttributeName : ctx.allAttributeNames()) {
                TypedElementInfo method = ctx.allTypeInfos().get(i++);
                TypeName typeName = method.typeName();
                String getterName = method.elementName();
                acceptThisBuilder.add(beanAttributeName + "(");
                boolean isList = typeName.isList();
                boolean isMap = !isList && typeName.isMap();
                boolean isSet = !isMap && typeName.isSet();
                if (isList || isSet) {
                    innerClassBuilder.addImport(Collection.class);
                    acceptThisBuilder.add("(Collection) ");
                } else if (isMap) {
                    innerClassBuilder.addImport(Map.class);
                    acceptThisBuilder.add("(Map) ");
                }
                boolean isPrimitive = method.typeName().primitive();
                if (!isPrimitive && ctx.allowNulls()) {
                    acceptThisBuilder.add("((val == null) ? null : ");
                }
                acceptThisBuilder.add("val." + getterName + "()");
                if (!isPrimitive && ctx.allowNulls()) {
                    acceptThisBuilder.add(")");
                }
                acceptThisBuilder.addLine(");");
            }
            innerClassBuilder.addMethod(acceptThisBuilder);
        }
        appendBuilderClassComponents(innerClassBuilder, ctx);
        appendExtraBuilderMethods(innerClassBuilder, ctx);
    }

    private void appendToBuilderMethods(ClassModel.Builder builder, BodyContext ctx) {
        if (!ctx.doingConcreteType()) {
            return;
        }

        builder.addImport(Objects.class);
        builder.addMethod(method -> method.name("builder")
                .returnType(ctx.implTypeName() + ".Builder", "a builder for {@link " + ctx.typeInfo().typeName() + "}")
                .isStatic(true)
                .description("Creates a builder for this type.")
                .addLine("return new Builder();"));

        builder.addMethod(method -> method.name("toBuilder")
                .returnType(ctx.implTypeName()+ ".Builder", "a builder for {@link " + ctx.typeInfo().typeName() + "}")
                .isStatic(true)
                .description("Creates a builder for this type, initialized with the attributes from the values passed.")
                .addParameter(param -> param.name("val")
                        .type(ctx.ctorBuilderAcceptTypeName().declaredName())
                        .description("the value to copy to initialize the builder attributes"))
                .addLine("Objects.requireNonNull(val);")
                .addLine("return builder().accept(val);"));
    }

    private void appendInterfaceBasedGetters(AbstractClass.Builder<?, ?> builder, BodyContext ctx) {
        if (ctx.doingConcreteType()) {
            return;
        }

        int i = 0;
        for (String beanAttributeName : ctx.allAttributeNames()) {
            TypedElementInfo method = ctx.allTypeInfos().get(i++);

            builder.addMethod(methodBuilder -> {
                methodBuilder.name(method.elementName())
                        .returnType(toType(method.typeName(), false))
                        .generateJavadoc(false)
                        .addAnnotation(annotation -> annotation.type(Override.class))
                        .addLine("return " + beanAttributeName + ";");
                appendAnnotations(methodBuilder, method.annotations());
            });
        }

        if (ctx.parentAnnotationTypeName().isPresent()) {
            Type returnType = Type.generic()
                    .type(Class.class)
                    .addParam(Type.tokenBuilder()
                                      .token("?")
                                      .bound(Annotation.class)
                                      .build())
                    .build();
            builder.addMethod(methodBuilder -> methodBuilder.name("annotationType")
                    .addAnnotation(annotation -> annotation.type(Override.class))
                    .generateJavadoc(false)
                    .returnType(returnType)
                    .addLine("return " + ctx.typeInfo().superTypeInfo().get().typeName() + ".class;"));
        }
    }

    private void appendCtor(ClassModel.Builder builder,
                            BodyContext ctx) {
        builder.addConstructor(constructorBuilder -> {
            constructorBuilder.description("Constructor using the builder argument.")
                    .accessModifier(AccessModifier.PROTECTED);
            String builderClass = ctx.implTypeName().declaredName() + "." +ctx.genericBuilderClassDecl();
            if (ctx.doingConcreteType()) {
                constructorBuilder.addParameter(param -> param.name("b")
                                .type(builderClass)
                                .description("the builder"))
                        .addLine("super(b);");
            } else {
                constructorBuilder.addParameter(param -> param.name("b")
                        .type(Type.generic()
                                      .type(builderClass)
                                      .addParam(Type.token("?"))
                                      .addParam(Type.token("?"))
                                      .build())
                        .description("the builder"));
                StringBuilder sb = new StringBuilder();
                appendExtraCtorCode(sb, ctx, "b");
                appendCtorCodeBody(builder, sb, ctx, "b");
                constructorBuilder.content(sb.toString());
            }
        });
    }

    /**
     * Appends the constructor body.
     *
     * @param builder           the builder
     * @param ctx               the context
     * @param builderTag        the tag (variable name) used for the builder arg
     */
    protected void appendCtorCodeBody(ClassModel.Builder classBuilder,
                                      StringBuilder builder,
                                      BodyContext ctx,
                                      String builderTag) {
        if (ctx.hasParent()) {
            builder.append("super(").append(builderTag).append(");\n");
        }
        int i = 0;
        for (String beanAttributeName : ctx.allAttributeNames()) {
            TypedElementInfo method = ctx.allTypeInfos().get(i++);
            builder.append("this.").append(beanAttributeName).append(" = ");

            if (method.typeName().isList()) {
                classBuilder.addImport(Collections.class);
                builder.append("Collections.unmodifiableList(new ")
                        .append(ctx.listType()).append("<>(").append(builderTag).append(".")
                        .append(beanAttributeName).append("));\n");
            } else if (method.typeName().isMap()) {
                classBuilder.addImport(Collections.class);
                builder.append("Collections.unmodifiableMap(new ")
                        .append(ctx.mapType()).append("<>(").append(builderTag).append(".")
                        .append(beanAttributeName).append("));\n");
            } else if (method.typeName().isSet()) {
                classBuilder.addImport(Collections.class);
                builder.append("Collections.unmodifiableSet(new ")
                        .append(ctx.setType()).append("<>(").append(builderTag).append(".")
                        .append(beanAttributeName).append("));\n");
            } else {
                builder.append(builderTag).append(".").append(beanAttributeName).append(";\n");
            }
        }
    }

    private void appendHashCodeAndEquals(ClassModel.Builder builder, BodyContext ctx) {
        if (ctx.doingConcreteType()) {
            return;
        }

        if (!ctx.hasOtherMethod("hashCode", ctx.typeInfo())) {
            builder.addImport(Objects.class);
            builder.addMethod(method -> {
                method.name("hashCode")
                        .returnType(int.class)
                        .generateJavadoc(false)
                        .addAnnotation(annotation -> annotation.type(Override.class));

                method.add("return Objects.hash(");
                if (ctx.hasParent()) {
                    method.add("super.hashCode()");
                    if (!ctx.allTypeInfos().isEmpty()) {
                        method.add(", ");
                    }
                }
                String methods = ctx.allTypeInfos().stream()
                        .map(methodElement -> methodElement.elementName() + "()")
                        .collect(Collectors.joining(", "));
                method.addLine(methods + ");");
                builder.addMethod(method);
            });
        }

        if (!ctx.hasOtherMethod("equals", ctx.typeInfo())) {
            builder.addImport(Objects.class);

            Method.Builder methodBuilder = Method.builder()
                    .name("equals")
                    .returnType(boolean.class)
                    .addParameter(Parameter.create("o", Object.class))
                    .generateJavadoc(false)
                    .addAnnotation(annotation -> annotation.type(Override.class));

            methodBuilder.addLine("if (this == o) {");
            methodBuilder.padding().addLine("return true;");
            methodBuilder.addLine("}");
            methodBuilder.addLine("if (o instanceof " + ctx.typeInfo().typeName().className() + " other) {");
            methodBuilder.padding().add("return ");
            if (ctx.hasParent()) {
                methodBuilder.add("super.equals(other)");
                if (!ctx.allTypeInfos().isEmpty()) {
                    methodBuilder.addLine(" && ").padding().padding();
                }
            }
            boolean first = true;
            for (TypedElementInfo method : ctx.allTypeInfos()) {
                String equalsClass;
                if (method.typeName().array()) {
                    builder.addImport(Arrays.class);
                    equalsClass = Arrays.class.getSimpleName();
                } else {
                    equalsClass = Objects.class.getSimpleName();
                }
                if (first) {
                    first = false;
                } else {
                    methodBuilder.addLine("").padding().padding().add("&& ");
                }
                methodBuilder.add(equalsClass).add(".equals(")
                        .add(method.elementName()).add("(), other.")
                        .add(method.elementName()).add("())");
            }
            if (!ctx.hasParent() && ctx.allTypeInfos().isEmpty()) {
                //if there was no equals method defined on our parent and there are no fields to be validated, return true
                methodBuilder.add("true");
            }
            methodBuilder.addLine(";");
            methodBuilder.addLine("}");
            methodBuilder.addLine("return false;");
            builder.addMethod(methodBuilder);
        }
    }

    private void appendInnerToStringMethod(ClassModel.Builder builder,
                                           BodyContext ctx) {
        if (ctx.doingConcreteType()) {
            return;
        }
        Method.Builder methodBuilder = Method.builder()
                .name("toStringInner")
                .description("Produces the inner portion of the toString() output (i.e., what is between the parents).")
                .accessModifier(AccessModifier.PROTECTED)
                .returnType(String.class, "portion of the toString output");
        if (ctx.hasParent()) {
            methodBuilder.generateJavadoc(false)
                    .addAnnotation(annotation -> annotation.type(Override.class));
        }
        if (ctx.hasParent()) {
            methodBuilder.addLine("String result = super.toStringInner();");
            if (!ctx.allAttributeNames().isEmpty()) {
                methodBuilder.addLine("if (!result.isEmpty() && !result.endsWith(\", \")) {");
                methodBuilder.padding().addLine("result += \", \";");
                methodBuilder.addLine("}");
            }
        } else {
            methodBuilder.addLine("String result = \"\";");
        }

        int i = 0;
        for (String beanAttributeName : ctx.allAttributeNames()) {
            TypedElementInfo method = ctx.allTypeInfos().get(i++);
            TypeName typeName = method.typeName();

            methodBuilder.add("result += \"" + beanAttributeName + "=\" + ");

            boolean handled = false;

            if (typeName.isOptional()) {
                if (!typeName.typeArguments().isEmpty()) {
                    TypeName innerType = typeName.typeArguments().get(0);
                    if (innerType.array() && innerType.primitive()) {
                        // primitive types only if present or not
                        methodBuilder.add("(" + method.elementName() + "().isEmpty() ? \"Optional.empty\" : \"not-empty\")");
                        handled = true;
                    }
                }
            }

            if (!handled) {
                if (typeName.array()) {
                    methodBuilder.add("(" + beanAttributeName + " == null ? \"null\" : ");
                    if (typeName.primitive()) {
                        methodBuilder.add("\"not-null\"");
                    } else {
                        builder.addImport(Arrays.class);
                        methodBuilder.add("Arrays.asList(" + method.elementName() + "())");
                    }
                    methodBuilder.add(")");
                } else {
                    methodBuilder.add(method.elementName() + "()");
                }
            }
            if (i < ctx.allAttributeNames().size()) {
                methodBuilder.add(" + \", \"");
            }
            methodBuilder.addLine(";");
        }
        methodBuilder.addLine("return result;");
        builder.addMethod(methodBuilder);
    }

    private String constructDefaultValue(AbstractClass.Builder<?, ?> classBuilder, TypedElementInfo method, String defaultVal) {
        StringBuilder builder = new StringBuilder();
        TypeName type = method.typeName();
        boolean isOptional = type.isOptional();
        if (isOptional) {
            builder.append(Optional.class.getName()).append(".of(");
            if (!type.typeArguments().isEmpty()) {
                type = type.typeArguments().get(0);
            }
        }

        if (Duration.class.getName().equals(type.name())) {
            classBuilder.addImport(Duration.class);
            return "Duration.parse(\"" + defaultVal + "\")";
        }

        boolean isString = type.declaredName().equals(String.class.getName()) && !type.array();
        boolean isCharArr = type.declaredName().equals("char[]");
        if ((isString || isCharArr) && !defaultVal.startsWith("\"")) {
            builder.append("\"");
        } else if (!type.primitive() && !type.declaredName().startsWith("java.")) {
            builder.append(type.declaredName()).append(".");
        }

        builder.append(defaultVal);

        if ((isString || isCharArr) && !defaultVal.endsWith("\"")) {
            builder.append("\"");
            if (isCharArr) {
                builder.append(".toCharArray()");
            }
        }

        if (isOptional) {
            builder.append(")");
        }
        return builder.toString();
    }

    private void appendOverridesOfDefaultValues(AbstractClass.Builder<?, ?> classBuilder,
                                                Constructor.Builder builder,
                                                BodyContext ctx) {
        for (TypedElementInfo method : ctx.typeInfo().interestingElementInfo()) {
            String beanAttributeName = toBeanAttributeName(method, ctx.beanStyleRequired());
            if (!ctx.allAttributeNames().contains(beanAttributeName)) {
                // candidate for override...
                String thisDefault = toConfiguredOptionValue(method, true, true).orElse(null);
                String superDefault = superValue(ctx.typeInfo().superTypeInfo(), beanAttributeName, ctx.beanStyleRequired());
                if (hasNonBlankValue(thisDefault) && !Objects.equals(thisDefault, superDefault)) {
                    appendDefaultOverride(classBuilder, builder, beanAttributeName, method, thisDefault);
                }
            }
        }
    }

    private String superValue(Optional<TypeInfo> optSuperTypeInfo,
                              String elemName,
                              boolean isBeanStyleRequired) {
        if (optSuperTypeInfo.isEmpty()) {
            return null;
        }
        TypeInfo superTypeInfo = optSuperTypeInfo.get();
        Optional<TypedElementInfo> method = superTypeInfo.interestingElementInfo().stream()
                .filter(it -> toBeanAttributeName(it, isBeanStyleRequired).equals(elemName))
                .findFirst();
        if (method.isPresent()) {
            Optional<String> defaultValue = toConfiguredOptionValue(method.get(), true, true);
            if (defaultValue.isPresent() && hasNonBlankValue(defaultValue.get())) {
                return defaultValue.orElse(null);
            }
        } else {
            return superValue(superTypeInfo.superTypeInfo(), elemName, isBeanStyleRequired);
        }

        return null;
    }

    private void appendDefaultOverride(AbstractClass.Builder<?, ?> classBuilder,
                                       Constructor.Builder builder,
                                       String attrName,
                                       TypedElementInfo method,
                                       String override) {
        String defaultValue = constructDefaultValue(classBuilder, method, override);
        builder.addLine(attrName + "(" +defaultValue + ");");
    }

    private void appendCustomMapOf(ClassModel.Builder builder) {
        builder.addImport(LinkedHashMap.class);
        Type type = Type.generic()
                .type(Map.class)
                .addParam(String.class)
                .addParam(Object.class)
                .build();
        builder.addMethod(method -> method.name("__mapOf")
                                  .generateJavadoc(false)
                                  .returnType(type)
                                  .isStatic(true)
                                  .addParameter(param -> param.name("args")
                                          .type(Object.class)
                                          .optional(true))
                                  .addLine("Map<String, Object> result = new LinkedHashMap<>(args.length / 2);")
                                  .addLine("int i = 0;")
                                  .addLine("while (i < args.length) {")
                                  .padding().addLine("result.put((String) args[i], args[i + 1]);")
                                  .padding().addLine("i += 2;")
                                  .addLine("}")
                                  .addLine("return result;"));
    }

    private String mapOf(String attrName,
                         TypedElementInfo method,
                         AtomicBoolean needsCustomMapOf) {
        Optional<? extends AnnotationAndValue> configuredOptions = AnnotationAndValueDefault
                .findFirst(ConfiguredOption.class, method.annotations());

        TypeName typeName = method.typeName();
        String typeDecl = "\"__type\", " + typeName.declaredName() + ".class";
        if (!typeName.typeArguments().isEmpty()) {
            int pos = typeName.typeArguments().size() - 1;
            TypeName arg = typeName.typeArguments().get(pos);
            typeDecl += ", \"__componentType\", " + normalize(arg);
        }

        String key = (configuredOptions.isEmpty())
                ? null : configuredOptions.get().value("key").orElse(null);
        key = normalizeConfiguredOptionKey(key, attrName, true);
        if (hasNonBlankValue(key)) {
            typeDecl += ", " + quotedTupleOf(method.typeName(), "key", key);
        }
        String defaultValue = method.defaultValue().orElse(null);

        if (configuredOptions.isEmpty() && !hasNonBlankValue(defaultValue)) {
            return "Map.of(" + typeDecl + ")";
        }

        needsCustomMapOf.set(true);
        StringBuilder result = new StringBuilder();
        result.append("__mapOf(").append(typeDecl);

        if (configuredOptions.isEmpty()) {
            result.append(", ");
            if (defaultValue.startsWith("{")) {
                defaultValue = "new String[] " + defaultValue;
                result.append(quotedValueOf("value"));
                result.append(", ");
                result.append(defaultValue);
            } else {
                result.append(quotedTupleOf(typeName, "value", defaultValue));
            }
        } else {
            configuredOptions.get().values().entrySet().stream()
                    .filter(e -> hasNonBlankValue(e.getValue()))
                    .filter(e -> !e.getKey().equals("key"))
                    .forEach(e -> {
                        result.append(", ");
                        result.append(quotedTupleOf(typeName, e.getKey(), e.getValue()));
                    });
        }
        result.append(")");

        return result.toString();
    }

    private String normalize(TypeName typeName) {
        return (typeName.generic() ? "Object" : typeName.name()) + ".class";
    }

    private String quotedTupleOf(TypeName valType,
                                 String key,
                                 String val) {
        assert (key != null);
        assert (hasNonBlankValue(val)) : key;
        boolean isEnumLikeType = isEnumLikeType(valType, key, val);
        if (isEnumLikeType) {
            val = valType + "." + val;
        } else if (!key.equals("value") || !val.startsWith(ConfiguredOption.class.getName())) {
            val = quotedValueOf(val);
        }
        return quotedValueOf(key) + ", " + val;
    }

    private String quotedValueOf(String val) {
        if (val.startsWith("\"") && val.endsWith("\"")) {
            return val;
        }

        return "\"" + val + "\"";
    }

    private boolean isEnumLikeType(TypeName valType,
                                   String key,
                                   String val) {
        if (!hasNonBlankValue(val) || valType.primitive()) {
            return false;
        }

        int dotPos = key.indexOf(".");
        if (dotPos < 0) {
            return false;
        }

        if (valType.isOptional() && !valType.typeArguments().isEmpty()) {
            return isEnumLikeType(valType.typeArguments().get(0), key, val);
        }

        return !BeanUtils.isBuiltInJavaType(valType);
    }

    private String maybeRequireNonNull(BodyContext ctx, String tag) {
        return ctx.allowNulls() ? tag : "Objects.requireNonNull(" + tag + ")";
    }

}
