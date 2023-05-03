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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.lang.annotation.Annotation;
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
import io.helidon.builder.processor.spi.BuilderCreatorProvider;
import io.helidon.builder.processor.spi.DefaultTypeAndBody;
import io.helidon.builder.processor.spi.TypeAndBody;
import io.helidon.builder.processor.tools.model.AbstractClass;
import io.helidon.builder.processor.tools.model.AccessModifier;
import io.helidon.builder.processor.tools.model.AnnotParameter;
import io.helidon.builder.processor.tools.model.ClassModel;
import io.helidon.builder.processor.tools.model.Constructor;
import io.helidon.builder.processor.tools.model.Field;
import io.helidon.builder.processor.tools.model.GenericType;
import io.helidon.builder.processor.tools.model.InnerClass;
import io.helidon.builder.processor.tools.model.Javadoc;
import io.helidon.builder.processor.tools.model.Method;
import io.helidon.builder.processor.tools.model.Parameter;
import io.helidon.builder.processor.tools.model.Type;
import io.helidon.common.Weight;
import io.helidon.common.Weighted;
import io.helidon.common.types.AnnotationAndValue;
import io.helidon.common.types.DefaultAnnotationAndValue;
import io.helidon.common.types.DefaultTypeName;
import io.helidon.common.types.TypeInfo;
import io.helidon.common.types.TypeName;
import io.helidon.common.types.TypedElementName;
import io.helidon.config.metadata.ConfiguredOption;

import static io.helidon.builder.processor.tools.BodyContext.TAG_META_PROPS;
import static io.helidon.builder.processor.tools.BodyContext.toBeanAttributeName;
import static io.helidon.builder.processor.tools.BuilderTypeTools.copyrightHeaderFor;
import static io.helidon.builder.processor.tools.BuilderTypeTools.hasNonBlankValue;
import static io.helidon.builder.processor.tools.GenerateMethod.SINGULAR_PREFIX;

/**
 * Default implementation for {@link BuilderCreatorProvider}.
 */
@Weight(Weighted.DEFAULT_WEIGHT-2)
public class DefaultBuilderCreatorProvider2 implements BuilderCreatorProvider {
    static final boolean DEFAULT_INCLUDE_META_ATTRIBUTES = true;
    static final boolean DEFAULT_REQUIRE_LIBRARY_DEPENDENCIES = true;
    static final String DEFAULT_IMPL_PREFIX = Builder.DEFAULT_IMPL_PREFIX;
    static final String DEFAULT_ABSTRACT_IMPL_PREFIX = Builder.DEFAULT_ABSTRACT_IMPL_PREFIX;
    static final String DEFAULT_SUFFIX = Builder.DEFAULT_SUFFIX;
    static final String DEFAULT_LIST_TYPE = Builder.DEFAULT_LIST_TYPE.getName();
    static final String DEFAULT_MAP_TYPE = Builder.DEFAULT_MAP_TYPE.getName();
    static final String DEFAULT_SET_TYPE = Builder.DEFAULT_SET_TYPE.getName();
    static final TypeName BUILDER_ANNO_TYPE_NAME = DefaultTypeName.create(Builder.class);
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
    public List<TypeAndBody> create(TypeInfo typeInfo,
                                    AnnotationAndValue builderAnnotation) {
        try {
            TypeName abstractImplTypeName = toAbstractImplTypeName(typeInfo.typeName(), builderAnnotation);
            TypeName implTypeName = toBuilderImplTypeName(typeInfo.typeName(), builderAnnotation);
            preValidate(implTypeName, typeInfo, builderAnnotation);

            List<TypeAndBody> builds = new ArrayList<>();
            builds.add(DefaultTypeAndBody.builder()
                               .typeName(abstractImplTypeName)
                               .body(toBody(createBodyContext(false, abstractImplTypeName, typeInfo, builderAnnotation)))
                               .build());
            builds.add(DefaultTypeAndBody.builder()
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

        typeInfo.elementInfo().stream()
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
        String suffix = toImplTypeSuffix(builderAnnotation);
        return DefaultTypeName.create(toPackageName, prefix + typeName.className() + suffix);
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
        return DefaultTypeName.create(toPackageName, prefix + typeName.className() + suffix);
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
        StringBuilder builder = new StringBuilder();
        appendHeader(classBuilder, ctx);
        appendExtraFields(classBuilder, ctx);
        appendFields(classBuilder, ctx);
        appendCtor(classBuilder, ctx);
        appendExtraPostCtorCode(builder, ctx); //Needed?
        appendInterfaceBasedGetters(classBuilder, ctx);
        appendBasicGetters(classBuilder, ctx);
        appendMetaAttributes(classBuilder, ctx);
        appendToStringMethod(classBuilder, ctx);
        appendInnerToStringMethod(classBuilder, ctx);
        appendHashCodeAndEquals(classBuilder, ctx);
        appendExtraMethods(classBuilder, ctx);
        appendToBuilderMethods(classBuilder, ctx);
        appendBuilder(classBuilder, ctx);
        appendExtraBuilderMethods(classBuilder, ctx);
        appendClassComponents(classBuilder, ctx);
        appendExtraInnerClasses(builder, ctx);
        appendFooter(builder, ctx);


        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            try (OutputStreamWriter writer = new OutputStreamWriter(outputStream)) {
                classBuilder.build().saveToFile(writer);
            }
            return outputStream.toString();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private ClassModel.Builder createClassModelBuilder(BodyContext ctx) {
        TypeName typeName = ctx.implTypeName();
        return ClassModel.builder(typeName.packageName(), typeName.className());
    }

    private Type toType(TypeName typeName) {
        if (typeName.typeArguments().isEmpty()) {
            if (typeName.array()
                    || Optional.class.getName().equals(typeName.name())
                    || (typeName.wildcard())) {
                return Type.create(typeName.fqName());
            }
            return Type.create(typeName.name());
        }
        GenericType.Builder typeBuilder = Type.generic(typeName.fqName());
        typeName.typeArguments().stream()
                .map(this::toType)
                .forEach(typeBuilder::addParam);
        return typeBuilder.build();
    }

    protected void appendClassComponents(ClassModel.Builder builder, BodyContext ctx) {
    }

    protected void appendBuilderClassComponents(InnerClass.Builder builder, BodyContext ctx) {
    }

    /**
     * Appends the footer of the generated class.
     *
     * @param builder the builder
     * @param ctx     the context
     */
    protected void appendFooter(StringBuilder builder, BodyContext ctx) {
        builder.append("}\n");
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
            String impl = ctx.interceptorTypeName().get().name();
            builder.add(impl + " interceptor = ");
            if (ctx.interceptorCreateMethod().isEmpty()) {
                builder.addLine("new " + impl + "();");
            } else {
                builder.addLine(ctx.interceptorTypeName().get() + "." + ctx.interceptorCreateMethod().get() + "();");
            }
            builder.addLine(builderTag + " = (Builder) interceptor.intercept(" + builderTag + ");");
        }
    }

    /**
     * Appends the simple {@link ConfiguredOption#required()} validation inside the build() method.
     *
     * @param builder       the builder
     * @param ctx           the context
     * @param builderTag    the tag (variable name) used for the builder arg
     */
    protected void appendRequiredVisitor(Method.Builder builder,
                                         BodyContext ctx,
                                         String builderTag) {
        assert (!builderTag.equals("visitor"));
        if (ctx.includeMetaAttributes()) {
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
            builder.addMethod(Method.builder("get", Type.token("T"))
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
            Type calcReturnType = Type.generic(Map.class)
                    .addParam(String.class)
                    .addParam(Type.generic(Map.class).addParam(String.class).addParam(Object.class).build())
                    .build();
            Method.Builder methodBuilder = Method.builder("__calcMeta", calcReturnType)
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

            Javadoc javadoc = Javadoc.builder()
                    .addLine("The map of meta attributes describing each element of this type.")
                    .returnDescription("the map of meta attributes using the key being the attribute name")
                    .build();
            Type returnType = Type.generic(Map.class)
                    .addParam(String.class)
                    .addParam(Type.generic(Map.class).addParam(String.class).addParam(Object.class).build())
                    .build();
            builder.addMethod(Method.builder("__metaAttributes", returnType)
                                      .isStatic(true)
                                      .javadoc(javadoc)
                                      .addLine("return " + BodyContext.TAG_META_PROPS + ";"));
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
            Type typeBuilder = toType(fieldTypeName);
            Field.Builder fieldBuilder = Field.builder(beanAttributeName, typeBuilder).isFinal(true);
            builder.addField(fieldBuilder);
        }
    }

    /**
     * Adds the header part of the generated builder.
     *
     * @param builder the builder
     * @param ctx     the context
     */
    protected void appendHeader(ClassModel.Builder builder, BodyContext ctx) {
        builder.licenseHeader(generatedCopyrightHeaderFor(ctx));

        String type = (ctx.doingConcreteType()) ? "Concrete" : "Abstract";
        Javadoc javadoc = Javadoc.builder()
                .addLine(type + " implementation w/ builder for {@link " + ctx.typeInfo().typeName() + "}.")
                .build();
        builder.javadoc(javadoc);
        builder.addAnnotation(io.helidon.builder.processor.tools.model.Annotation.builder("jakarta.annotation.Generated")
                               .addParameter(AnnotParameter.create("value", String.class, getClass().getName()))
                               .addParameter(AnnotParameter.create("comments", String.class, generatedVersionFor(ctx))))
                .addAnnotation(io.helidon.builder.processor.tools.model.Annotation.builder(SuppressWarnings.class)
                                       .addParameter(AnnotParameter.create("value", String.class, "unchecked")))
                .accessModifier(ctx.publicOrPackagePrivateDecl())
                .isAbstract(!ctx.doingConcreteType());

        if (ctx.doingConcreteType()) {
            builder.inheritance(toAbstractImplTypeName(ctx.typeInfo().typeName(),
                                                       ctx.builderTriggerAnnotation()).fqName());
        } else {
            if (ctx.hasParent()) {
                builder.inheritance(toAbstractImplTypeName(ctx.parentTypeName().orElseThrow(),
                                                           ctx.builderTriggerAnnotation()).fqName());
            } else {
                Optional<TypeName> baseExtendsTypeName = baseExtendsTypeName(ctx);
                if (baseExtendsTypeName.isEmpty() && ctx.isExtendingAnAbstractClass()) {
                    baseExtendsTypeName = Optional.of(ctx.typeInfo().typeName());
                }
                baseExtendsTypeName.ifPresent(typeName -> builder.inheritance(typeName.fqName()));
            }
            if (!ctx.isExtendingAnAbstractClass()) {
                builder.addInterface(ctx.typeInfo().typeName().fqName());
            }
            if (!ctx.hasParent() && ctx.hasStreamSupportOnImpl()) {
                builder.addInterface(Type.generic(Supplier.class)
                                             .addParam(ctx.genericBuilderAcceptAliasDecl())
                                             .build());
            }
            List<TypeName> extraImplementContracts = extraImplementedTypeNames(ctx);
            extraImplementContracts.forEach(t -> builder.addInterface(t.fqName()));
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
            Method.Builder methodBuilder = Method.builder("toString", String.class)
                    .addAnnotation(io.helidon.builder.processor.tools.model.Annotation.create(Override.class))
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
    protected void appendVisitAttributes(ClassModel.Builder builder, BodyContext ctx, boolean beanNameRef) {
        if (ctx.doingConcreteType()) {
            return;
        }
        builder.addImport(AttributeVisitor.class);
        Method.Builder methodBuilder = Method.builder("visitAttributes", void.class)
                .addParameter(Parameter.create("visitor", Type.generic(AttributeVisitor.class)
                        .addParam(Type.token("T"))
                        .build()))
                .addParameter(Parameter.create("userDefinedCtx", Type.token("T")));
        if (!overridesVisitAttributes(ctx)) {
            Javadoc javadoc = Javadoc.builder()
                    .addLine("Visits all attributes of " + ctx.typeInfo().typeName() + ", calling the {@link "
                                     + "AttributeVisitor} for each.")
                    .addParameter("visitor", "the visitor called for each attribute")
                    .addParameter("userDefinedCtx", "any object you wish to pass to each visit call")
                    .addParameter("<T>", "type of the user defined context")
                    .build();
            methodBuilder.javadoc(javadoc);
        }
        if (ctx.hasParent()) {
            methodBuilder.addLine("super.visitAttributes(visitor, userDefinedCtx);");
        }

        int i = 0;
        for (String attrName : ctx.allAttributeNames()) {
            TypedElementName method = ctx.allTypeInfos().get(i);
            String typeName = method.typeName().declaredName();
            List<String> typeArgs = method.typeName().typeArguments().stream()
                    .map(it -> normalize(it.declaredName()) + ".class")
                    .collect(Collectors.toList());
            String typeArgsStr = String.join(", ", typeArgs);

            methodBuilder.add("visitor.visit(\"").add(attrName).add("\", () -> this.");
            if (beanNameRef) {
                methodBuilder.add(attrName).add(", ");
            } else {
                methodBuilder.add(method.elementName()).add("(), ");
            }
            methodBuilder.add(TAG_META_PROPS).add(".get(\"").add(attrName).add("\"), userDefinedCtx, ");
            methodBuilder.add(normalize(typeName)).add(".class");
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
     * Adds extra code following the ctor decl.
     *
     * @param builder the builder
     * @param ctx     the context
     */
    protected void appendExtraPostCtorCode(StringBuilder builder,
                                           BodyContext ctx) {
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
            Type fieldType = Type.generic(Map.class)
                    .addParam(String.class)
                    .addParam(Type.generic(Map.class).addParam(String.class).addParam(Object.class).build())
                    .build();
            builder.addField(Field.builder(TAG_META_PROPS, fieldType)
                                     .accessModifier(AccessModifier.PRIVATE)
                                     .isFinal(true)
                                     .isStatic(true)
                                     .javadoc(Javadoc.builder()
                                                      .addLine("Meta properties, statically cached.")
                                                      .build())
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
     * @param builder the builder
     * @param ctx     the context
     * @param builderTag        the tag (variable name) used for the builder arg
     */
    protected void appendBuilderBuildPreSteps(Method.Builder builder, BodyContext ctx, String builderTag) {
        maybeAppendInterceptor(builder, ctx, builderTag);
        appendRequiredVisitor(builder, ctx, builderTag);
    }

    /**
     * Adds extra builder methods. This base implementation will write the visitAttributes() method on the
     * generated builder class.
     *
     * @param builder the builder
     * @param ctx     the context
     */
    private void appendExtraBuilderMethods(ClassModel.Builder builder, BodyContext ctx) {
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
                                             TypedElementName method,
                                             String beanAttributeName,
                                             boolean isList, boolean isMap, boolean isSet) {
        String singularVal = toValue(Singular.class, method, false, false).orElse(null);
        if ((singularVal != null) && (isList || isMap || isSet)) {
            char[] methodName = reverseBeanName(beanAttributeName);
            appendSetter(builder, ctx, beanAttributeName, new String(methodName), method, false, SINGULAR_PREFIX);

            methodName = reverseBeanName(singularVal.isBlank() ? maybeSingularFormOf(beanAttributeName) : singularVal);
//            singularSetter(builder, ctx, method, beanAttributeName, methodName);
        }
    }

//    //TODO taken from GeneratedMethod class to prevent even more changes
//    static void singularSetter(ClassModel.Builder builder,
//                               BodyContext ctx,
//                               TypedElementName method,
//                               String beanAttributeName,
//                               char[] methodName) {
//        TypeName typeName = method.typeName();
//        TypeName mapValueType = mapValueTypeNameOf(typeName);
//        builder.append(
//                oneSingularSetter(ctx,
//                                  typeName,
//                                  toGenericsDecl2(method, false, mapValueType),
//                                  beanAttributeName,
//                                  methodName,
//                                  false,
//                                  mapValueType));
//
//        // check if the values of the map are collection types, and overload that style method as well for singular usage
//        if (mapValueType != null && !mapValueType.typeArguments().isEmpty()) {
//            if (mapValueType.isSet() || mapValueType.isList()) {
//                TypeName singularMapValueType = Objects.requireNonNull(mapValueType.typeArguments().get(0));
//                builder.append(
//                        oneSingularSetter(ctx,
//                                          typeName,
//                                          toGenericsDecl2(method, true, singularMapValueType),
//                                          beanAttributeName,
//                                          methodName,
//                                          true,
//                                          mapValueType));
//            }
//        }
//    }
//
//    //TODO taken from GeneratedMethod class to prevent even more changes.
//    //Added 2 since there is already method of this name with slightly different impl
//    private static String toGenericsDecl2(TypedElementName method,
//                                         boolean useSingluarMapValues,
//                                         TypeName mapValueType) {
//        List<TypeName> compTypeNames = method.typeName().typeArguments();
//        if (1 == compTypeNames.size()) {
//            return avoidWildcard(compTypeNames.get(0)) + " val";
//        } else if (2 == compTypeNames.size()) {
//            if (useSingluarMapValues) {
//                return avoidWildcard(compTypeNames.get(0)) + " key, " + avoidWildcard(mapValueType) + " val";
//            } else {
//                return avoidWildcard(compTypeNames.get(0)) + " key, " + avoidWildcard(compTypeNames.get(1)) + " val";
//            }
//        }
//        return "Object val";
//    }
//
//    //TODO taken from GeneratedMethod class to prevent even more changes
//    private static Method oneSingularSetter(BodyContext ctx,
//                                                   TypeName typeName,
//                                                   String genericDecl,
//                                                   String beanAttributeName,
//                                                   char[] methodName,
//                                                   boolean forceUseComputeStyle,
//                                                   TypeName mapValueType) {
//        GenerateJavadoc.singularSetter(builder, typeName, beanAttributeName);
//
//        // builder method declaration for "addSomething()"
//        builder.append("\t\tpublic ")
//                .append(ctx.genericBuilderAliasDecl())
//                .append(" ").append(SINGULAR_PREFIX)
//                .append(methodName)
//                .append("(")
//                .append(genericDecl)
//                .append(") {\n");
//        // body of the method
//        if (typeName.isMap()) {
//            builder.append("\t\t\tObjects.requireNonNull(key);\n");
//        }
//        builder.append("\t\t\tObjects.requireNonNull(val);\n");
//
//        builder.append("\t\t\tthis.").append(beanAttributeName);
//        if (typeName.isList() || typeName.isSet()) {
//            builder.append(".add(val);\n");
//        } else { // isMap
//            boolean useComputeStyle = forceUseComputeStyle
//                    || (mapValueType != null && (mapValueType.isSet() || mapValueType.isList() || mapValueType.isMap()));
//            if (useComputeStyle) {
//                builder.append(".compute(key, (k, v) -> {\n");
//                builder.append("\t\t\t\tif (v == null) {\n");
//                builder.append("\t\t\t\t\tv = new ");
//                if (mapValueType.isSet()) {
//                    builder.append(ctx.setType());
//                } else if (mapValueType.isList()) {
//                    builder.append(ctx.listType());
//                } else if (mapValueType.isMap()) {
//                    builder.append(ctx.mapType());
//                } else {
//                    throw new IllegalStateException("Unhandled singular type: " + mapValueType);
//                }
//                builder.append("<>();\n");
//                builder.append("\t\t\t\t}\n");
//                if (forceUseComputeStyle) {
//                    if (mapValueType.isSet() || mapValueType.isList()) {
//                        builder.append("\t\t\t\t((java.util.Collection) v).add(val);\n");
//                    } else if (mapValueType.isMap()) {
//                        builder.append("\t\t\t\t((java.util.Map) v).put(k, val);\n");
//                    } else {
//                        throw new IllegalStateException("Unhandled singular type: " + mapValueType);
//                    }
//                } else {
//                    if (mapValueType.isSet() || mapValueType.isList()) {
//                        builder.append("\t\t\t\t((java.util.Collection) v).addAll(val);\n");
//                    } else if (mapValueType.isMap()) {
//                        builder.append("\t\t\t\t((java.util.Map) v).putAll(val);\n");
//                    } else {
//                        builder.append("\t\t\t\t((java.util.Map) v).put(k, val);\n");
//                    }
//                }
//                builder.append("\t\t\t\treturn v;\n");
//                builder.append("\t\t\t});\n");
//            } else {
//                builder.append(".put(key, val);\n");
//            }
//        }
//        builder.append("\t\t\treturn identity();\n");
//        builder.append("\t\t}\n\n");
//        return builder;
//    }

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
    protected static String nameOf(TypedElementName elem) {
        return DefaultAnnotationAndValue.findFirst(Singular.class.getName(), elem.annotations())
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
                                TypedElementName method) {
        appendSetter(builder, ctx, beanAttributeName, methodName, method, true, "");
    }

    private void appendSetter(AbstractClass.Builder<?, ?> builder,
                              BodyContext ctx,
                              String beanAttributeName,
                              String methodName,
                              TypedElementName method,
                              boolean doClear,
                              String prefixName) {
        TypeName typeName = method.typeName();
        boolean isList = typeName.isList();
        boolean isMap = !isList && typeName.isMap();
        boolean isSet = !isMap && typeName.isSet();
        boolean upLevel = isSet || isList;

        Javadoc javadoc = Javadoc.builder()
                .addLine("Setter for '" + beanAttributeName + ".\n")
                .addParameter("val", "the new value")
                .returnDescription("this fluent builder")
                .build();
        Method.Builder methodBuilder = Method.builder(prefixName + methodName, ctx.genericBuilderAliasDecl())
                .javadoc(javadoc)
                .addParameter(Parameter.create("val", toType(method.typeName())));

        /*
         Assign field, or update collection
         */
        if (isList || isSet) {
            if (doClear) {
                methodBuilder.addLine("this." + beanAttributeName + ".clear();");
            }
            methodBuilder.add("this." + beanAttributeName + ".addAll(" + maybeRequireNonNull(ctx, "val") + ");");
        } else if (isMap) {
            if (doClear) {
                methodBuilder.addLine("this." + beanAttributeName + ".clear();");
            }
            methodBuilder.add("this." + beanAttributeName + ".putAll(" + maybeRequireNonNull(ctx, "val") + ");");
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

        if (typeName.fqName().equals("char[]")) {
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
                                   TypedElementName method,
                                   String methodName) {
        Javadoc javadoc = Javadoc.builder()
                .addLine("Setter for '" + beanAttributeName + ".\n")
                .addParameter("val", "the new value")
                .returnDescription("this fluent builder")
                .build();
        builder.addMethod(Method.builder(methodName, Type.token(ctx.genericBuilderAliasDecl()))
                                  .javadoc(javadoc)
                                  .addParameter(Parameter.create("val", String.class))
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
                                                 TypedElementName method,
                                                 String methodName,
                                                 TypeName genericType) {
        nonOptionalSetter(builder, ctx, beanAttributeName, method, methodName, genericType);
    }


    //TODO taken from GeneratedMethod class to prevent even more changes
    static void nonOptionalSetter(AbstractClass.Builder<?, ?> builder,
                                  BodyContext ctx,
                                  String beanAttributeName,
                                  TypedElementName method,
                                  String methodName,
                                  TypeName genericType) {
//        builder.addImport(Optional.class);
        //TODO create common method out of this. It is used several times in this class
        Javadoc javadoc = Javadoc.builder()
                .addLine("Setter for '" + beanAttributeName + ".\n")
                .addParameter("val", "the new value")
                .returnDescription("this fluent builder")
                .build();
        builder.addMethod(Method.builder(methodName, Type.token(ctx.genericBuilderAliasDecl()))
                                  .javadoc(javadoc)
                                  .addParameter(Parameter.create("val", genericType.fqName()))
                                  .addLine("Objects.requireNonNull(val);")
                                  .addLine("return " + beanAttributeName + "(" + Optional.class.getSimpleName() + ".of(val));"));

        if ("char[]".equals(genericType.fqName())) {
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
            if (methodAnno.typeName().name().equals(Annotated.class.getName())) {
                String val = methodAnno.value().orElse("");
                if (!hasNonBlankValue(val)) {
                    continue;
                }
                if (!val.startsWith("@")) {
                    val = "@" + val;
                }
                builder.addAnnotation(io.helidon.builder.processor.tools.model.Annotation.create(val));
            }
        }
    }

    /**
     * Produces the generic descriptor decl for the method.
     *
     * @param method              the method
     * @param upLevelToCollection true if the generics should be "up leveled"
     * @return the generic decl
     */
    protected static String toGenerics(TypedElementName method,
                                       boolean upLevelToCollection) {
        return toGenerics(method.typeName(), upLevelToCollection);
    }

    /**
     * Produces the generic descriptor decl for the method.
     *
     * @param typeName            the type name
     * @param upLevelToCollection true if the generics should be "up leveled"
     * @return the generic decl
     */
    protected static String toGenerics(TypeName typeName,
                                       boolean upLevelToCollection) {
        return toGenerics(typeName, upLevelToCollection, 0);
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
    protected static Optional<String> toConfiguredOptionValue(TypedElementName method,
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
                                              TypedElementName method,
                                              boolean wantTypeElementDefaults,
                                              boolean avoidBlanks) {
        if (wantTypeElementDefaults && method.defaultValue().isPresent()) {
            if (!avoidBlanks || hasNonBlankValue(method.defaultValue().orElse(null))) {
                return method.defaultValue();
            }
        }

        TypeName searchFor = DefaultTypeName.create(annoType);
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

    private static String toGenerics(TypeName typeName,
                                     boolean upLevelToCollection,
                                     int depth) {
        if (typeName.typeArguments().isEmpty()) {
            return (typeName.array()
                            || Optional.class.getName().equals(typeName.name())
                            || (typeName.wildcard() && depth > 0))
                    ? typeName.fqName() : typeName.name();
        }

        if (upLevelToCollection) {
            List<String> upLevelInner = typeName.typeArguments().stream()
                    .map(it -> toGenerics(it, upLevelToCollection && 0 == depth, depth + 1))
                    .collect(Collectors.toList());
            if (typeName.isList() || typeName.isSet()) {
                return Collection.class.getName() + "<" + toString(upLevelInner) + ">";
            } else if (typeName.isMap()) {
                return Map.class.getName() + "<" + toString(upLevelInner) + ">";
            }
        }

        return typeName.fqName();
    }

    private static String toGenericsDecl(TypedElementName method) {
        List<TypeName> compTypeNames = method.typeName().typeArguments();
        if (1 == compTypeNames.size()) {
            return avoidWildcard(compTypeNames.get(0)) + " val";
        } else if (2 == compTypeNames.size()) {
            return avoidWildcard(compTypeNames.get(0)) + " key, " + avoidWildcard(compTypeNames.get(1)) + " val";
        }
        return "Object val";
    }

    private static String avoidWildcard(TypeName typeName) {
        return typeName.wildcard() ? typeName.name() : typeName.fqName();
    }

    private static char[] reverseBeanName(String beanName) {
        char[] c = beanName.toCharArray();
        c[0] = Character.toUpperCase(c[0]);
        return c;
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

    private void appendBuilder(ClassModel.Builder builder, BodyContext ctx) {
        InnerClass.Builder innerClassBuilder = createInnerClassBuilder(ctx);
        appendExtraBuilderFields(innerClassBuilder, ctx);
        appendBuilderBody(innerClassBuilder, ctx);

        if (ctx.hasAnyBuilderClashingMethodNames()) {
//            builder.append("\t\t// *** IMPORTANT NOTE: There are getter methods that clash with the base Builder methods ***\n");
            appendInterfaceBasedGetters(innerClassBuilder, ctx);
        } else {
            appendInterfaceBasedGetters(innerClassBuilder, ctx);
        }

        if (ctx.doingConcreteType()) {
            Method.Builder methodBuilder = Method.builder("build", ctx.implTypeName().fqName());
            if (ctx.hasParent()) {
                methodBuilder.addAnnotation(io.helidon.builder.processor.tools.model.Annotation.create(Override.class));
            } else {
                Javadoc javadoc = Javadoc.builder()
                        .addLine("Builds the instance.")
                        .returnDescription("the built instance")
                        .addThrows(IllegalArgumentException.class, "if any required attributes are missing")
                        .build();
                methodBuilder.javadoc(javadoc);
            }
            methodBuilder.addLine("Builder b = this;");
            appendBuilderBuildPreSteps(methodBuilder, ctx, "b");
            methodBuilder.addLine("return new " + ctx.implTypeName().className() + "(b);");
            innerClassBuilder.addMethod(methodBuilder);
        } else {
            int i = 0;
            for (String beanAttributeName : ctx.allAttributeNames()) {
                TypedElementName method = ctx.allTypeInfos().get(i);
                TypeName typeName = method.typeName();
                boolean isList = typeName.isList();
                boolean isMap = !isList && typeName.isMap();
                boolean isSet = !isMap && typeName.isSet();
                boolean ignoredUpLevel = isSet || isList;
                appendSetter(innerClassBuilder, ctx, beanAttributeName, beanAttributeName, method);
                if (!isList && !isMap && !isSet) {
                    boolean isBoolean = BeanUtils.isBooleanType(typeName.name());
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
                Javadoc buildJavadoc = Javadoc.builder()
                        .addLine("Builds the instance.")
                        .returnDescription("the built instance")
                        .addThrows(IllegalArgumentException.class, "if any required attributes are missing")
                        .build();
                String acceptAliasDecl = ctx.genericBuilderAcceptAliasDecl();
                innerClassBuilder.addMethod(Method.builder("build", Type.token(acceptAliasDecl))
                                                    .javadoc(buildJavadoc)
                                                    .isAbstract(true));

                if (ctx.hasStreamSupportOnBuilder()) {
                    Javadoc updateJavadoc = Javadoc.builder()
                            .addLine("Update the builder in a fluent API way.")
                            .addParameter("consumer", "consumer of the builder instance")
                            .returnDescription("updated builder instance")
                            .build();
                    Method.Builder updateMethodBuilder = Method.builder("update", Type.token(acceptAliasDecl))
                            .addParameter(Parameter.create("consumer",
                                                           Type.generic(Consumer.class)
                                                                   .addParam(Type.token(acceptAliasDecl))
                                                                   .build()))
                            .javadoc(updateJavadoc)
                            .addLine("consumer.accept(get());")
                            .addLine("return identity();");
                    innerClassBuilder.addMethod(updateMethodBuilder);
                }

                if (!ctx.requireLibraryDependencies()) {
                    Javadoc identityJavadoc = Javadoc.builder()
                            .addLine("Instance of this builder as the correct type.")
                            .returnDescription("this instance typed to correct type")
                            .build();
                    Method.Builder identityMethodBuilder = Method.builder("identity", Type.token(ctx.genericBuilderAliasDecl()))
                            .accessModifier(AccessModifier.PROTECTED)
                            .javadoc(identityJavadoc)
                            .addAnnotation(io.helidon.builder.processor.tools.model.Annotation.builder(SuppressWarnings.class)
                                                   .addParameter(AnnotParameter.create("value", String.class, "unchecked"))
                                                   .build())
                            .addLine("return this;");
                    innerClassBuilder.addMethod(identityMethodBuilder);


                    Method.Builder getMethodBuilder = Method.builder("get", Type.token(acceptAliasDecl))
                            .addAnnotation(io.helidon.builder.processor.tools.model.Annotation.create(Override.class))
                            .addLine("return (" + acceptAliasDecl + ") build();");
                    innerClassBuilder.addMethod(getMethodBuilder);
                }
            }

            Method.Builder acceptMethodBuilder = Method.builder("accept", Type.token(ctx.genericBuilderAliasDecl()))
                    .addParameter(Parameter.create("val", Type.token(ctx.genericBuilderAcceptAliasDecl())));
            if (ctx.hasParent()) {
                acceptMethodBuilder.addAnnotation(io.helidon.builder.processor.tools.model.Annotation.create(Override.class));
            } else {
                Javadoc javadoc = Javadoc.builder()
                        .addLine("Accept and update from the provided value object.")
                        .addParameter("val", "the value object to copy from")
                        .returnDescription("this instance typed to correct type")
                        .build();
                acceptMethodBuilder.javadoc(javadoc);
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

            Method.Builder acceptThisBuilder = Method.builder("__acceptThis", void.class)
                    .accessModifier(AccessModifier.PRIVATE)
                    .addParameter(Parameter.create("val", Type.token(ctx.genericBuilderAcceptAliasDecl())));
            if (!ctx.allowNulls()) {
                acceptThisBuilder.addLine("Objects.requireNonNull(val);");
            }
            i = 0;
            for (String beanAttributeName : ctx.allAttributeNames()) {
                TypedElementName method = ctx.allTypeInfos().get(i++);
                TypeName typeName = method.typeName();
                String getterName = method.elementName();
                acceptThisBuilder.add(beanAttributeName + "(");
                boolean isList = typeName.isList();
                boolean isMap = !isList && typeName.isMap();
                boolean isSet = !isMap && typeName.isSet();
                if (isList || isSet) {
                    builder.addImport(Collection.class);
                    acceptThisBuilder.add("(Collection) ");
                } else if (isMap) {
                    builder.addImport(Map.class);
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
        builder.addInnerClass(innerClassBuilder.build());
    }

    private void appendBuilderBody(InnerClass.Builder builder, BodyContext ctx) {
        if (!ctx.doingConcreteType()) {
            // prepare builder fields, starting with final (list, map, set)
            for (int i = 0; i < ctx.allAttributeNames().size(); i++) {
                String beanAttributeName = ctx.allAttributeNames().get(i);
                TypedElementName method = ctx.allTypeInfos().get(i);
                TypeName typeName = method.typeName();
                if (typeName.isList() || typeName.isMap() || typeName.isSet()) {
                    addCollectionField(builder, ctx, method, typeName, beanAttributeName);
                }
            }
            // then any other field
            for (int i = 0; i < ctx.allAttributeNames().size(); i++) {
                String beanAttributeName = ctx.allAttributeNames().get(i);
                TypedElementName method = ctx.allTypeInfos().get(i);
                TypeName typeName = method.typeName();
                if (typeName.isList() || typeName.isMap() || typeName.isSet()) {
                    continue;
                }
                addBuilderField(builder, ctx, method, typeName, beanAttributeName);
            }
        }

        Constructor.Builder constructorBuilder = Constructor.builder(ctx.genericBuilderClassDecl())
                .javadoc(Javadoc.create("Fluent API builder constructor."))
                .accessModifier(AccessModifier.PROTECTED);
        if (ctx.doingConcreteType()) {
            constructorBuilder.addLine("super();");
        } else {
            if (ctx.hasParent()) {
                constructorBuilder.addLine("super();");
            }
            appendOverridesOfDefaultValues(constructorBuilder, ctx);
        }
        builder.addConstructor(constructorBuilder.build());
    }

    private void addBuilderField(InnerClass.Builder builder,
                                 BodyContext ctx,
                                 TypedElementName method,
                                 TypeName type,
                                 String beanAttributeName) {
        Field.Builder fieldBuilder = Field.builder(beanAttributeName, type.fqName())
                .javadoc(Javadoc.create("Field value for {@code " + method + "()}."))
                .accessModifier(AccessModifier.PRIVATE);
        toConfiguredOptionValue(method, true, true)
                .ifPresentOrElse(defaultValue -> fieldBuilder.defaultValue(constructDefaultValue(method, defaultValue)),
                                 () -> {
                                     if (type.isOptional()) {
                                         fieldBuilder.defaultValue("java.util.Optional.empty()");
                                     }
                                 });
        builder.addField(fieldBuilder);
    }

    private void addCollectionField(InnerClass.Builder builder,
                                    BodyContext ctx,
                                    TypedElementName method,
                                    TypeName typeName,
                                    String beanAttributeName) {
        Field field = Field.builder(beanAttributeName, typeName.fqName())
                .isFinal(true)
                .accessModifier(AccessModifier.PROTECTED)
                .defaultValue("new " + collectionType(ctx, typeName) + "<>();")
                .javadoc(Javadoc.create("Field value for {@code " + method + "()}."))
                .build();
        builder.addField(field);
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

    private InnerClass.Builder createInnerClassBuilder(BodyContext ctx) {
        Javadoc.Builder javadocBuilder = Javadoc.builder()
                .addLine("Fluent API builder for {@code " + ctx.genericBuilderAcceptAliasDecl() + "}.");
        if (!ctx.doingConcreteType()) {
            javadocBuilder.addParameter("<" + ctx.genericBuilderAliasDecl() + ">",
                                        "the type of the builder")
                    .addParameter("<" + ctx.genericBuilderAcceptAliasDecl() + ">",
                                  "the type of the built instance");
        }

        InnerClass.Builder builder = InnerClass.builder(ctx.genericBuilderClassDecl())
                .javadoc(javadocBuilder.build())
                .accessModifier(ctx.publicOrPackagePrivateDecl())
                .isStatic(true);
        if (!ctx.doingConcreteType()) {
            builder.isAbstract(true);
        }

        if (ctx.doingConcreteType()) {
            TypeName parentType = toAbstractImplTypeName(ctx.typeInfo().typeName(), ctx.builderTriggerAnnotation());
            Type extendsType = Type.generic(parentType.fqName() + "$" + ctx.genericBuilderClassDecl())
                    .addParam(ctx.genericBuilderClassDecl())
                    .addParam(ctx.ctorBuilderAcceptTypeName().fqName())
                    .build();
            builder.inheritance(extendsType);
        } else {
            builder.addGenericParameter(Type.token(ctx.genericBuilderAliasDecl(),
                                                   Type.generic(ctx.genericBuilderClassDecl())
                                                           .addParam(Type.token(ctx.genericBuilderAliasDecl()))
                                                           .addParam(Type.token(ctx.genericBuilderAcceptAliasDecl()))
                                                           .build()));
            builder.addGenericParameter(Type.token(ctx.genericBuilderAcceptAliasDecl(),
                                                   Type.create(ctx.ctorBuilderAcceptTypeName().fqName())));

            if (ctx.hasParent()) {
                TypeName parentType = toAbstractImplTypeName(ctx.parentTypeName().orElseThrow(), ctx.builderTriggerAnnotation());
                Type extendsType = Type.generic(parentType.fqName() + "$" + ctx.genericBuilderClassDecl())
                        .addParam(Type.token(ctx.genericBuilderAliasDecl()))
                        .addParam(Type.token(ctx.genericBuilderAcceptAliasDecl()))
                        .build();
                builder.inheritance(extendsType);
            } else {
                Optional<TypeName> baseExtendsTypeName = baseExtendsBuilderTypeName(ctx);
                if (baseExtendsTypeName.isEmpty() && ctx.isExtendingAnAbstractClass()) {
                    baseExtendsTypeName = Optional.of(ctx.typeInfo().typeName());
                }
                baseExtendsTypeName.ifPresent(typeName -> builder.inheritance(typeName.fqName()));
            }

            if (!ctx.isExtendingAnAbstractClass() && !ctx.hasAnyBuilderClashingMethodNames()) {
                builder.addInterface(ctx.typeInfo().typeName().name());
            }
            if (!ctx.hasParent()) {
                if (ctx.hasStreamSupportOnBuilder() && !ctx.requireLibraryDependencies()) {
                    builder.addInterface(Type.generic(Supplier.class)
                                                 .addParam(Type.token(ctx.genericBuilderAcceptAliasDecl()))
                                                 .build());
                }

                if (ctx.requireLibraryDependencies()) {
                    builder.addInterface(Type.generic(io.helidon.common.Builder.class)
                                                 .addParam(Type.token(ctx.genericBuilderAliasDecl()))
                                                 .addParam(Type.token(ctx.genericBuilderAcceptAliasDecl()))
                                                 .build());
                }
                extraImplementedBuilderContracts(ctx).forEach(t -> builder.addInterface(t.fqName()));
            }
        }
        return builder;
    }

    private void appendToBuilderMethods(ClassModel.Builder builder, BodyContext ctx) {
        if (!ctx.doingConcreteType()) {
            return;
        }

        Method.Builder builderMethod = Method.builder("builder", ctx.implTypeName() + "$Builder")
                .isStatic(true)
                .javadoc(Javadoc.builder()
                                 .addLine("Creates a builder for this type.")
                                 .returnDescription("a builder for {@link " + ctx.typeInfo().typeName() + "}")
                                 .build())
                .addLine("return new Builder();");
        builder.addMethod(builderMethod);

        Javadoc javadoc = Javadoc.builder()
                .addLine("Creates a builder for this type, initialized with the attributes from the values passed.")
                .addParameter("val", "the value to copy to initialize the builder attributes")
                .returnDescription("a builder for {@link " + ctx.typeInfo().typeName() + "}")
                .build();
        Method.Builder toBuilderMethod = Method.builder("toBuilder", ctx.implTypeName()+ "$Builder")
                .isStatic(true)
                .javadoc(javadoc)
                .addParameter(Parameter.create("val", ctx.ctorBuilderAcceptTypeName().fqName()))
                .addLine("Objects.requireNonNull(val);")
                .addLine("return builder().accept(val);");
        builder.addMethod(toBuilderMethod);

//        appendExtraToBuilderBuilderFunctions(builder, ctx, "???????"); //TODO upravit
    }

    private void appendInterfaceBasedGetters(AbstractClass.Builder<?, ?> builder, BodyContext ctx) {
        if (ctx.doingConcreteType()) {
            return;
        }

        int i = 0;
        for (String beanAttributeName : ctx.allAttributeNames()) {
            TypedElementName method = ctx.allTypeInfos().get(i++);
            Method.Builder methodBuilder = Method.builder(method.elementName(), toType(method.typeName()))
                    .addAnnotation(io.helidon.builder.processor.tools.model.Annotation.create(Override.class))
                    .addLine("return " + beanAttributeName + ";");
            appendAnnotations(methodBuilder, method.annotations());
            builder.addMethod(methodBuilder);
        }

        if (ctx.parentAnnotationTypeName().isPresent()) {
            Type returnType = Type.generic(Class.class).addParam(Type.token("?", Annotation.class)).build();
            Method.Builder methodBuilder = Method.builder("annotationType", returnType)
                    .addLine("return " + ctx.typeInfo().superTypeInfo().get().typeName() + ".class;");
            builder.addMethod(methodBuilder);
        }
//        ctx.typeInfo().superTypeInfo().ifPresent(typeInfo -> {
//            Type returnType = Type.builder(Class.class).addParam(Annotation.class).build();
//            Method.Builder methodBuilder = Method.builder("annotationType", returnType)
//                    .addLine("return " + typeInfo.typeName() + ".class;");
//            builder.addMethod(methodBuilder);
//        });
    }

    private void appendCtor(ClassModel.Builder builder,
                            BodyContext ctx) {
        Constructor.Builder constorBuilder = Constructor.builder(ctx.implTypeName().fqName())
                .javadoc(Javadoc.builder()
                                 .addLine("Constructor using the builder argument.")
                                 .addParameter("b", "the builder")
                                 .build())
                .accessModifier(AccessModifier.PROTECTED);

        String builderClass = ctx.implTypeName().fqName() + "$" +ctx.genericBuilderClassDecl();
        if (ctx.doingConcreteType()) {
            constorBuilder.addParameter(Parameter.create("b", Type.create(builderClass)))
                    .addLine("super(b);");
        } else {
            constorBuilder.addParameter(Parameter.create("b", Type.generic(builderClass)
                    .addParam(Type.token("?"))
                    .addParam(Type.token("?"))
                    .build()));
            StringBuilder sb = new StringBuilder();
            appendExtraCtorCode(sb, ctx, "b");
            appendCtorCodeBody(sb, ctx, "b");
            constorBuilder.content(sb.toString());
        }
        builder.addConstructor(constorBuilder.build());
    }

    /**
     * Appends the constructor body.
     *
     * @param builder           the builder
     * @param ctx               the context
     * @param builderTag        the tag (variable name) used for the builder arg
     */
    protected void appendCtorCodeBody(StringBuilder builder,
                                      BodyContext ctx,
                                      String builderTag) {
        if (ctx.hasParent()) {
            builder.append("\t\tsuper(").append(builderTag).append(");\n");
        }
        int i = 0;
        for (String beanAttributeName : ctx.allAttributeNames()) {
            TypedElementName method = ctx.allTypeInfos().get(i++);
            builder.append("\t\tthis.").append(beanAttributeName).append(" = ");

            if (method.typeName().isList()) {
                builder.append("Collections.unmodifiableList(new ")
                        .append(ctx.listType()).append("<>(").append(builderTag).append(".")
                        .append(beanAttributeName).append("));\n");
            } else if (method.typeName().isMap()) {
                builder.append("Collections.unmodifiableMap(new ")
                        .append(ctx.mapType()).append("<>(").append(builderTag).append(".")
                        .append(beanAttributeName).append("));\n");
            } else if (method.typeName().isSet()) {
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
            Method.Builder methodBuilder = Method.builder("hashCode", int.class)
                    .addAnnotation(io.helidon.builder.processor.tools.model.Annotation.create(Override.class));

            methodBuilder.add("return Objects.hash(");
            if (ctx.hasParent()) {
                methodBuilder.add("super.hashCode(), ");
            }
            String methods = ctx.allTypeInfos().stream()
                    .map(method -> method.elementName() + "()")
                    .collect(Collectors.joining(", "));
            methodBuilder.addLine(methods + ");");
            builder.addMethod(methodBuilder);
        }

        if (!ctx.hasOtherMethod("equals", ctx.typeInfo())) {
            builder.addImport(Objects.class);

            Method.Builder methodBuilder = Method.builder("equals", boolean.class)
                    .addParameter(Parameter.create("o", Object.class))
                    .addAnnotation(io.helidon.builder.processor.tools.model.Annotation.create(Override.class));

            methodBuilder.addLine("if (this == o) {");
            methodBuilder.padding().addLine("return true;");
            methodBuilder.addLine("}");
            methodBuilder.addLine("if (o instanceof " + ctx.typeInfo().typeName().className() + " other) {");
            methodBuilder.padding().add("return ");
            if (ctx.hasParent()) {
                methodBuilder.addLine("super.equals(other) && ").padding().padding();
            }
            boolean first = true;
            for (TypedElementName method : ctx.allTypeInfos()) {
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
        Method.Builder methodBuilder = Method.builder("toStringInner", String.class)
                .accessModifier(AccessModifier.PROTECTED)
                .javadoc(Javadoc.builder()
                                 .addLine("Produces the inner portion of the toString() output (i.e., what is between the parents).")
                                 .returnDescription("portion of the toString output")
                                 .build());
        if (ctx.hasParent()) {
            methodBuilder.addAnnotation(io.helidon.builder.processor.tools.model.Annotation.create(Override.class));
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
            TypedElementName method = ctx.allTypeInfos().get(i++);
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

    private String constructDefaultValue(TypedElementName method, String defaultVal) {
        StringBuilder builder = new StringBuilder();
        TypeName type = method.typeName();
        boolean isOptional = type.isOptional();
        if (isOptional) {
            builder.append(Optional.class.getName()).append(".of(");
            if (!type.typeArguments().isEmpty()) {
                type = type.typeArguments().get(0);
            }
        }

        boolean isString = type.name().equals(String.class.getName()) && !type.array();
        boolean isCharArr = type.fqName().equals("char[]");
        if ((isString || isCharArr) && !defaultVal.startsWith("\"")) {
            builder.append("\"");
        } else if (!type.primitive() && !type.name().startsWith("java.")) {
            builder.append(type.name()).append(".");
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

    private void appendOverridesOfDefaultValues(Constructor.Builder builder,
                                                BodyContext ctx) {
        for (TypedElementName method : ctx.typeInfo().elementInfo()) {
            String beanAttributeName = toBeanAttributeName(method, ctx.beanStyleRequired());
            if (!ctx.allAttributeNames().contains(beanAttributeName)) {
                // candidate for override...
                String thisDefault = toConfiguredOptionValue(method, true, true).orElse(null);
                String superDefault = superValue(ctx.typeInfo().superTypeInfo(), beanAttributeName, ctx.beanStyleRequired());
                if (hasNonBlankValue(thisDefault) && !Objects.equals(thisDefault, superDefault)) {
                    appendDefaultOverride(builder, beanAttributeName, method, thisDefault);
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
        Optional<TypedElementName> method = superTypeInfo.elementInfo().stream()
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

    private void appendDefaultOverride(Constructor.Builder builder,
                                       String attrName,
                                       TypedElementName method,
                                       String override) {
        String defaultValue = constructDefaultValue(method, override);
        builder.addLine(attrName + "(" +defaultValue + ");");
    }

    private void appendCustomMapOf(ClassModel.Builder builder) {
        builder.addImport(LinkedHashMap.class);
        Type type = Type.generic(Map.class)
                .addParam(String.class)
                .addParam(Object.class)
                .build();
        builder.addMethod(Method.builder("__mapOf", type)
                                  .isStatic(true)
                                  .addParameter(Parameter.builder("args", Object.class).optional(true).build()) //Need to be optional
                                  .addLine("Map<String, Object> result = new LinkedHashMap<>(args.length / 2);")
                                  .addLine("int i = 0;")
                                  .addLine("while (i < args.length) {")
                                  .padding().addLine("result.put((String) args[i], args[i + 1]);")
                                  .padding().addLine("i += 2;")
                                  .addLine("}")
                                  .addLine("return result;"));
    }

    private String mapOf(String attrName,
                         TypedElementName method,
                         AtomicBoolean needsCustomMapOf) {
        Optional<? extends AnnotationAndValue> configuredOptions = DefaultAnnotationAndValue
                .findFirst(ConfiguredOption.class.getName(), method.annotations());

        TypeName typeName = method.typeName();
        String typeDecl = "\"__type\", " + typeName.name() + ".class";
        if (!typeName.typeArguments().isEmpty()) {
            int pos = typeName.typeArguments().size() - 1;
            typeDecl += ", \"__componentType\", " + normalize(typeName.typeArguments().get(pos).name()) + ".class";
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

    private String normalize(String name) {
        return name.equals("?") ? "Object" : name;
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
