/*
 * Copyright (c) 2023 Oracle and/or its affiliates.
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

package io.helidon.builder.config.processor;

import java.lang.annotation.Annotation;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import io.helidon.builder.config.ConfigBean;
import io.helidon.builder.config.spi.ConfigBeanBuilderValidator;
import io.helidon.builder.config.spi.ConfigBeanInfo;
import io.helidon.builder.config.spi.ConfigResolver;
import io.helidon.builder.config.spi.DefaultConfigResolverRequest;
import io.helidon.builder.config.spi.GeneratedConfigBean;
import io.helidon.builder.config.spi.GeneratedConfigBeanBase;
import io.helidon.builder.config.spi.GeneratedConfigBeanBuilder;
import io.helidon.builder.config.spi.GeneratedConfigBeanBuilderBase;
import io.helidon.builder.config.spi.MetaConfigBeanInfo;
import io.helidon.builder.config.spi.ResolutionContext;
import io.helidon.builder.processor.tools.BodyContext;
import io.helidon.builder.processor.tools.DefaultBuilderCreatorProvider2;
import io.helidon.builder.processor.tools.model.AccessModifier;
import io.helidon.builder.processor.tools.model.ClassModel;
import io.helidon.builder.processor.tools.model.Field;
import io.helidon.builder.processor.tools.model.InnerClass;
import io.helidon.builder.processor.tools.model.Method;
import io.helidon.builder.processor.tools.model.Parameter;
import io.helidon.builder.processor.tools.model.Type;
import io.helidon.common.Weight;
import io.helidon.common.Weighted;
import io.helidon.common.config.Config;
import io.helidon.common.types.AnnotationAndValue;
import io.helidon.common.types.DefaultAnnotationAndValue;
import io.helidon.common.types.DefaultTypeName;
import io.helidon.common.types.TypeInfo;
import io.helidon.common.types.TypeName;
import io.helidon.common.types.TypedElementName;
import io.helidon.config.metadata.ConfiguredOption;

import static io.helidon.builder.config.spi.ConfigBeanInfo.LevelType;
import static io.helidon.builder.config.spi.ConfigBeanInfo.TAG_AT_LEAST_ONE;
import static io.helidon.builder.config.spi.ConfigBeanInfo.TAG_DRIVES_ACTIVATION;
import static io.helidon.builder.config.spi.ConfigBeanInfo.TAG_KEY;
import static io.helidon.builder.config.spi.ConfigBeanInfo.TAG_LEVEL_TYPE;
import static io.helidon.builder.config.spi.ConfigBeanInfo.TAG_REPEATABLE;
import static io.helidon.builder.config.spi.ConfigBeanInfo.TAG_WANT_DEFAULT_CONFIG_BEAN;

/**
 * A specialization of {@link io.helidon.builder.processor.tools.DefaultBuilderCreatorProvider} that supports the additional
 * add-ons to the builder generated classes that binds to the config sub-system.
 *
 * @see GeneratedConfigBean
 * @see GeneratedConfigBeanBuilder
 */
@Weight(Weighted.DEFAULT_WEIGHT)
public class ConfigBeanBuilderCreator2 extends DefaultBuilderCreatorProvider2 {
    static final String PICO_CONTRACT_TYPENAME = "io.helidon.pico.api.Contract";
    static final String PICO_EXTERNAL_CONTRACT_TYPENAME = "io.helidon.pico.api.ExternalContracts";
    static final String PICO_CONFIGUREDBY_TYPENAME = "io.helidon.pico.configdriven.ConfiguredBy";

    /**
     * Default constructor.
     */
    // note: this needs to remain public since it will be resolved via service loader ...
    @Deprecated
    public ConfigBeanBuilderCreator2() {
    }

    @Override
    public Set<Class<? extends Annotation>> supportedAnnotationTypes() {
        return Set.of(ConfigBean.class);
    }

    @Override
    protected void preValidate(TypeName implTypeName,
                               TypeInfo typeInfo,
                               AnnotationAndValue configBeanAnno) {
        assertNoAnnotation(PICO_CONTRACT_TYPENAME, typeInfo);
        assertNoAnnotation(PICO_EXTERNAL_CONTRACT_TYPENAME, typeInfo);
        assertNoAnnotation(PICO_CONFIGUREDBY_TYPENAME, typeInfo);
        assertNoAnnotation(jakarta.inject.Singleton.class.getName(), typeInfo);
        assertNoAnnotation("javax.inject.Singleton", typeInfo);

        if (!typeInfo.typeKind().equals(TypeInfo.KIND_INTERFACE)) {
            throw new IllegalStateException("@" + configBeanAnno.typeName().className()
                                                    + " is only supported on interface types: " + typeInfo.typeName());
        }

        boolean drivesActivation = Boolean.parseBoolean(configBeanAnno.value(TAG_DRIVES_ACTIVATION).orElseThrow());
        LevelType levelType = LevelType.valueOf(configBeanAnno.value(TAG_LEVEL_TYPE).orElseThrow());
        if (drivesActivation && levelType != LevelType.ROOT) {
            throw new IllegalStateException("Only levelType {" + LevelType.ROOT + "} config beans can drive activation for: "
                                                    + typeInfo.typeName());
        }

        boolean wantDefaultConfigBean = Boolean.parseBoolean(configBeanAnno.value(TAG_WANT_DEFAULT_CONFIG_BEAN).orElseThrow());
        if (wantDefaultConfigBean && levelType != LevelType.ROOT) {
            throw new IllegalStateException("Only levelType {" + LevelType.ROOT + "} config beans can have a default bean for: "
                                                    + typeInfo.typeName());
        }

        assertNoGenericMaps(typeInfo);

        super.preValidate(implTypeName, typeInfo, configBeanAnno);
    }

    /**
     * Generic/simple map types are not supported on config beans, only &lt;String, &lt;Known ConfigBean types&gt;&gt;.
     */
    private void assertNoGenericMaps(TypeInfo typeInfo) {
        List<TypedElementName> list = typeInfo.elementInfo().stream()
                .filter(it -> it.typeName().isMap())
                .filter(it -> {
                    TypeName typeName = it.typeName();
                    List<TypeName> componentArgs = typeName.typeArguments();
                    boolean bad = (componentArgs.size() != 2);
                    if (!bad) {
                        bad = !componentArgs.get(0).name().equals(String.class.getName());
                        // right now we will accept any component type - ConfigBean Type or other (just not generic)
//                        bad |= !typeInfo.referencedTypeNamesToAnnotations().containsKey(componentArgs.get(1));
                        bad |= componentArgs.get(1).generic();
                    }
                    return bad;
                })
                .collect(Collectors.toList());

        if (!list.isEmpty()) {
            throw new IllegalStateException(list + ": only methods returning Map<String, <any-non-generic-type>> are supported "
                                                    + "for: " + typeInfo.typeName());
        }
    }

    @Override
    protected String generatedVersionFor(BodyContext ctx) {
        return Versions.CURRENT_BUILDER_CONFIG_VERSION;
    }

    @Override
    protected Optional<TypeName> baseExtendsTypeName(BodyContext ctx) {
        return Optional.of(DefaultTypeName.create(GeneratedConfigBeanBase.class));
    }

    @Override
    protected Optional<TypeName> baseExtendsBuilderTypeName(BodyContext ctx) {
        return Optional.of(DefaultTypeName.create(GeneratedConfigBeanBuilderBase.class));
    }

    @Override
    protected String instanceIdRef(BodyContext ctx) {
        return "__instanceId()";
    }

    @Override
    protected void appendExtraImports(StringBuilder builder,
                                      BodyContext ctx) {
        builder.append("\nimport ").append(AtomicInteger.class.getName()).append(";\n");

        builder.append("import ").append(Optional.class.getName()).append(";\n");
        builder.append("import ").append(Function.class.getName()).append(";\n\n");
        builder.append("import ").append(Supplier.class.getName()).append(";\n\n");

        super.appendExtraImports(builder, ctx);

        builder.append("import ").append(Config.class.getName()).append(";\n");
        builder.append("import ").append(ConfigResolver.class.getName()).append(";\n");
        builder.append("import ").append(ConfigBeanBuilderValidator.class.getName()).append(";\n\n");
    }

    @Override
    protected void appendMetaAttributes(ClassModel.Builder builder, BodyContext ctx) {
        if (ctx.doingConcreteType()) {
            super.appendMetaAttributes(builder, ctx);
            return;
        }
        builder.addMethod(Method.builder("__configBeanType")
                                  .returnType(Type.generic(Class.class).addParam(Type.token("?")).build())
                                  .addAnnotation(io.helidon.builder.processor.tools.model.Annotation.create(Override.class))
                                  .generateJavadoc(false)
                                  .addLine("return " + ctx.typeInfo().typeName().name() + ".class;"));

        builder.addMethod(Method.builder("__thisConfigBeanType")
                                  .returnType(Type.generic(Class.class).addParam(Type.token("?")).build())
                                  .isStatic(true)
                                  .addAnnotation(io.helidon.builder.processor.tools.model.Annotation.create(Override.class))
                                  .generateJavadoc(false)
                                  .addLine("return " + ctx.typeInfo().typeName().name() + ".class;"));
        super.appendMetaAttributes(builder, ctx);
    }

    @Override
    protected void appendMetaProps(Method.Builder builder,
                                   BodyContext ctx,
                                   String tag,
                                   AtomicBoolean needsCustomMapOf) {
        builder.add(tag).add(".put(\"__meta\", Map.of(\"").add(ConfigBeanInfo.class.getName()).addLine("\",");
        builder.add(MetaConfigBeanInfo.class.getName()).addLine(".builder()");
        appendConfigBeanInfoAttributes(builder,
                                       ctx.typeInfo(),
                                       DefaultAnnotationAndValue
                                               .findFirst(ConfigBean.class.getTypeName(),
                                                          ctx.typeInfo().annotations()).orElseThrow());
        builder.addLine(".build()));");
        super.appendMetaProps(builder, ctx, tag, needsCustomMapOf);
    }

    @Override
    protected void appendExtraFields(ClassModel.Builder builder, BodyContext ctx) {
        super.appendExtraFields(builder, ctx);
        if (!ctx.hasParent() && !ctx.doingConcreteType()) {
            builder.addField(Field.builder("__INSTANCE_ID", AtomicInteger.class)
                                     .accessModifier(AccessModifier.PRIVATE)
                                     .isFinal(true)
                                     .isStatic(true)
                                     .defaultValue("new AtomicInteger();"));
        }
    }

    @Override
    protected void appendExtraCtorCode(StringBuilder builder,
                                       BodyContext ctx,
                                       String builderTag) {
        if (!ctx.hasParent()) {
            builder.append("super(b, b.__config().isPresent() ? String.valueOf(__INSTANCE_ID.getAndIncrement()) : "
                                   + "\"-1\");\n");
        }

        super.appendExtraCtorCode(builder, ctx, builderTag);
    }

    @Override
    protected void appendClassComponents(ClassModel.Builder builder, BodyContext ctx) {
        Method toBuilderMethod = Method.builder("toBuilder")
                .description("Creates a builder for this type, initialized with the Config value passed.")
                .returnType(ctx.implTypeName() + "$Builder", "a fluent builder for {@link " + ctx.typeInfo().typeName() + "}")
                .addParameter(Parameter.builder("cfg", Config.class).description("the config to copy and initialize from"))
                .addLine("Builder b = builder();")
                .addLine("b.acceptConfig(cfg, true);")
                .addLine("return b;")
                .build();
        builder.addMethod(toBuilderMethod);
    }

    @Override
    protected void appendBuilderClassComponents(InnerClass.Builder builder, BodyContext ctx) {
        if (ctx.doingConcreteType()) {
            super.appendExtraBuilderMethods(builder, ctx);
            return;
        }

        if (!ctx.hasParent()) {
            acceptConfigMethod(builder);
        }

        if (!ctx.doingConcreteType()) {
            Method.Builder acceptAndResolveBuilder = Method.builder("__acceptAndResolve")
                    .description("Accept the config, resolves it, optionally validates.");
            if (ctx.hasParent()) {
                acceptAndResolveBuilder.generateJavadoc(false)
                        .addAnnotation(io.helidon.builder.processor.tools.model.Annotation.create(Override.class));
            }
            acceptAndResolveBuilder.accessModifier(AccessModifier.PROTECTED)
                    .addParameter(Parameter.builder("ctx", ResolutionContext.class)
                                          .description("the config resolution context"));
            if (ctx.hasParent()) {
                acceptAndResolveBuilder.addLine("super.__acceptAndResolve(ctx);");
            }

            int i = 0;
            for (String attrName : ctx.allAttributeNames()) {
                TypedElementName method = ctx.allTypeInfos().get(i);
                String configKey = toConfigKey(attrName, method, ctx.builderTriggerAnnotation());

                // resolver.of(config, "port", int.class).ifPresent(this::port);
                String ofClause = "of";
                TypeName outerType = method.typeName();
                String outerTypeName = outerType.declaredName();
                TypeName type = outerType;
                String typeName = type.declaredName();
                TypeName mapKeyType = null;
                TypeName mapKeyComponentType = null;
                boolean isMap = typeName.equals(Map.class.getName());
                boolean isCollection = (typeName.equals(Collection.class.getName())
                                                || typeName.equals(Set.class.getName())
                                                || typeName.equals(List.class.getName()));
                if (isCollection) {
                    ofClause = "ofCollection";
                    type = type.typeArguments().get(0);
                    typeName = type.declaredName();
                } else if (isMap) {
                    ofClause = "ofMap";
                    mapKeyType = type.typeArguments().get(0);
                    if (!mapKeyType.typeArguments().isEmpty()) {
                        mapKeyComponentType = mapKeyType.typeArguments().get(0);
                    }
                    type = type.typeArguments().get(1);
                    typeName = type.declaredName();
                } else if (Optional.class.getName().equals(typeName)) {
                    type = type.typeArguments().get(0);
                    typeName = type.declaredName();
                }

                acceptAndResolveBuilder.add("ctx.resolver().")
                        .add(ofClause)
                        .add("(ctx, __metaAttributes(), ")
                        .add(DefaultConfigResolverRequest.class.getPackage().getName() + ".DefaultConfigResolver");
                if (isMap) {
                    acceptAndResolveBuilder.add("Map");
                }
                acceptAndResolveBuilder.addLine("Request.builder()")
                        .add(".configKey(\"").add(configKey).add("\").attributeName(\"" + attrName + "\")")
                        .add(".valueType(").add(outerTypeName).add(".class)");
                if (type != outerType) {
                    acceptAndResolveBuilder.add(".valueComponentType(").add(typeName).add(".class)");
                }
                if (isMap) {
                    acceptAndResolveBuilder.add(".keyType(").add(mapKeyType.name()).add(".class)");
                    if (mapKeyComponentType != null) {
                        acceptAndResolveBuilder.add(".keyComponentType(").add(mapKeyComponentType.name()).add(".class)");
                    }
                }
                acceptAndResolveBuilder.addLine(".build())")
                        .padding().add(".ifPresent(val -> this.").add(method.elementName())
                        .add("((").add(outerTypeName).addLine(") val));");
                i++;
            }
            builder.addMethod(acceptAndResolveBuilder);

            Method.Builder configBeanTypeBuilder = Method.builder("__configBeanType")
                    .returnType(Type.generic(Class.class)
                                        .addParam(Type.token("?"))
                                        .build())
                    .generateJavadoc(false)
                    .addAnnotation(io.helidon.builder.processor.tools.model.Annotation.create(Override.class))
                    .addLine("return " + ctx.typeInfo().typeName().name() + ".class;");
            builder.addMethod(configBeanTypeBuilder);

            Type mappersType = Type.generic(Map.class)
                    .addParam(Type.generic(Class.class).addParam(Type.token("?")).build())
                    .addParam(Type.generic(Function.class)
                                      .addParam(Type.create(Config.class))
                                      .addParam(Type.token("?"))
                                      .build())
                    .build();
            Method.Builder mappersBuilder = Method.builder("__mappers")
                    .returnType(mappersType)
                    .generateJavadoc(false)
                    .addAnnotation(io.helidon.builder.processor.tools.model.Annotation.create(Override.class))
                    .addLine("return " + ctx.typeInfo().typeName().name() + ".class;")
                    .add("Map<Class<?>, Function<Config, ?>> result = ");

            if (ctx.hasParent()) {
                mappersBuilder.addLine("super.__mappers();");
            } else {
                mappersBuilder.addLine("new java.util.LinkedHashMap<>();");
            }
            appendAvailableReferencedBuilders(mappersBuilder, ctx.typeInfo());
            mappersBuilder.addLine("return result;");
            builder.addMethod(mappersBuilder);
        }
    }

    private void acceptConfigMethod(InnerClass.Builder builder) {
        Method acceptConfig = Method.builder("acceptConfig")
                .generateJavadoc(false)
                .addAnnotation(io.helidon.builder.processor.tools.model.Annotation.create(Override.class))
                .addParameter(Parameter.create("cfg", Config.class))
                .addParameter(Parameter.create("resolver", ConfigResolver.class))
                .addParameter(Parameter.create("validator", Type.generic(ConfigBeanBuilderValidator.class)
                        .addParam(Type.token("?"))
                        .build()))
                .addLine(ResolutionContext.class.getName() + " ctx = "
                                 + "createResolutionContext(__configBeanType(), cfg, resolver, validator, __mappers());")
                .addLine("__config(ctx.config());")
                .addLine("__acceptAndResolve(ctx);")
                .addLine("super.finishedResolution(ctx);")
                .build();
        builder.addMethod(acceptConfig);
    }

    private void appendAvailableReferencedBuilders(Method.Builder builder, TypeInfo typeInfo) {
        typeInfo.referencedTypeNamesToAnnotations().forEach((k, v) -> {
            AnnotationAndValue builderAnnotation = DefaultAnnotationAndValue
                    .findFirst(io.helidon.builder.Builder.class.getName(), v).orElse(null);
            if (builderAnnotation == null) {
                builderAnnotation = DefaultAnnotationAndValue
                        .findFirst(ConfigBean.class.getName(), v).orElse(null);
            }

            if (builderAnnotation != null) {
                TypeName referencedBuilderTypeName = toBuilderImplTypeName(k, builderAnnotation);
                builder.add("result.put(").add(k.name()).add(".class, ")
                        .add(referencedBuilderTypeName.toString()).addLine("::toBuilder);");
            }
        });
    }

    @Override
    protected boolean overridesVisitAttributes(BodyContext ctx) {
        return true;
    }

    @Override
    protected String toConfigKey(String name,
                                 boolean isAttribute) {
        return (isAttribute) ? ConfigBeanInfo.toConfigAttributeName(name) : ConfigBeanInfo.toConfigBeanName(name);
    }

    private void appendConfigBeanInfoAttributes(Method.Builder builder,
                                                TypeInfo typeInfo,
                                                AnnotationAndValue configBeanAnno) {
        String configKey = configBeanAnno.value(TAG_KEY).orElse(null);
        configKey = Objects.requireNonNull(normalizeConfiguredOptionKey(configKey, typeInfo.typeName().className(), false));
        builder.add(".value(\"").add(configKey).addLine("\")");
        builder.add(".").add(TAG_REPEATABLE).add("(").add(configBeanAnno.value(TAG_REPEATABLE).orElseThrow()).addLine(")");
        builder.add(".").add(TAG_DRIVES_ACTIVATION).add("(")
                .add(configBeanAnno.value(TAG_DRIVES_ACTIVATION).orElseThrow()).addLine(")");
        builder.add(".").add(TAG_AT_LEAST_ONE).add("(").add(configBeanAnno.value(TAG_AT_LEAST_ONE).orElseThrow()).addLine(")");
        builder.add(".").add(TAG_WANT_DEFAULT_CONFIG_BEAN).add("(")
                .add(configBeanAnno.value(TAG_WANT_DEFAULT_CONFIG_BEAN).orElseThrow()).addLine(")");
        builder.add(".").add(TAG_LEVEL_TYPE).add("(").add(LevelType.class.getCanonicalName()).add(".")
                .add(configBeanAnno.value(TAG_LEVEL_TYPE).orElseThrow()).addLine(")");
    }

    private String toConfigKey(String attrName,
                               TypedElementName method,
                               AnnotationAndValue ignoredBuilderAnnotation) {
        String configKey = null;
        Optional<? extends AnnotationAndValue> configuredOptions = DefaultAnnotationAndValue
                .findFirst(ConfiguredOption.class.getName(), method.annotations());
        if (configuredOptions.isPresent()) {
            configKey = configuredOptions.get().value("key").orElse(null);
        }
        if (configKey == null || configKey.isBlank()) {
            configKey = ConfigBeanInfo.toConfigAttributeName(attrName);
        }
        return configKey;
    }

    private static void assertNoAnnotation(String annoTypeName, TypeInfo typeInfo) {
        Optional<? extends AnnotationAndValue> anno = DefaultAnnotationAndValue
                .findFirst(annoTypeName, typeInfo.annotations());
        if (anno.isPresent()) {
            throw new IllegalStateException(annoTypeName + " cannot be used in conjunction with "
                                                    + ConfigBean.class.getName()
                                                    + " on " + typeInfo.typeName());
        }

        for (TypedElementName elem : typeInfo.elementInfo()) {
            anno = DefaultAnnotationAndValue.findFirst(annoTypeName, elem.annotations());
            if (anno.isEmpty()) {
                anno = DefaultAnnotationAndValue.findFirst(annoTypeName, elem.elementTypeAnnotations());
            }
            if (anno.isPresent()) {
                throw new IllegalStateException(annoTypeName + " cannot be used in conjunction with "
                                                        + ConfigBean.class.getName()
                                                        + " on " + typeInfo.typeName() + "." + elem + "()");
            }
        }

        if (typeInfo.superTypeInfo().isPresent()) {
            assertNoAnnotation(annoTypeName, typeInfo.superTypeInfo().get());
        }
    }

}
