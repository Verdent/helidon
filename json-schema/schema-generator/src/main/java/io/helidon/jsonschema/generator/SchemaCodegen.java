package io.helidon.jsonschema.generator;

import java.util.Collection;
import java.util.List;

import io.helidon.codegen.CodegenContext;
import io.helidon.codegen.RoundContext;
import io.helidon.codegen.classmodel.ClassModel;
import io.helidon.codegen.classmodel.TypeArgument;
import io.helidon.codegen.spi.CodegenExtension;
import io.helidon.common.types.AccessModifier;
import io.helidon.common.types.Annotation;
import io.helidon.common.types.Annotations;
import io.helidon.common.types.TypeInfo;
import io.helidon.common.types.TypeName;
import io.helidon.common.types.TypeNames;
import io.helidon.jsonschema.schema.Schema;

class SchemaCodegen implements CodegenExtension {

    private final CodegenContext ctx;
    private final TypeName generatorType;

    public SchemaCodegen(CodegenContext ctx, TypeName generatorType) {
        this.ctx = ctx;
        this.generatorType = generatorType;
    }

    @Override
    public void process(RoundContext roundContext) {

        Collection<TypeInfo> schemas = roundContext.annotatedTypes(Types.JSON_SCHEMA_SCHEMA);
        for (TypeInfo schema : schemas) {
            TypeName annotatedTypeName = schema.typeName();
            SchemaInfo schemaInfo = SchemaInfo.create(schema, ctx);
            TypeName typeName = schemaInfo.generatedSchema();
            Schema helidonSchema = schemaInfo.schema();
            //This includes $ properties
            String schemaJson = helidonSchema.generate();
            String schemaJsonNoKeywords = helidonSchema.generateNoKeywords();
            TypeName returnType = TypeName.builder()
                    .type(Class.class)
                    .addTypeArgument(TypeArgument.create("?"))
                    .build();
            ClassModel.Builder builder = ClassModel.builder()
                    .type(typeName)
                    .accessModifier(AccessModifier.PACKAGE_PRIVATE)
                    .addInterface(Types.JSON_SCHEMA_PROVIDER)
                    .addAnnotation(Annotation.create(Types.SERVICE_SINGLETON))
                    .addAnnotation(Annotation.builder()
                                           .typeName(Types.SERVICE_NAMED_BY_TYPE)
                                           .putValue("value", annotatedTypeName)
                                           .build())
                    .addMethod(it -> it.name("schemaClass")
                            .returnType(returnType)
                            .addAnnotation(Annotations.OVERRIDE)
                            .addContent("return ")
                            .addContent(annotatedTypeName)
                            .addContentLine(".class;"))
                    .addMethod(it -> it.name("schema")
                            .returnType(TypeNames.STRING)
                            .addAnnotation(Annotations.OVERRIDE)
                            .addContentLine("return \"\"\"")
                            .addContentLine(schemaJson)
                            .addContent("\"\"\";"))
                    .addMethod(it -> it.name("schemaNoKeywords")
                            .returnType(TypeNames.STRING)
                            .addAnnotation(Annotations.OVERRIDE)
                            .addContentLine("return \"\"\"")
                            .addContentLine(schemaJsonNoKeywords)
                            .addContent("\"\"\";"));

            roundContext.addGeneratedType(typeName,
                                          builder,
                                          annotatedTypeName,
                                          schema.originatingElement().orElse(annotatedTypeName));
        }

    }

}
