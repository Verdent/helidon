/*
 * Copyright (c) 2026 Oracle and/or its affiliates.
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

package io.helidon.declarative.codegen.grpc.server;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import io.helidon.codegen.CodegenException;
import io.helidon.codegen.CodegenUtil;
import io.helidon.codegen.ElementInfoPredicates;
import io.helidon.codegen.TypeHierarchy;
import io.helidon.codegen.classmodel.ClassModel;
import io.helidon.codegen.classmodel.Constructor;
import io.helidon.common.types.AccessModifier;
import io.helidon.common.types.Annotation;
import io.helidon.common.types.Annotations;
import io.helidon.common.types.ElementKind;
import io.helidon.common.types.TypeInfo;
import io.helidon.common.types.TypeName;
import io.helidon.common.types.TypeNames;
import io.helidon.common.types.TypedElementInfo;
import io.helidon.service.codegen.RegistryCodegenContext;
import io.helidon.service.codegen.RegistryRoundContext;
import io.helidon.service.codegen.ServiceCodegenTypes;
import io.helidon.service.codegen.spi.RegistryCodegenExtension;

import static io.helidon.codegen.CodegenUtil.toConstantName;
import static io.helidon.declarative.codegen.DeclarativeTypes.SINGLETON_ANNOTATION;
import static java.util.function.Predicate.not;

class RpcServerExtension implements RegistryCodegenExtension {
    static final TypeName GENERATOR = TypeName.create(RpcServerExtension.class);

    private final RegistryCodegenContext ctx;

    RpcServerExtension(RegistryCodegenContext ctx) {
        this.ctx = ctx;
    }

    @Override
    public void process(RegistryRoundContext roundContext) {
        Collection<TypeInfo> serverEndpoints = roundContext.annotatedTypes(RpcServerTypes.ANNOTATION_ENDPOINT);

        for (TypeInfo serverEndpoint : serverEndpoints) {
            process(roundContext, serverEndpoint);
        }
    }

    private void process(RegistryRoundContext roundContext, TypeInfo serverEndpoint) {
        if (serverEndpoint.kind() == ElementKind.INTERFACE) {
            throw new CodegenException("Interfaces should not be annotated with "
                                               + RpcServerTypes.ANNOTATION_ENDPOINT.fqName(),
                                       serverEndpoint.originatingElementValue());
        }

        Endpoint endpoint = toEndpoint(serverEndpoint);
        TypeName endpointType = serverEndpoint.typeName();
        TypeName descriptorType = ctx.descriptorType(endpointType);

        String className = endpointType.classNameWithEnclosingNames().replace('.', '_') + "__GrpcRouteRegistration";
        TypeName generatedRegistration = TypeName.builder()
                .packageName(endpointType.packageName())
                .className(className)
                .build();

        ClassModel.Builder classModel = ClassModel.builder()
                .copyright(CodegenUtil.copyright(GENERATOR,
                                                 endpointType,
                                                 generatedRegistration))
                .addAnnotation(CodegenUtil.generatedAnnotation(GENERATOR,
                                                               endpointType,
                                                               generatedRegistration,
                                                               "1",
                                                               ""))
                .accessModifier(AccessModifier.PACKAGE_PRIVATE)
                .type(generatedRegistration)
                .addAnnotation(SINGLETON_ANNOTATION)
                .addInterface(RpcServerTypes.GRPC_ROUTE_REGISTRATION);

        classModel.addField(field -> field
                .accessModifier(AccessModifier.PRIVATE)
                .isFinal(true)
                .type(RpcServerTypes.GRPC_SERVICE_DESCRIPTOR)
                .name("descriptor"));

        classModel.addConstructor(constructor(endpoint,
                                              endpointType,
                                              descriptorType));

        classModel.addMethod(method -> method
                .addAnnotation(Annotations.OVERRIDE)
                .accessModifier(AccessModifier.PUBLIC)
                .returnType(RpcServerTypes.GRPC_SERVICE_DESCRIPTOR)
                .name("descriptor")
                .addContentLine("return descriptor;"));

        addSocketMethods(classModel, endpoint.listener());

        classModel.addMethod(toString -> toString
                .addAnnotation(Annotations.OVERRIDE)
                .accessModifier(AccessModifier.PUBLIC)
                .returnType(TypeNames.STRING)
                .name("toString")
                .addContent("return ")
                .addContentLiteral("gRPC route registration for " + endpointType.className())
                .addContentLine(";"));

        roundContext.addGeneratedType(generatedRegistration,
                                      classModel,
                                      endpointType,
                                      serverEndpoint.originatingElementValue());
    }

    private Constructor.Builder constructor(Endpoint endpoint,
                                            TypeName endpointType,
                                            TypeName descriptorType) {
        Constructor.Builder constructor = Constructor.builder();
        constructor.accessModifier(AccessModifier.PACKAGE_PRIVATE)
                .addAnnotation(Annotation.create(ServiceCodegenTypes.SERVICE_ANNOTATION_INJECT))
                .addParameter(endpointType, "endpoint")
                .addParameter(RpcServerTypes.GRPC_ENTRY_POINTS, "entryPoints")
                .addContent("var serviceDescriptor = ")
                .addContent(descriptorType)
                .addContentLine(".INSTANCE;")
                .addContent("var annotations = ")
                .addContent(descriptorType)
                .addContentLine(".ANNOTATIONS;")
                .addContent("var proto = ");

        if (endpoint.protoMethod().isStatic()) {
            constructor.addContent(endpointType)
                    .addContent(".");
        } else {
            constructor.addContent("endpoint.");
        }
        constructor.addContent(endpoint.protoMethod().name())
                .addContentLine("();")
                .addContent("this.descriptor = ")
                .addContent(RpcServerTypes.GRPC_SERVICE_DESCRIPTOR)
                .addContent(".builder(")
                .addContent(endpointType)
                .addContent(".class, ")
                .addContentLiteral(endpoint.serviceName())
                .addContentLine(")")
                .increaseContentPadding()
                .increaseContentPadding()
                .addContentLine(".proto(proto)");

        for (UnaryMethod unaryMethod : endpoint.unaryMethods()) {
            constructor.addContentLine(".unary(")
                    .increaseContentPadding()
                    .increaseContentPadding()
                    .addContentLiteral(unaryMethod.grpcMethodName())
                    .addContentLine(",")
                    .addContent("entryPoints.unary(serviceDescriptor, annotations, ")
                    .addContent(descriptorType)
                    .addContent(".")
                    .addContent(unaryMethod.descriptorConstant())
                    .addContent(", endpoint::")
                    .addContent(unaryMethod.javaMethodName())
                    .addContentLine("),")
                    .addContent("it -> it.requestType(")
                    .addContent(unaryMethod.requestType())
                    .addContent(".class)")
                    .addContent(".responseType(")
                    .addContent(unaryMethod.responseType())
                    .addContent(".class)")
                    .addContentLine(")");
            constructor.decreaseContentPadding()
                    .decreaseContentPadding();
        }

        constructor.addContentLine(".build();")
                .decreaseContentPadding()
                .decreaseContentPadding();
        return constructor;
    }

    private static void addSocketMethods(ClassModel.Builder classModel, Optional<String> listener) {
        if (listener.isEmpty()) {
            return;
        }

        classModel.addMethod(socket -> socket
                .addAnnotation(Annotations.OVERRIDE)
                .accessModifier(AccessModifier.PUBLIC)
                .returnType(TypeNames.STRING)
                .name("socket")
                .addContent("return ")
                .addContentLiteral(listener.get())
                .addContentLine(";"));

        classModel.addMethod(socketRequired -> socketRequired
                .addAnnotation(Annotations.OVERRIDE)
                .accessModifier(AccessModifier.PUBLIC)
                .returnType(TypeNames.PRIMITIVE_BOOLEAN)
                .name("socketRequired")
                .addContentLine("return true;"));
    }

    private Endpoint toEndpoint(TypeInfo typeInfo) {
        Set<Annotation> typeAnnotations = new HashSet<>(TypeHierarchy.hierarchyAnnotations(ctx, typeInfo));

        String serviceName = Annotations.findFirst(RpcServerTypes.ANNOTATION_SERVICE_NAME, typeAnnotations)
                .flatMap(Annotation::stringValue)
                .filter(not(String::isBlank))
                .orElse(typeInfo.typeName().className());

        Optional<String> listener = Annotations.findFirst(RpcServerTypes.ANNOTATION_LISTENER, typeAnnotations)
                .flatMap(Annotation::stringValue)
                .filter(not(String::isBlank));

        ProtoMethod protoMethod = protoMethod(typeInfo);

        List<UnaryMethod> unaryMethods = new ArrayList<>();
        for (TypedElementInfo element : typeInfo.elementInfo()) {
            if (!ElementInfoPredicates.isMethod(element)
                    || ElementInfoPredicates.isPrivate(element)
                    || ElementInfoPredicates.isStatic(element)) {
                continue;
            }

            Set<Annotation> annotations = new HashSet<>(TypeHierarchy.hierarchyAnnotations(ctx, typeInfo, element));
            MethodAnnotation methodAnnotation = methodAnnotation(typeInfo, element, annotations);
            if (methodAnnotation == null) {
                continue;
            }

            if (methodAnnotation.type() != MethodType.UNARY) {
                throw new CodegenException("Declarative gRPC endpoint " + typeInfo.typeName().fqName()
                                                   + " uses method " + element.signature().text()
                                                   + " annotated with " + methodAnnotation.type().description()
                                                   + ", but only unary methods are supported in the initial declarative slice",
                                           element.originatingElementValue());
            }

            unaryMethods.add(unaryMethod(typeInfo, element, methodAnnotation.annotation()));
        }

        if (unaryMethods.isEmpty()) {
            throw new CodegenException("Declarative gRPC endpoint " + typeInfo.typeName().fqName()
                                               + " does not declare any supported gRPC methods",
                                       typeInfo.originatingElementValue());
        }

        return new Endpoint(typeInfo, serviceName, listener, protoMethod, List.copyOf(unaryMethods));
    }

    private ProtoMethod protoMethod(TypeInfo typeInfo) {
        List<TypedElementInfo> protoMethods = new ArrayList<>();

        for (TypedElementInfo element : typeInfo.elementInfo()) {
            if (!ElementInfoPredicates.isMethod(element) || ElementInfoPredicates.isPrivate(element)) {
                continue;
            }

            Set<Annotation> annotations = new HashSet<>(TypeHierarchy.hierarchyAnnotations(ctx, typeInfo, element));
            if (Annotations.findFirst(RpcServerTypes.ANNOTATION_PROTO, annotations).isPresent()) {
                protoMethods.add(element);
            }
        }

        if (protoMethods.isEmpty()) {
            throw new CodegenException("Declarative gRPC endpoint " + typeInfo.typeName().fqName()
                                               + " must define a method annotated with "
                                               + RpcServerTypes.ANNOTATION_PROTO.fqName(),
                                       typeInfo.originatingElementValue());
        }

        if (protoMethods.size() > 1) {
            throw new CodegenException("Declarative gRPC endpoint " + typeInfo.typeName().fqName()
                                               + " defines multiple @" + RpcServerTypes.ANNOTATION_PROTO.className(),
                                       typeInfo.originatingElementValue());
        }

        TypedElementInfo protoMethod = protoMethods.getFirst();
        if (!protoMethod.parameterArguments().isEmpty()) {
            throw new CodegenException("Method annotated with @" + RpcServerTypes.ANNOTATION_PROTO.className()
                                               + " must not declare parameters: "
                                               + protoMethod.signature().text(),
                                       protoMethod.originatingElementValue());
        }

        if (!protoMethod.typeName().equals(RpcServerTypes.PROTO_FILE_DESCRIPTOR)) {
            throw new CodegenException("Method annotated with @" + RpcServerTypes.ANNOTATION_PROTO.className()
                                               + " must return "
                                               + RpcServerTypes.PROTO_FILE_DESCRIPTOR.fqName() + ": "
                                               + protoMethod.signature().text(),
                                       protoMethod.originatingElementValue());
        }

        return new ProtoMethod(protoMethod.elementName(), ElementInfoPredicates.isStatic(protoMethod));
    }

    private MethodAnnotation methodAnnotation(TypeInfo typeInfo,
                                              TypedElementInfo method,
                                              Set<Annotation> annotations) {
        List<MethodAnnotation> found = new ArrayList<>(4);

        annotation(annotations, RpcServerTypes.ANNOTATION_UNARY, MethodType.UNARY).ifPresent(found::add);
        annotation(annotations, RpcServerTypes.ANNOTATION_SERVER_STREAMING, MethodType.SERVER_STREAMING).ifPresent(found::add);
        annotation(annotations, RpcServerTypes.ANNOTATION_CLIENT_STREAMING, MethodType.CLIENT_STREAMING).ifPresent(found::add);
        annotation(annotations, RpcServerTypes.ANNOTATION_BIDIRECTIONAL, MethodType.BIDIRECTIONAL).ifPresent(found::add);

        if (found.isEmpty()) {
            return null;
        }

        if (found.size() > 1) {
            throw new CodegenException("Declarative gRPC method " + typeInfo.typeName().fqName()
                                               + "." + method.signature().text()
                                               + " declares more than one gRPC method annotation",
                                       method.originatingElementValue());
        }

        return found.getFirst();
    }

    private Optional<MethodAnnotation> annotation(Set<Annotation> annotations,
                                                  TypeName annotationType,
                                                  MethodType methodType) {
        return Annotations.findFirst(annotationType, annotations)
                .map(annotation -> new MethodAnnotation(annotation, methodType));
    }

    private UnaryMethod unaryMethod(TypeInfo typeInfo, TypedElementInfo method, Annotation annotation) {
        if (!method.typeName().equals(TypeNames.PRIMITIVE_VOID)) {
            throw new CodegenException("Unary declarative gRPC method must return void: "
                                               + typeInfo.typeName().fqName() + "." + method.signature().text(),
                                       method.originatingElementValue());
        }

        List<TypedElementInfo> params = method.parameterArguments();
        if (params.size() != 2) {
            throw new CodegenException("Unary declarative gRPC method must declare exactly two parameters "
                                               + "(request, StreamObserver): "
                                               + typeInfo.typeName().fqName() + "." + method.signature().text(),
                                       method.originatingElementValue());
        }

        TypedElementInfo request = params.getFirst();
        TypedElementInfo observer = params.get(1);

        if (!observer.typeName().fqName().equals(RpcServerTypes.STREAM_OBSERVER.fqName())
                || observer.typeName().typeArguments().size() != 1) {
            throw new CodegenException("Unary declarative gRPC method must use "
                                               + RpcServerTypes.STREAM_OBSERVER.fqName()
                                               + " as the second parameter: "
                                               + typeInfo.typeName().fqName() + "." + method.signature().text(),
                                       method.originatingElementValue());
        }

        String grpcMethodName = annotation.stringValue()
                .filter(not(String::isBlank))
                .orElse(method.elementName());
        String uniqueName = ctx.uniqueName(typeInfo, method);
        String descriptorConstant = "METHOD_" + toConstantName(uniqueName);

        return new UnaryMethod(method.elementName(),
                               grpcMethodName,
                               descriptorConstant,
                               request.typeName(),
                               observer.typeName().typeArguments().getFirst());
    }

    private record Endpoint(TypeInfo type,
                            String serviceName,
                            Optional<String> listener,
                            ProtoMethod protoMethod,
                            List<UnaryMethod> unaryMethods) {
    }

    private record ProtoMethod(String name, boolean isStatic) {
    }

    private record UnaryMethod(String javaMethodName,
                               String grpcMethodName,
                               String descriptorConstant,
                               TypeName requestType,
                               TypeName responseType) {
    }

    private record MethodAnnotation(Annotation annotation, MethodType type) {
    }

    private enum MethodType {
        UNARY("unary"),
        SERVER_STREAMING("server streaming"),
        CLIENT_STREAMING("client streaming"),
        BIDIRECTIONAL("bidirectional streaming");

        private final String description;

        MethodType(String description) {
            this.description = description;
        }

        String description() {
            return description;
        }
    }
}
