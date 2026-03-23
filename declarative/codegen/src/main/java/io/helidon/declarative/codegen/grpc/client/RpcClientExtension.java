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

package io.helidon.declarative.codegen.grpc.client;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.HashSet;

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
import io.helidon.declarative.codegen.DelcarativeConfigSupport;
import io.helidon.service.codegen.RegistryCodegenContext;
import io.helidon.service.codegen.RegistryRoundContext;
import io.helidon.service.codegen.spi.RegistryCodegenExtension;

import static io.helidon.declarative.codegen.DeclarativeTypes.CONFIG;
import static io.helidon.declarative.codegen.DeclarativeTypes.SINGLETON_ANNOTATION;
import static io.helidon.service.codegen.ServiceCodegenTypes.SERVICE_REGISTRY;
import static java.util.function.Predicate.not;

class RpcClientExtension implements RegistryCodegenExtension {
    static final TypeName GENERATOR = TypeName.create(RpcClientExtension.class);

    private final RegistryCodegenContext ctx;

    RpcClientExtension(RegistryCodegenContext ctx) {
        this.ctx = ctx;
    }

    @Override
    public void process(RegistryRoundContext roundContext) {
        Collection<TypeInfo> clientApis = roundContext.annotatedTypes(RpcClientTypes.ANNOTATION_ENDPOINT);

        for (TypeInfo clientApi : clientApis) {
            process(roundContext, clientApi);
        }
    }

    private void process(RegistryRoundContext roundContext, TypeInfo clientApi) {
        if (clientApi.kind() != ElementKind.INTERFACE) {
            throw new CodegenException("Types annotated with "
                                               + RpcClientTypes.ANNOTATION_ENDPOINT.classNameWithEnclosingNames()
                                               + " must be interfaces. This type is: " + clientApi.kind(),
                                       clientApi.originatingElementValue());
        }

        Endpoint endpoint = toEndpoint(clientApi);
        TypeName apiType = clientApi.typeName();
        String className = apiType.classNameWithEnclosingNames().replace('.', '_') + "__GrpcClient";
        TypeName generatedType = TypeName.builder()
                .packageName(apiType.packageName())
                .className(className)
                .build();

        var classModel = ClassModel.builder()
                .copyright(CodegenUtil.copyright(GENERATOR,
                                                 apiType,
                                                 generatedType))
                .addAnnotation(CodegenUtil.generatedAnnotation(GENERATOR,
                                                               apiType,
                                                               generatedType,
                                                               "1",
                                                               ""))
                .accessModifier(AccessModifier.PACKAGE_PRIVATE)
                .type(generatedType)
                .addInterface(apiType)
                .addAnnotation(SINGLETON_ANNOTATION)
                .addAnnotation(RpcClientTypes.RPC_CLIENT_QUALIFIER_INSTANCE);

        classModel.addField(field -> field
                .accessModifier(AccessModifier.PRIVATE)
                .isFinal(true)
                .type(RpcClientTypes.GRPC_CLIENT)
                .name("client"));
        classModel.addField(field -> field
                .accessModifier(AccessModifier.PRIVATE)
                .isFinal(true)
                .type(RpcClientTypes.GRPC_SERVICE_CLIENT)
                .name("serviceClient"));

        classModel.addConstructor(constructor(endpoint));

        for (GrpcMethod method : endpoint.methods()) {
            generateMethod(classModel, method);
        }

        classModel.addMethod(toString -> toString
                .addAnnotation(Annotations.OVERRIDE)
                .accessModifier(AccessModifier.PUBLIC)
                .returnType(TypeNames.STRING)
                .name("toString")
                .addContent("return ")
                .addContentLiteral("Declarative gRPC client for " + apiType.className())
                .addContentLine(";"));

        roundContext.addGeneratedType(generatedType,
                                      classModel,
                                      apiType,
                                      clientApi.originatingElementValue());
    }

    private Constructor.Builder constructor(Endpoint endpoint) {
        Constructor.Builder constructor = Constructor.builder()
                .accessModifier(AccessModifier.PACKAGE_PRIVATE)
                .addParameter(config -> config
                        .name("config")
                        .type(CONFIG));

        if (endpoint.clientName().isPresent()) {
            constructor.addParameter(SERVICE_REGISTRY, "registry");
        }

        DelcarativeConfigSupport.assignResolveExpression(constructor,
                                                         "config",
                                                         "uri",
                                                         endpoint.uri());

        DelcarativeConfigSupport.assignResolveExpression(constructor,
                                                         "config",
                                                         "serviceName",
                                                         endpoint.serviceName());

        constructor.addContentLine("if (serviceName.isBlank()) {")
                .increaseContentPadding()
                .addContent("serviceName = ")
                .addContentLiteral(endpoint.type().className())
                .addContentLine(";")
                .decreaseContentPadding()
                .addContentLine("}");

        if (endpoint.clientName().isPresent()) {
            DelcarativeConfigSupport.assignResolveExpression(constructor,
                                                             "config",
                                                             "clientName",
                                                             endpoint.clientName().get());

            constructor.addContentLine("if (!clientName.isBlank()) {")
                    .increaseContentPadding()
                    .addContent("var maybeClient = registry.firstNamed(")
                    .addContent(RpcClientTypes.GRPC_CLIENT)
                    .addContentLine(".class, clientName);")
                    .addContentLine("if (maybeClient.isPresent()) {")
                    .increaseContentPadding()
                    .addContentLine("this.client = maybeClient.get();")
                    .decreaseContentPadding()
                    .addContentLine("} else {")
                    .increaseContentPadding()
                    .addContent("var supplierLookup = ")
                    .addContent(RpcClientTypes.LOOKUP)
                    .addContentLine(".builder()")
                    .increaseContentPadding()
                    .increaseContentPadding()
                    .addContentLine(".named(clientName)")
                    .addContent(".addContract(")
                    .addContent(RpcClientTypes.GRPC_CLIENT)
                    .addContentLine(".class)")
                    .addContent(".addFactoryType(")
                    .addContent(RpcClientTypes.FACTORY_TYPE)
                    .addContentLine(".SUPPLIER)")
                    .addContentLine(".build();")
                    .decreaseContentPadding()
                    .decreaseContentPadding()
                    .addContentLine("var maybeClientSupplier = registry.first(supplierLookup);")
                    .addContentLine("if (maybeClientSupplier.isPresent()) {")
                    .increaseContentPadding()
                    .addContent("this.client = ((")
                    .addContent(TypeNames.SUPPLIER)
                    .addContent("<")
                    .addContent(RpcClientTypes.GRPC_CLIENT)
                    .addContentLine(">) maybeClientSupplier.get()).get();")
                    .decreaseContentPadding()
                    .addContentLine("} else {")
                    .increaseContentPadding()
                    .update(it -> assignCreatedClient(it, endpoint))
                    .decreaseContentPadding()
                    .addContentLine("}")
                    .decreaseContentPadding()
                    .addContentLine("}")
                    .decreaseContentPadding()
                    .addContentLine("} else {")
                    .increaseContentPadding()
                    .update(it -> assignCreatedClient(it, endpoint))
                    .decreaseContentPadding()
                    .addContentLine("}");
        } else {
            assignCreatedClient(constructor, endpoint);
        }

        constructor.addContent("var descriptor = ")
                .addContent(RpcClientTypes.GRPC_SERVICE_DESCRIPTOR)
                .addContentLine(".builder()")
                .increaseContentPadding()
                .increaseContentPadding()
                .addContentLine(".serviceName(serviceName)");

        for (GrpcMethod method : endpoint.methods()) {
            addMethod(constructor, method);
        }

        constructor.addContentLine(".build();")
                .decreaseContentPadding()
                .decreaseContentPadding()
                .addContentLine("this.serviceClient = client.serviceClient(descriptor);");

        return constructor;
    }

    private void assignCreatedClient(Constructor.Builder constructor, Endpoint endpoint) {
        constructor.addContentLine("if (uri.isBlank()) {")
                .increaseContentPadding()
                .addContent("throw new ")
                .addContent(IllegalStateException.class)
                .addContent("(")
                .addContentLiteral("Declarative gRPC client " + endpoint.type().fqName()
                                           + " must define a non-blank endpoint URI")
                .addContentLine(");")
                .decreaseContentPadding()
                .addContentLine("}")
                .addContentLine("if (uri.startsWith(\"http://\")) {")
                .increaseContentPadding()
                .addContent("this.client = ")
                .addContent(RpcClientTypes.GRPC_CLIENT)
                .addContentLine(".create(it -> it.baseUri(uri).tls(t -> t.enabled(false)));")
                .decreaseContentPadding()
                .addContentLine("} else {")
                .increaseContentPadding()
                .addContent("this.client = ")
                .addContent(RpcClientTypes.GRPC_CLIENT)
                .addContentLine(".create(it -> it.baseUri(uri));")
                .decreaseContentPadding()
                .addContentLine("}");
    }

    private void addMethod(Constructor.Builder constructor, GrpcMethod method) {
        constructor.addContent(".putMethod(")
                .addContentLiteral(method.grpcMethodName())
                .addContentLine(",")
                .increaseContentPadding()
                .increaseContentPadding()
                .addContent(RpcClientTypes.GRPC_CLIENT_METHOD_DESCRIPTOR)
                .addContent(".")
                .addContent(method.type().descriptorMethodName())
                .addContent("(serviceName, ")
                .addContentLiteral(method.grpcMethodName())
                .addContentLine(")")
                .addContent(".requestType(")
                .addContent(method.requestType())
                .addContent(".class)")
                .addContent(".responseType(")
                .addContent(method.responseType())
                .addContent(".class)")
                .addContentLine(".build())");
        constructor.decreaseContentPadding()
                .decreaseContentPadding();
    }

    private void generateMethod(ClassModel.Builder classModel, GrpcMethod method) {
        classModel.addMethod(clientMethod -> clientMethod
                .addAnnotation(Annotations.OVERRIDE)
                .accessModifier(AccessModifier.PUBLIC)
                .name(method.javaMethodName())
                .returnType(method.returnType())
                .update(it -> {
                    method.parameters()
                            .forEach(parameter -> it.addParameter(newParam -> newParam
                                    .name(parameter.name())
                                    .type(parameter.typeName())));

                    it.addContent("return serviceClient.")
                            .addContent(method.type().clientMethodName())
                            .addContent("(")
                            .addContentLiteral(method.grpcMethodName())
                            .addContent(", ")
                            .addContent(method.parameters().getFirst().name())
                            .addContentLine(");");
                }));
    }

    private Endpoint toEndpoint(TypeInfo typeInfo) {
        Set<Annotation> typeAnnotations = new HashSet<>(TypeHierarchy.hierarchyAnnotations(ctx, typeInfo));

        Annotation endpointAnnotation = Annotations.findFirst(RpcClientTypes.ANNOTATION_ENDPOINT, typeAnnotations)
                .orElseThrow(() -> new CodegenException("Type is not annotated with "
                                                               + RpcClientTypes.ANNOTATION_ENDPOINT.fqName(),
                                                       typeInfo.originatingElementValue()));

        String serviceName = Annotations.findFirst(RpcClientTypes.ANNOTATION_SERVICE_NAME, typeAnnotations)
                .flatMap(Annotation::stringValue)
                .filter(not(String::isBlank))
                .orElse(typeInfo.typeName().className());

        Optional<String> clientName = endpointAnnotation.stringValue("clientName")
                .filter(not(String::isBlank));

        Map<MethodSignature, MethodOrigin> discoveredMethods = new LinkedHashMap<>();

        typeInfo.elementInfo()
                .stream()
                .filter(ElementInfoPredicates::isMethod)
                .filter(not(ElementInfoPredicates::isPrivate))
                .filter(not(ElementInfoPredicates::isStatic))
                .filter(not(ElementInfoPredicates::isDefault))
                .forEach(it -> discoveredMethods.put(MethodSignature.create(it), new MethodOrigin(typeInfo, it)));

        typeInfo.interfaceTypeInfo()
                .forEach(iface -> iface.elementInfo()
                        .stream()
                        .filter(ElementInfoPredicates::isMethod)
                        .filter(not(ElementInfoPredicates::isPrivate))
                        .filter(not(ElementInfoPredicates::isStatic))
                        .filter(not(ElementInfoPredicates::isDefault))
                        .forEach(it -> discoveredMethods.putIfAbsent(MethodSignature.create(it),
                                                                     new MethodOrigin(iface, it))));

        List<GrpcMethod> grpcMethods = new ArrayList<>();
        discoveredMethods.forEach((signature, origin) -> {
            Set<Annotation> annotations = new HashSet<>(TypeHierarchy.hierarchyAnnotations(ctx, origin.type(), origin.method()));
            MethodAnnotation methodAnnotation = methodAnnotation(origin.method(), annotations);
            if (methodAnnotation == null) {
                return;
            }
            grpcMethods.add(grpcMethod(origin.method(), methodAnnotation));
        });

        if (grpcMethods.isEmpty()) {
            throw new CodegenException("Declarative gRPC client " + typeInfo.typeName().fqName()
                                               + " does not declare any supported gRPC methods",
                                       typeInfo.originatingElementValue());
        }

        return new Endpoint(typeInfo.typeName(),
                            endpointAnnotation.stringValue().orElse(""),
                            clientName,
                            serviceName,
                            grpcMethods);
    }

    private MethodAnnotation methodAnnotation(TypedElementInfo method, Set<Annotation> annotations) {
        List<MethodAnnotation> found = new ArrayList<>();

        annotation(annotations, RpcClientTypes.ANNOTATION_UNARY, MethodType.UNARY).ifPresent(found::add);
        annotation(annotations, RpcClientTypes.ANNOTATION_SERVER_STREAMING, MethodType.SERVER_STREAMING).ifPresent(found::add);
        annotation(annotations, RpcClientTypes.ANNOTATION_CLIENT_STREAMING, MethodType.CLIENT_STREAMING).ifPresent(found::add);
        annotation(annotations, RpcClientTypes.ANNOTATION_BIDIRECTIONAL, MethodType.BIDIRECTIONAL).ifPresent(found::add);

        if (found.isEmpty()) {
            return null;
        }
        if (found.size() > 1) {
            throw new CodegenException("Declarative gRPC client method " + method.elementName()
                                               + " must have exactly one RpcClient method annotation",
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

    private GrpcMethod grpcMethod(TypedElementInfo method, MethodAnnotation methodAnnotation) {
        String grpcMethodName = methodAnnotation.annotation()
                .stringValue()
                .filter(not(String::isBlank))
                .orElse(method.elementName());

        return switch (methodAnnotation.type()) {
            case UNARY -> unaryMethod(method, grpcMethodName);
            case SERVER_STREAMING -> serverStreamingMethod(method, grpcMethodName);
            case CLIENT_STREAMING -> clientStreamingMethod(method, grpcMethodName);
            case BIDIRECTIONAL -> bidirectionalMethod(method, grpcMethodName);
        };
    }

    private GrpcMethod unaryMethod(TypedElementInfo method, String grpcMethodName) {
        List<TypedElementInfo> parameters = method.parameterArguments();
        if (parameters.size() != 1) {
            throw new CodegenException("Declarative gRPC unary client method must have exactly one request parameter",
                                       method.originatingElementValue());
        }

        TypeName requestType = parameters.getFirst().typeName();
        TypeName responseType = method.typeName();

        if (voidType(responseType) || isIterator(responseType) || isStreamObserver(responseType)) {
            throw new CodegenException("Declarative gRPC unary client method must return a single response type",
                                       method.originatingElementValue());
        }
        if (isIterator(requestType) || isStreamObserver(requestType)) {
            throw new CodegenException("Declarative gRPC unary client request parameter must not be an iterator or"
                                               + " stream observer",
                                       method.originatingElementValue());
        }

        return new GrpcMethod(MethodType.UNARY,
                              method.elementName(),
                              method.typeName(),
                              toParameters(parameters),
                              requestType,
                              responseType,
                              grpcMethodName);
    }

    private GrpcMethod serverStreamingMethod(TypedElementInfo method, String grpcMethodName) {
        List<TypedElementInfo> parameters = method.parameterArguments();
        if (parameters.size() != 1) {
            throw new CodegenException("Declarative gRPC server streaming client method must have exactly one request"
                                               + " parameter",
                                       method.originatingElementValue());
        }

        TypeName requestType = parameters.getFirst().typeName();
        if (isIterator(requestType) || isStreamObserver(requestType)) {
            throw new CodegenException("Declarative gRPC server streaming client request parameter must not be an iterator or"
                                               + " stream observer",
                                       method.originatingElementValue());
        }

        TypeName responseType = iteratorType(method.typeName(),
                                             method,
                                             "Declarative gRPC server streaming client method must return "
                                                     + RpcClientTypes.ITERATOR.fqName()
                                                     + "<ResponseT>");

        return new GrpcMethod(MethodType.SERVER_STREAMING,
                              method.elementName(),
                              method.typeName(),
                              toParameters(parameters),
                              requestType,
                              responseType,
                              grpcMethodName);
    }

    private GrpcMethod clientStreamingMethod(TypedElementInfo method, String grpcMethodName) {
        List<TypedElementInfo> parameters = method.parameterArguments();
        if (parameters.size() != 1) {
            throw new CodegenException("Declarative gRPC client streaming client method must have exactly one request"
                                               + " iterator parameter",
                                       method.originatingElementValue());
        }

        TypeName requestType = iteratorType(parameters.getFirst().typeName(),
                                            method,
                                            "Declarative gRPC client streaming client request parameter must be "
                                                    + RpcClientTypes.ITERATOR.fqName()
                                                    + "<RequestT>");
        TypeName responseType = method.typeName();

        if (voidType(responseType) || isIterator(responseType) || isStreamObserver(responseType)) {
            throw new CodegenException("Declarative gRPC client streaming client method must return a single response type",
                                       method.originatingElementValue());
        }

        return new GrpcMethod(MethodType.CLIENT_STREAMING,
                              method.elementName(),
                              method.typeName(),
                              toParameters(parameters),
                              requestType,
                              responseType,
                              grpcMethodName);
    }

    private GrpcMethod bidirectionalMethod(TypedElementInfo method, String grpcMethodName) {
        List<TypedElementInfo> parameters = method.parameterArguments();
        if (parameters.size() != 1) {
            throw new CodegenException("Declarative gRPC bidirectional client method must have exactly one request"
                                               + " iterator parameter",
                                       method.originatingElementValue());
        }

        TypeName requestType = iteratorType(parameters.getFirst().typeName(),
                                            method,
                                            "Declarative gRPC bidirectional client request parameter must be "
                                                    + RpcClientTypes.ITERATOR.fqName()
                                                    + "<RequestT>");
        TypeName responseType = iteratorType(method.typeName(),
                                             method,
                                             "Declarative gRPC bidirectional client method must return "
                                                     + RpcClientTypes.ITERATOR.fqName()
                                                     + "<ResponseT>");

        return new GrpcMethod(MethodType.BIDIRECTIONAL,
                              method.elementName(),
                              method.typeName(),
                              toParameters(parameters),
                              requestType,
                              responseType,
                              grpcMethodName);
    }

    private List<GrpcParameter> toParameters(List<TypedElementInfo> parameters) {
        return parameters.stream()
                .map(parameter -> new GrpcParameter(parameter.elementName(), parameter.typeName()))
                .toList();
    }

    private TypeName iteratorType(TypeName typeName, TypedElementInfo method, String message) {
        if (!isIterator(typeName) || typeName.typeArguments().size() != 1) {
            throw new CodegenException(message, method.originatingElementValue());
        }
        return typeName.typeArguments().getFirst();
    }

    private boolean isIterator(TypeName typeName) {
        return typeName.fqName().equals(RpcClientTypes.ITERATOR.fqName());
    }

    private boolean isStreamObserver(TypeName typeName) {
        return typeName.fqName().equals(RpcClientTypes.STREAM_OBSERVER.fqName());
    }

    private boolean voidType(TypeName typeName) {
        return TypeNames.PRIMITIVE_VOID.equals(typeName) || TypeNames.BOXED_VOID.equals(typeName);
    }
    private record Endpoint(TypeName type,
                            String uri,
                            Optional<String> clientName,
                            String serviceName,
                            List<GrpcMethod> methods) {
    }

    private record MethodSignature(String name, List<TypeName> parameterTypes) {
        private static MethodSignature create(TypedElementInfo element) {
            return new MethodSignature(element.elementName(),
                                       element.parameterArguments()
                                               .stream()
                                               .map(TypedElementInfo::typeName)
                                               .toList());
        }
    }

    private record MethodOrigin(TypeInfo type, TypedElementInfo method) {
    }

    private record GrpcParameter(String name, TypeName typeName) {
    }

    private record GrpcMethod(MethodType type,
                              String javaMethodName,
                              TypeName returnType,
                              List<GrpcParameter> parameters,
                              TypeName requestType,
                              TypeName responseType,
                              String grpcMethodName) {
    }

    private record MethodAnnotation(Annotation annotation, MethodType type) {
    }

    private enum MethodType {
        UNARY("unary", "unary"),
        SERVER_STREAMING("serverStreaming", "serverStream"),
        CLIENT_STREAMING("clientStreaming", "clientStream"),
        BIDIRECTIONAL("bidirectional", "bidi");

        private final String descriptorMethodName;
        private final String clientMethodName;

        MethodType(String descriptorMethodName, String clientMethodName) {
            this.descriptorMethodName = descriptorMethodName;
            this.clientMethodName = clientMethodName;
        }

        private String descriptorMethodName() {
            return descriptorMethodName;
        }

        private String clientMethodName() {
            return clientMethodName;
        }
    }
}
