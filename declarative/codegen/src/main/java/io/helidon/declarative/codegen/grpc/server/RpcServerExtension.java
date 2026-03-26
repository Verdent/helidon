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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import io.helidon.codegen.CodegenException;
import io.helidon.codegen.CodegenUtil;
import io.helidon.codegen.ElementInfoPredicates;
import io.helidon.codegen.TypeHierarchy;
import io.helidon.codegen.classmodel.ClassModel;
import io.helidon.codegen.classmodel.Constructor;
import io.helidon.codegen.classmodel.Parameter;
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
import io.helidon.service.codegen.ServiceCodegenTypes;
import io.helidon.service.codegen.spi.RegistryCodegenExtension;

import static io.helidon.codegen.CodegenUtil.toConstantName;
import static io.helidon.declarative.codegen.DeclarativeTypes.CONFIG;
import static io.helidon.declarative.codegen.DeclarativeTypes.SINGLETON_ANNOTATION;
import static java.util.function.Predicate.not;

class RpcServerExtension implements RegistryCodegenExtension {
    static final TypeName GENERATOR = TypeName.create(RpcServerExtension.class);
    private static final String DEFAULT_MARSHALLER_NAME = "default";
    private static final String PROTO_MARSHALLER_NAME = "proto";

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

        Endpoint endpoint = toEndpoint(roundContext, serverEndpoint);
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

        if (endpoint.listener().isPresent()) {
            classModel.addField(field -> field
                    .accessModifier(AccessModifier.PRIVATE)
                    .isFinal(true)
                    .type(TypeNames.STRING)
                    .name("socket"));
        }

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
        Map<String, MarshallerDependency> marshallerDependencies = marshallerDependencies(endpoint);
        Map<TypeName, InterceptorDependency> interceptorDependencies = interceptorDependencies(endpoint);
        boolean singleton = endpoint.type().hasAnnotation(ServiceCodegenTypes.SERVICE_ANNOTATION_SINGLETON);

        Constructor.Builder constructor = Constructor.builder();
        constructor.accessModifier(AccessModifier.PACKAGE_PRIVATE)
                .addAnnotation(Annotation.create(ServiceCodegenTypes.SERVICE_ANNOTATION_INJECT))
                .addParameter(CONFIG, "config")
                .addParameter(singleton ? endpointType : supplierOf(endpointType), "endpoint")
                .addParameter(RpcServerTypes.GRPC_ENTRY_POINTS, "entryPoints");

        marshallerDependencies.values()
                .forEach(dependency -> constructor.addParameter(param -> param
                        .name(dependency.parameterName())
                        .update(it -> marshallerSupplierParameter(it, dependency.name()))));
        interceptorDependencies.values()
                .forEach(dependency -> constructor.addParameter(param -> param
                        .name(dependency.variableName())
                        .type(dependency.type())));

        DelcarativeConfigSupport.assignResolveExpression(constructor,
                                                         "config",
                                                         "serviceName",
                                                         endpoint.serviceName());

        constructor.addContentLine("if (serviceName.isBlank()) {")
                .addContent("serviceName = ")
                .addContentLiteral(endpointType.className())
                .addContentLine(";")
                .addContentLine("}");

        if (endpoint.listener().isPresent()) {
            DelcarativeConfigSupport.assignResolveExpression(constructor,
                                                             "config",
                                                             "socket",
                                                             endpoint.listener().get());

            constructor.addContentLine("if (socket.isBlank()) {")
                    .addContent("socket = ")
                    .addContent(RpcServerTypes.WEB_SERVER)
                    .addContentLine(".DEFAULT_SOCKET_NAME;")
                    .addContentLine("}")
                    .addContentLine("this.socket = socket;");
        }

        constructor.addContent("var serviceDescriptor = ")
                .addContent(descriptorType)
                .addContentLine(".INSTANCE;")
                .addContent("var annotations = ")
                .addContent(descriptorType)
                .addContentLine(".ANNOTATIONS;");

        endpoint.protoMethod().ifPresent(protoMethod -> {
            constructor.addContent("var proto = ");

            if (protoMethod.isStatic()) {
                constructor.addContent(endpointType)
                        .addContent(".");
            } else {
                constructor.addContent(singleton ? "endpoint." : "endpoint.get().");
            }
            constructor.addContent(protoMethod.name())
                    .addContentLine("();")
                    .addContentLine("if (proto != null) {")
                    .addContentLine("var packageName = proto.getPackage();")
                    .addContentLine("if (!packageName.isBlank()) {")
                    .addContentLine("var servicePrefix = packageName + \".\";")
                    .addContentLine("if (serviceName.startsWith(servicePrefix)) {")
                    .addContentLine("serviceName = serviceName.substring(servicePrefix.length());")
                    .addContentLine("}")
                    .addContentLine("}")
                    .addContentLine("}");
        });

        marshallerDependencies.values().forEach(dependency -> addMarshallerResolution(constructor, endpoint, dependency));

        constructor.addContent("var descriptorBuilder = ")
                .addContent(RpcServerTypes.GRPC_SERVICE_DESCRIPTOR)
                .addContent(".builder(")
                .addContent(endpointType)
                .addContentLine(".class, serviceName);");

        if (endpoint.protoMethod().isPresent()) {
            constructor.addContentLine("if (proto != null) {")
                    .addContentLine("descriptorBuilder.proto(proto);")
                    .addContentLine("}");
        }

        endpoint.marshaller().ifPresent(marshaller -> {
            constructor.addContent("descriptorBuilder.marshallerSupplier(");
            addMarshallerReference(constructor, marshaller, marshallerDependencies);
            constructor.addContentLine(");");
        });

        endpoint.interceptors().forEach(interceptor -> constructor.addContent("descriptorBuilder.intercept(")
                .addContent(interceptorDependencies.get(interceptor.type()).variableName())
                .addContentLine(");"));

        for (GrpcMethod method : endpoint.methods()) {
            addMethod(constructor, descriptorType, method, marshallerDependencies, interceptorDependencies, singleton);
        }

        constructor.addContentLine("this.descriptor = descriptorBuilder.build();");
        return constructor;
    }

    private void addMethod(Constructor.Builder constructor,
                           TypeName descriptorType,
                           GrpcMethod method,
                           Map<String, MarshallerDependency> marshallerDependencies,
                           Map<TypeName, InterceptorDependency> interceptorDependencies,
                           boolean singleton) {
        constructor.addContent("descriptorBuilder.")
                .addContent(method.type().registrationMethodName())
                .addContentLine("(")
                .increaseContentPadding()
                .increaseContentPadding()
                .addContentLiteral(method.grpcMethodName())
                .addContentLine(",")
                .addContent("entryPoints.")
                .addContent(method.type().registrationMethodName())
                .addContent("(serviceDescriptor, annotations, ")
                .addContent(descriptorType)
                .addContent(".")
                .addContent(method.descriptorConstant())
                .addContent(", ");

        addActualHandler(constructor, method, singleton);

        constructor.addContentLine("),")
                .addContent("it -> it.requestType(")
                .addContent(method.requestType())
                .addContent(".class)")
                .addContent(".responseType(")
                .addContent(method.responseType())
                .addContent(".class)");

        method.marshaller().ifPresent(marshaller -> {
            constructor.addContent(".marshallerSupplier(");
            addMarshallerReference(constructor, marshaller, marshallerDependencies);
            constructor.addContent(")");
        });

        method.interceptors().forEach(interceptor -> constructor.addContent(".intercept(")
                .addContent(interceptorDependencies.get(interceptor.type()).variableName())
                .addContent(")"));

        constructor.addContentLine(");");
        constructor.decreaseContentPadding()
                .decreaseContentPadding();
    }

    private void addActualHandler(Constructor.Builder constructor,
                                  GrpcMethod method,
                                  boolean singleton) {
        String endpointAccess = singleton ? "endpoint" : "endpoint.get()";

        switch (method.shape()) {
        case OBSERVER -> {
            if (singleton) {
                constructor.addContent("endpoint::")
                        .addContent(method.javaMethodName());
                return;
            }

            switch (method.type()) {
            case UNARY, SERVER_STREAMING -> constructor.addContent("(")
                    .addContent(method.requestType())
                    .addContent(" request, ")
                    .addContent(streamObserverOf(method.responseType()))
                    .addContent(" observer) -> endpoint.get().")
                    .addContent(method.javaMethodName())
                    .addContent("(request, observer)");
            case CLIENT_STREAMING, BIDIRECTIONAL -> constructor.addContent("(")
                    .addContent(streamObserverOf(method.responseType()))
                    .addContent(" observer) -> endpoint.get().")
                    .addContent(method.javaMethodName())
                    .addContent("(observer)");
            }
        }
        case NO_REQUEST_OBSERVER -> constructor.addContent("(")
                .addContent(method.requestType())
                .addContent(" request, ")
                .addContent(streamObserverOf(method.responseType()))
                .addContent(" observer) -> ")
                .addContent(endpointAccess)
                .addContent(".")
                .addContent(method.javaMethodName())
                .addContent("(observer)");
        case COMPLETING_RETURN -> constructor.addContent("(")
                .addContent(method.requestType())
                .addContent(" request, ")
                .addContent(streamObserverOf(method.responseType()))
                .addContent(" observer) -> ")
                .addContent(RpcServerTypes.RESPONSE_HELPER)
                .addContent(".complete(observer, ")
                .addContent(endpointAccess)
                .addContent(".")
                .addContent(method.javaMethodName())
                .addContent("(request))");
        case NO_REQUEST_COMPLETING_RETURN -> constructor.addContent("(")
                .addContent(method.requestType())
                .addContent(" request, ")
                .addContent(streamObserverOf(method.responseType()))
                .addContent(" observer) -> ")
                .addContent(RpcServerTypes.RESPONSE_HELPER)
                .addContent(".complete(observer, ")
                .addContent(endpointAccess)
                .addContent(".")
                .addContent(method.javaMethodName())
                .addContent("())");
        case EMPTY_RESPONSE -> constructor.addContent("(")
                .addContent(method.requestType())
                .addContent(" request, ")
                .addContent(streamObserverOf(method.responseType()))
                .addContent(" observer) -> ")
                .addContent(RpcServerTypes.RESPONSE_HELPER)
                .addContent(".complete(observer, () -> ")
                .addContent(endpointAccess)
                .addContent(".")
                .addContent(method.javaMethodName())
                .addContent("(request), ")
                .addContent(RpcServerTypes.PROTO_EMPTY)
                .addContent(".getDefaultInstance())");
        case NO_REQUEST_EMPTY_RESPONSE -> constructor.addContent("(")
                .addContent(method.requestType())
                .addContent(" request, ")
                .addContent(streamObserverOf(method.responseType()))
                .addContent(" observer) -> ")
                .addContent(RpcServerTypes.RESPONSE_HELPER)
                .addContent(".complete(observer, () -> ")
                .addContent(endpointAccess)
                .addContent(".")
                .addContent(method.javaMethodName())
                .addContent("(), ")
                .addContent(RpcServerTypes.PROTO_EMPTY)
                .addContent(".getDefaultInstance())");
        case STREAM_RETURN -> constructor.addContent("(")
                .addContent(method.requestType())
                .addContent(" request, ")
                .addContent(streamObserverOf(method.responseType()))
                .addContent(" observer) -> ")
                .addContent(RpcServerTypes.RESPONSE_HELPER)
                .addContent(".stream(observer, ")
                .addContent(endpointAccess)
                .addContent(".")
                .addContent(method.javaMethodName())
                .addContent("(request))");
        case NO_REQUEST_STREAM_RETURN -> constructor.addContent("(")
                .addContent(method.requestType())
                .addContent(" request, ")
                .addContent(streamObserverOf(method.responseType()))
                .addContent(" observer) -> ")
                .addContent(RpcServerTypes.RESPONSE_HELPER)
                .addContent(".stream(observer, ")
                .addContent(endpointAccess)
                .addContent(".")
                .addContent(method.javaMethodName())
                .addContent("())");
        }
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
                .addContentLine("return socket;"));

        classModel.addMethod(socketRequired -> socketRequired
                .addAnnotation(Annotations.OVERRIDE)
                .accessModifier(AccessModifier.PUBLIC)
                .returnType(TypeNames.PRIMITIVE_BOOLEAN)
                .name("socketRequired")
                .addContent("return !socket.equals(")
                .addContent(RpcServerTypes.WEB_SERVER)
                .addContentLine(".DEFAULT_SOCKET_NAME);"));
    }

    private Endpoint toEndpoint(RegistryRoundContext roundContext, TypeInfo typeInfo) {
        Set<Annotation> typeAnnotations = new HashSet<>(TypeHierarchy.hierarchyAnnotations(ctx, typeInfo));

        String serviceName = Annotations.findFirst(RpcServerTypes.ANNOTATION_SERVICE_NAME, typeAnnotations)
                .flatMap(Annotation::stringValue)
                .filter(not(String::isBlank))
                .orElse(typeInfo.typeName().className());

        Optional<String> listener = Annotations.findFirst(RpcServerTypes.ANNOTATION_LISTENER, typeAnnotations)
                .flatMap(Annotation::stringValue)
                .filter(not(String::isBlank));

        Optional<MarshallerConfig> marshaller = marshaller(typeAnnotations);
        List<InterceptorConfig> interceptors = interceptors(roundContext,
                                                            typeInfo,
                                                            Optional.empty(),
                                                            typeAnnotations);
        Optional<ProtoMethod> protoMethod = protoMethod(typeInfo);

        List<GrpcMethod> grpcMethods = new ArrayList<>();
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

            grpcMethods.add(grpcMethod(typeInfo,
                                       element,
                                       methodAnnotation,
                                       marshaller(annotations),
                                       interceptors(roundContext,
                                                    typeInfo,
                                                    Optional.of(element),
                                                    annotations)));
        }

        if (grpcMethods.isEmpty()) {
            throw new CodegenException("Declarative gRPC endpoint " + typeInfo.typeName().fqName()
                                               + " does not declare any supported gRPC methods",
                                       typeInfo.originatingElementValue());
        }

        return new Endpoint(typeInfo, serviceName, listener, marshaller, interceptors, protoMethod, List.copyOf(grpcMethods));
    }

    private Optional<ProtoMethod> protoMethod(TypeInfo typeInfo) {
        List<TypedElementInfo> protoMethods = new ArrayList<>();

        for (TypedElementInfo element : typeInfo.elementInfo()) {
            if (!ElementInfoPredicates.isMethod(element)) {
                continue;
            }

            Set<Annotation> annotations = new HashSet<>(TypeHierarchy.hierarchyAnnotations(ctx, typeInfo, element));
            if (Annotations.findFirst(RpcServerTypes.ANNOTATION_PROTO, annotations).isPresent()) {
                protoMethods.add(element);
            }
        }

        if (protoMethods.isEmpty()) {
            return Optional.empty();
        }

        if (protoMethods.size() > 1) {
            throw new CodegenException("Declarative gRPC endpoint " + typeInfo.typeName().fqName()
                                               + " defines multiple @" + RpcServerTypes.ANNOTATION_PROTO.className(),
                                       typeInfo.originatingElementValue());
        }

        TypedElementInfo protoMethod = protoMethods.getFirst();
        if (ElementInfoPredicates.isPrivate(protoMethod)) {
            throw new CodegenException("Method annotated with @" + RpcServerTypes.ANNOTATION_PROTO.className()
                                               + " must not be private: "
                                               + protoMethod.signature().text(),
                                       protoMethod.originatingElementValue());
        }

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

        return Optional.of(new ProtoMethod(protoMethod.elementName(), ElementInfoPredicates.isStatic(protoMethod)));
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

    private GrpcMethod grpcMethod(TypeInfo typeInfo,
                                  TypedElementInfo method,
                                  MethodAnnotation methodAnnotation,
                                  Optional<MarshallerConfig> marshaller,
                                  List<InterceptorConfig> interceptors) {
        MethodType methodType = methodAnnotation.type();
        MethodSignature signature = switch (methodType) {
            case UNARY -> unarySignature(typeInfo, method);
            case SERVER_STREAMING -> serverStreamingSignature(typeInfo, method);
            case CLIENT_STREAMING -> clientStreamingSignature(typeInfo, method);
            case BIDIRECTIONAL -> streamingSignature(typeInfo, method, methodType);
        };

        return new GrpcMethod(methodType,
                              method.elementName(),
                              grpcMethodName(method, methodAnnotation.annotation()),
                              descriptorConstant(typeInfo, method),
                              signature.shape(),
                              signature.requestType(),
                              signature.responseType(),
                              marshaller,
                              interceptors);
    }

    private MethodSignature unarySignature(TypeInfo typeInfo, TypedElementInfo method) {
        String errorPrefix = MethodType.UNARY.errorPrefix();
        List<TypedElementInfo> params = method.parameterArguments();
        if (params.size() == 2 && isVoidType(method.typeName())) {
            TypedElementInfo request = params.getFirst();
            TypedElementInfo response = params.get(1);
            TypeName parameterType = response.typeName();
            if (parameterType.fqName().equals(RpcServerTypes.STREAM_OBSERVER.fqName())) {
                TypeName responseType = streamObserverType(typeInfo,
                                                           method,
                                                           parameterType,
                                                           "second parameter",
                                                           errorPrefix);
                return new MethodSignature(MethodShape.OBSERVER, request.typeName(), responseType);
            }
        }

        if (params.size() == 1) {
            TypedElementInfo parameter = params.getFirst();
            TypeName parameterType = parameter.typeName();
            if (isVoidType(method.typeName())) {
                if (isStreamObserverType(parameterType)) {
                    TypeName responseType = streamObserverType(typeInfo,
                                                               method,
                                                               parameterType,
                                                               "first and only parameter",
                                                               errorPrefix);
                    return new MethodSignature(MethodShape.NO_REQUEST_OBSERVER,
                                               RpcServerTypes.PROTO_EMPTY,
                                               responseType);
                }

                return new MethodSignature(MethodShape.EMPTY_RESPONSE,
                                           parameterType,
                                           RpcServerTypes.PROTO_EMPTY);
            }

            TypeName responseType = completingReturnType(typeInfo, method, method.typeName(), errorPrefix);
            return new MethodSignature(MethodShape.COMPLETING_RETURN, parameterType, responseType);
        }

        if (params.isEmpty()) {
            if (isVoidType(method.typeName())) {
                return new MethodSignature(MethodShape.NO_REQUEST_EMPTY_RESPONSE,
                                           RpcServerTypes.PROTO_EMPTY,
                                           RpcServerTypes.PROTO_EMPTY);
            }

            TypeName responseType = completingReturnType(typeInfo, method, method.typeName(), errorPrefix);
            return new MethodSignature(MethodShape.NO_REQUEST_COMPLETING_RETURN,
                                       RpcServerTypes.PROTO_EMPTY,
                                       responseType);
        }

        throw new CodegenException(errorPrefix + " declarative gRPC method must declare one of "
                                           + "void method(RequestT request, StreamObserver<ResponseT> observer), "
                                           + "void method(StreamObserver<ResponseT> observer), "
                                           + "ResponseT method(RequestT request), "
                                           + "ResponseT method(), "
                                           + "void method(RequestT request), or "
                                           + "void method(): "
                                           + typeInfo.typeName().fqName() + "." + method.signature().text(),
                                   method.originatingElementValue());
    }

    private MethodSignature serverStreamingSignature(TypeInfo typeInfo, TypedElementInfo method) {
        String errorPrefix = MethodType.SERVER_STREAMING.errorPrefix();
        List<TypedElementInfo> params = method.parameterArguments();
        if (params.size() == 2 && isVoidType(method.typeName())) {
            TypedElementInfo request = params.getFirst();
            TypedElementInfo observer = params.get(1);
            TypeName responseType = streamObserverType(typeInfo, method, observer.typeName(), "second parameter", errorPrefix);

            return new MethodSignature(MethodShape.OBSERVER, request.typeName(), responseType);
        }

        if (params.size() == 1) {
            TypedElementInfo parameter = params.getFirst();
            if (isVoidType(method.typeName()) && isStreamObserverType(parameter.typeName())) {
                TypeName responseType = streamObserverType(typeInfo,
                                                           method,
                                                           parameter.typeName(),
                                                           "first and only parameter",
                                                           errorPrefix);
                return new MethodSignature(MethodShape.NO_REQUEST_OBSERVER,
                                           RpcServerTypes.PROTO_EMPTY,
                                           responseType);
            }

            TypeName responseType = streamResponseType(typeInfo, method, method.typeName(), errorPrefix);
            return new MethodSignature(MethodShape.STREAM_RETURN, parameter.typeName(), responseType);
        }

        if (params.isEmpty()) {
            TypeName responseType = streamResponseType(typeInfo, method, method.typeName(), errorPrefix);
            return new MethodSignature(MethodShape.NO_REQUEST_STREAM_RETURN,
                                       RpcServerTypes.PROTO_EMPTY,
                                       responseType);
        }

        throw new CodegenException(errorPrefix + " declarative gRPC method must declare one of "
                                           + "void method(RequestT request, StreamObserver<ResponseT> observer), "
                                           + "void method(StreamObserver<ResponseT> observer), "
                                           + "Stream<ResponseT> method(RequestT request), or "
                                           + "Stream<ResponseT> method(): "
                                           + typeInfo.typeName().fqName() + "." + method.signature().text(),
                                   method.originatingElementValue());
    }

    private MethodSignature clientStreamingSignature(TypeInfo typeInfo, TypedElementInfo method) {
        String errorPrefix = MethodType.CLIENT_STREAMING.errorPrefix();
        List<TypedElementInfo> params = method.parameterArguments();
        if (params.size() != 1) {
            throw new CodegenException(errorPrefix + " declarative gRPC method must declare exactly one parameter "
                                               + "(response StreamObserver): "
                                               + typeInfo.typeName().fqName() + "." + method.signature().text(),
                                       method.originatingElementValue());
        }

        TypeName requestType = streamObserverType(typeInfo,
                                                  method,
                                                  method.typeName(),
                                                  "return type",
                                                  errorPrefix);
        TypeName parameterType = params.getFirst().typeName();
        if (parameterType.fqName().equals(RpcServerTypes.STREAM_OBSERVER.fqName())) {
            TypeName responseType = streamObserverType(typeInfo,
                                                       method,
                                                       parameterType,
                                                       "first and only parameter",
                                                       errorPrefix);
            return new MethodSignature(MethodShape.OBSERVER, requestType, responseType);
        }

        throw new CodegenException(errorPrefix + " declarative gRPC method must declare "
                                           + "StreamObserver<RequestT> method(StreamObserver<ResponseT> observer): "
                                           + typeInfo.typeName().fqName() + "." + method.signature().text(),
                                   method.originatingElementValue());
    }

    private MethodSignature streamingSignature(TypeInfo typeInfo,
                                               TypedElementInfo method,
                                               MethodType methodType) {
        String errorPrefix = methodType.errorPrefix();
        List<TypedElementInfo> params = method.parameterArguments();
        if (params.size() != 1) {
            throw new CodegenException(errorPrefix + " declarative gRPC method must declare exactly one parameter "
                                               + "(response StreamObserver): "
                                               + typeInfo.typeName().fqName() + "." + method.signature().text(),
                                       method.originatingElementValue());
        }

        TypeName responseType = streamObserverType(typeInfo,
                                                   method,
                                                   params.getFirst().typeName(),
                                                   "first and only parameter",
                                                   errorPrefix);
        TypeName requestType = streamObserverType(typeInfo,
                                                  method,
                                                  method.typeName(),
                                                  "return type",
                                                  errorPrefix);

        return new MethodSignature(MethodShape.OBSERVER, requestType, responseType);
    }

    private TypeName streamObserverType(TypeInfo typeInfo,
                                        TypedElementInfo method,
                                        TypeName typeName,
                                        String element,
                                        String errorPrefix) {
        if (!typeName.fqName().equals(RpcServerTypes.STREAM_OBSERVER.fqName())
                || typeName.typeArguments().size() != 1) {
            throw new CodegenException(errorPrefix + " declarative gRPC method must use "
                                               + RpcServerTypes.STREAM_OBSERVER.fqName()
                                               + " as the " + element + ": "
                                               + typeInfo.typeName().fqName() + "." + method.signature().text(),
                                       method.originatingElementValue());
        }

        return typeName.typeArguments().getFirst();
    }

    private TypeName completingReturnType(TypeInfo typeInfo,
                                          TypedElementInfo method,
                                          TypeName typeName,
                                          String errorPrefix) {
        if (typeName.fqName().equals(RpcServerTypes.COMPLETABLE_FUTURE.fqName())
                || typeName.fqName().equals(RpcServerTypes.COMPLETION_STAGE.fqName())) {
            throw new CodegenException(errorPrefix + " declarative gRPC method must not use "
                                               + typeName.fqName()
                                               + " as a return type: "
                                               + typeInfo.typeName().fqName() + "." + method.signature().text(),
                                       method.originatingElementValue());
        }

        return typeName;
    }

    private TypeName streamResponseType(TypeInfo typeInfo,
                                        TypedElementInfo method,
                                        TypeName typeName,
                                        String errorPrefix) {
        if (!typeName.fqName().equals(RpcServerTypes.STREAM.fqName())
                || typeName.typeArguments().size() != 1) {
            throw new CodegenException(errorPrefix + " declarative gRPC method must return "
                                               + RpcServerTypes.STREAM.fqName()
                                               + "<ResponseT> when not using StreamObserver: "
                                               + typeInfo.typeName().fqName() + "." + method.signature().text(),
                                       method.originatingElementValue());
        }

        return typeName.typeArguments().getFirst();
    }

    private boolean isVoidType(TypeName typeName) {
        return typeName.equals(TypeNames.PRIMITIVE_VOID);
    }

    private boolean isStreamObserverType(TypeName typeName) {
        return typeName.fqName().equals(RpcServerTypes.STREAM_OBSERVER.fqName());
    }

    private Optional<MarshallerConfig> marshaller(Set<Annotation> annotations) {
        return Annotations.findFirst(RpcServerTypes.ANNOTATION_MARSHALLER, annotations)
                .map(annotation -> new MarshallerConfig(annotation.stringValue()
                                                                .filter(not(String::isBlank))
                                                                .orElse(DEFAULT_MARSHALLER_NAME)));
    }

    private List<InterceptorConfig> interceptors(RegistryRoundContext roundContext,
                                                 TypeInfo endpointType,
                                                 Optional<TypedElementInfo> method,
                                                 Set<Annotation> annotations) {
        List<TypeName> interceptorTypes = Annotations.findFirst(RpcServerTypes.ANNOTATION_INTERCEPTORS, annotations)
                .flatMap(Annotation::typeValues)
                .orElseGet(List::of);

        interceptorTypes.forEach(it -> validateServerInterceptor(roundContext, endpointType, method, it));

        return interceptorTypes.stream()
                .map(InterceptorConfig::new)
                .toList();
    }

    private void validateServerInterceptor(RegistryRoundContext roundContext,
                                           TypeInfo endpointType,
                                           Optional<TypedElementInfo> method,
                                           TypeName interceptorType) {
        Optional<TypeInfo> maybeInterceptor = roundContext.typeInfo(interceptorType)
                .or(() -> ctx.typeInfo(interceptorType));

        if (maybeInterceptor.isEmpty()) {
            return;
        }

        TypeInfo interceptorInfo = maybeInterceptor.get();
        Object originatingElement = method.map(TypedElementInfo::originatingElementValue)
                .orElseGet(endpointType::originatingElementValue);
        String location = method.map(it -> endpointType.typeName().fqName() + "." + it.signature().text())
                .orElseGet(() -> endpointType.typeName().fqName());

        if (interceptorInfo.findInHierarchy(RpcServerTypes.SERVER_INTERCEPTOR).isEmpty()) {
            throw new CodegenException("Declarative gRPC server interceptor " + interceptorType.fqName()
                                               + " must implement " + RpcServerTypes.SERVER_INTERCEPTOR.fqName()
                                               + ": " + location,
                                       originatingElement);
        }

        if (!isService(interceptorInfo)) {
            throw new CodegenException("Declarative gRPC server interceptor " + interceptorType.fqName()
                                               + " must be a Helidon service registry service"
                                               + " (annotated with @Service.Provider, @Service.Scope,"
                                               + " or a meta-annotation thereof): " + location,
                                       originatingElement);
        }
    }

    private boolean isService(TypeInfo type) {
        if (type.hasAnnotation(ServiceCodegenTypes.SERVICE_ANNOTATION_PROVIDER)) {
            return true;
        }
        if (type.hasAnnotation(ServiceCodegenTypes.SERVICE_ANNOTATION_SCOPE)) {
            return true;
        }
        for (Annotation annotation : type.annotations()) {
            if (annotation.hasMetaAnnotation(ServiceCodegenTypes.SERVICE_ANNOTATION_PROVIDER)) {
                return true;
            }
            if (annotation.hasMetaAnnotation(ServiceCodegenTypes.SERVICE_ANNOTATION_SCOPE)) {
                return true;
            }
        }
        return false;
    }

    private void marshallerSupplierParameter(Parameter.Builder param, String marshallerName) {
        param.addAnnotation(Annotation.create(ServiceCodegenTypes.SERVICE_ANNOTATION_NAMED, marshallerName));
        param.type(optionalMarshallerSupplierType());
    }

    private TypeName optionalMarshallerSupplierType() {
        return TypeName.builder()
                .from(TypeNames.OPTIONAL)
                .addTypeArgument(RpcServerTypes.MARSHALLER_SUPPLIER)
                .build();
    }

    private Map<String, MarshallerDependency> marshallerDependencies(Endpoint endpoint) {
        Map<String, MarshallerDependency> result = new LinkedHashMap<>();
        endpoint.marshaller().filter(not(MarshallerConfig::builtIn))
                .ifPresent(it -> result.computeIfAbsent(it.name(), this::marshallerDependency));
        endpoint.methods().stream()
                .map(GrpcMethod::marshaller)
                .flatMap(Optional::stream)
                .filter(not(MarshallerConfig::builtIn))
                .forEach(it -> result.computeIfAbsent(it.name(), this::marshallerDependency));
        return result;
    }

    private Map<TypeName, InterceptorDependency> interceptorDependencies(Endpoint endpoint) {
        Map<TypeName, InterceptorDependency> result = new LinkedHashMap<>();
        endpoint.interceptors().forEach(it -> result.computeIfAbsent(it.type(), this::serverInterceptorDependency));
        endpoint.methods().forEach(method -> method.interceptors()
                .forEach(it -> result.computeIfAbsent(it.type(), this::serverInterceptorDependency)));
        return result;
    }

    private MarshallerDependency marshallerDependency(String name) {
        String baseName = dependencyName("marshallerSupplier", name);
        return new MarshallerDependency(name, baseName + "_optional", baseName);
    }

    private InterceptorDependency serverInterceptorDependency(TypeName typeName) {
        return new InterceptorDependency(typeName, dependencyName("serverInterceptor", typeName.fqName()));
    }

    private void addMarshallerResolution(Constructor.Builder constructor,
                                         Endpoint endpoint,
                                         MarshallerDependency dependency) {
        constructor.addContent("var ")
                .addContent(dependency.variableName())
                .addContent(" = ")
                .addContent(dependency.parameterName())
                .addContent(".orElseThrow(() -> new ")
                .addContent(IllegalStateException.class)
                .addContent("(")
                .addContentLiteral("Declarative gRPC endpoint " + endpoint.type().typeName().fqName()
                                           + " requires a @Service.Named(\"" + dependency.name() + "\") "
                                           + RpcServerTypes.MARSHALLER_SUPPLIER.fqName() + " service")
                .addContentLine("));");
    }

    private void addMarshallerReference(Constructor.Builder constructor,
                                        MarshallerConfig marshaller,
                                        Map<String, MarshallerDependency> marshallerDependencies) {
        if (marshaller.builtIn()) {
            constructor.addContent(RpcServerTypes.MARSHALLER_SUPPLIER)
                    .addContent(".create()");
            return;
        }

        constructor.addContent(marshallerDependencies.get(marshaller.name()).variableName());
    }

    private String dependencyName(String prefix, String value) {
        return prefix + "_" + CodegenUtil.toConstantName(value).toLowerCase(Locale.ROOT);
    }

    private TypeName supplierOf(TypeName type) {
        return TypeName.builder(TypeNames.SUPPLIER)
                .addTypeArgument(type)
                .build();
    }

    private TypeName streamObserverOf(TypeName type) {
        return TypeName.builder(RpcServerTypes.STREAM_OBSERVER)
                .addTypeArgument(type)
                .build();
    }

    private static String grpcMethodName(TypedElementInfo method, Annotation annotation) {
        return annotation.stringValue()
                .filter(not(String::isBlank))
                .orElse(method.elementName());
    }

    private String descriptorConstant(TypeInfo typeInfo, TypedElementInfo method) {
        String uniqueName = ctx.uniqueName(typeInfo, method);
        return "METHOD_" + toConstantName(uniqueName);
    }

    private record Endpoint(TypeInfo type,
                            String serviceName,
                            Optional<String> listener,
                            Optional<MarshallerConfig> marshaller,
                            List<InterceptorConfig> interceptors,
                            Optional<ProtoMethod> protoMethod,
                            List<GrpcMethod> methods) {
    }

    private record ProtoMethod(String name, boolean isStatic) {
    }

    private record GrpcMethod(MethodType type,
                              String javaMethodName,
                              String grpcMethodName,
                              String descriptorConstant,
                              MethodShape shape,
                              TypeName requestType,
                              TypeName responseType,
                              Optional<MarshallerConfig> marshaller,
                              List<InterceptorConfig> interceptors) {
    }

    private record MarshallerConfig(String name) {
        private boolean builtIn() {
            return DEFAULT_MARSHALLER_NAME.equals(name) || PROTO_MARSHALLER_NAME.equals(name);
        }
    }

    private record MarshallerDependency(String name, String parameterName, String variableName) {
    }

    private record InterceptorConfig(TypeName type) {
    }

    private record InterceptorDependency(TypeName type, String variableName) {
    }

    private record MethodAnnotation(Annotation annotation, MethodType type) {
    }

    private record MethodSignature(MethodShape shape, TypeName requestType, TypeName responseType) {
    }

    private enum MethodShape {
        OBSERVER,
        NO_REQUEST_OBSERVER,
        COMPLETING_RETURN,
        NO_REQUEST_COMPLETING_RETURN,
        EMPTY_RESPONSE,
        NO_REQUEST_EMPTY_RESPONSE,
        STREAM_RETURN,
        NO_REQUEST_STREAM_RETURN
    }

    private enum MethodType {
        UNARY("unary", "unary") {
            @Override
            String errorPrefix() {
                return "Unary";
            }
        },
        SERVER_STREAMING("serverStreaming", "serverStreaming") {
            @Override
            String errorPrefix() {
                return "Server streaming";
            }
        },
        CLIENT_STREAMING("clientStreaming", "clientStreaming") {
            @Override
            String errorPrefix() {
                return "Client streaming";
            }
        },
        BIDIRECTIONAL("bidirectional", "bidirectional") {
            @Override
            String errorPrefix() {
                return "Bidirectional streaming";
            }
        };

        private final String registrationMethodName;
        private final String entryPointMethodName;

        MethodType(String registrationMethodName, String entryPointMethodName) {
            this.registrationMethodName = registrationMethodName;
            this.entryPointMethodName = entryPointMethodName;
        }

        private String registrationMethodName() {
            return registrationMethodName;
        }

        @SuppressWarnings("unused")
        private String entryPointMethodName() {
            return entryPointMethodName;
        }

        abstract String errorPrefix();
    }
}
