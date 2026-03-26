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
import io.helidon.codegen.classmodel.Method;
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

import static io.helidon.declarative.codegen.DeclarativeTypes.CONFIG;
import static io.helidon.declarative.codegen.DeclarativeTypes.SINGLETON_ANNOTATION;
import static io.helidon.service.codegen.ServiceCodegenTypes.SERVICE_ANNOTATION_NAMED;
import static java.util.function.Predicate.not;

class RpcClientExtension implements RegistryCodegenExtension {
    static final TypeName GENERATOR = TypeName.create(RpcClientExtension.class);
    private static final String DEFAULT_MARSHALLER_NAME = "default";
    private static final String PROTO_MARSHALLER_NAME = "proto";

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

        Endpoint endpoint = toEndpoint(roundContext, clientApi);
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
        Map<String, MarshallerDependency> marshallerDependencies = marshallerDependencies(endpoint);
        Map<TypeName, InterceptorDependency> interceptorDependencies = interceptorDependencies(endpoint);

        Constructor.Builder constructor = Constructor.builder()
                .accessModifier(AccessModifier.PACKAGE_PRIVATE)
                .addParameter(config -> config
                        .name("config")
                        .type(CONFIG));

        if (endpoint.clientName().isPresent()) {
            constructor.addParameter(param -> param
                    .name("namedClientSupplier")
                    .update(it -> grpcClientSupplierParameter(it, endpoint.clientName())));
        }
        constructor.addParameter(param -> param
                .name("clientSupplier")
                .update(it -> grpcClientSupplierParameter(it, Optional.empty())));
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
                                                         "uri",
                                                         endpoint.uri());
        constructor.addContent("var endpointConfig = config.get(")
                .addContentLiteral(endpoint.configKey())
                .addContentLine(");")
                .addContentLine("if (endpointConfig.exists()) {")
                .addContentLine("uri = endpointConfig.get(\"uri\").asString().orElse(uri);")
                .addContentLine("}");

        DelcarativeConfigSupport.assignResolveExpression(constructor,
                                                         "config",
                                                         "serviceName",
                                                         endpoint.serviceName());

        constructor.addContentLine("if (serviceName.isBlank()) {")
                .addContent("serviceName = ")
                .addContentLiteral(endpoint.type().className())
                .addContentLine(";")
                .addContentLine("}")
                .addContentLine("var clientUri = uri;");

        constructor.addContent(RpcClientTypes.GRPC_CLIENT)
                .addContentLine(" tmpClient = null;")
                .addContentLine("var clientConfig = endpointConfig.get(\"client\");")
                .addContentLine("if (clientConfig.exists()) {")
                .update(it -> assignConfiguredClient(it, "tmpClient", "clientUri"))
                .addContentLine("}");

        if (endpoint.clientName().isPresent()) {
            constructor.addContentLine("if (tmpClient == null) {")
                    .addContentLine("tmpClient = namedClientSupplier.get().orElse(null);")
                    .addContentLine("}");
        }

        constructor.addContentLine("if (tmpClient == null) {")
                .addContentLine("tmpClient = clientSupplier.get().orElse(null);")
                .addContentLine("}")
                .addContentLine("if (tmpClient == null) {")
                .update(it -> assignCreatedClient(it, endpoint, "tmpClient", "clientUri"))
                .addContentLine("}")
                .addContentLine("this.client = tmpClient;");

        marshallerDependencies.values().forEach(dependency -> addMarshallerResolution(constructor, endpoint, dependency));

        constructor.addContent("var descriptor = ")
                .addContent(RpcClientTypes.GRPC_SERVICE_DESCRIPTOR)
                .addContentLine(".builder()")
                .increaseContentPadding()
                .increaseContentPadding()
                .addContentLine(".serviceName(serviceName)");

        endpoint.interceptors().forEach(interceptor -> constructor.addContent(".addInterceptor(")
                .addContent(interceptorDependencies.get(interceptor.type()).variableName())
                .addContentLine(")"));

        for (GrpcMethod method : endpoint.methods()) {
            addMethod(constructor, method, marshallerDependencies, interceptorDependencies);
        }

        constructor.addContentLine(".build();")
                .decreaseContentPadding()
                .decreaseContentPadding()
                .addContentLine("this.serviceClient = client.serviceClient(descriptor);");

        return constructor;
    }

    private void assignConfiguredClient(Constructor.Builder constructor, String variableName, String uriVariableName) {
        constructor.addContent("if (")
                .addContent(uriVariableName)
                .addContentLine(".isBlank()) {")
                .addContent(variableName)
                .addContent(" = ")
                .addContent(RpcClientTypes.GRPC_CLIENT)
                .addContent(".create(")
                .addContent(RpcClientTypes.GRPC_CLIENT_CONFIG)
                .addContentLine(".create(clientConfig));")
                .decreaseContentPadding()
                .addContent("} else if (")
                .addContent(uriVariableName)
                .addContentLine(".startsWith(\"http://\")) {")
                .addContent(variableName)
                .addContent(" = ")
                .addContent(RpcClientTypes.GRPC_CLIENT)
                .addContent(".create(it -> it.config(clientConfig).baseUri(")
                .addContent(uriVariableName)
                .addContentLine(").tls(t -> t.enabled(false)));")
                .decreaseContentPadding()
                .addContentLine("} else {")
                .addContent(variableName)
                .addContent(" = ")
                .addContent(RpcClientTypes.GRPC_CLIENT)
                .addContent(".create(it -> it.config(clientConfig).baseUri(")
                .addContent(uriVariableName)
                .addContentLine("));")
                .addContentLine("}");
    }

    private void assignCreatedClient(Constructor.Builder constructor,
                                     Endpoint endpoint,
                                     String variableName,
                                     String uriVariableName) {
        constructor.addContent("if (")
                .addContent(uriVariableName)
                .addContentLine(".isBlank()) {")
                .addContent("throw new ")
                .addContent(IllegalStateException.class)
                .addContent("(")
                .addContentLiteral("Declarative gRPC client " + endpoint.type().fqName()
                                           + " must define a non-blank endpoint URI")
                .addContentLine(");")
                .addContentLine("}")
                .addContent("if (")
                .addContent(uriVariableName)
                .addContentLine(".startsWith(\"http://\")) {")
                .addContent(variableName)
                .addContent(" = ")
                .addContent(RpcClientTypes.GRPC_CLIENT)
                .addContent(".create(it -> it.baseUri(")
                .addContent(uriVariableName)
                .addContentLine(").tls(t -> t.enabled(false)));")
                .decreaseContentPadding()
                .addContentLine("} else {")
                .addContent(variableName)
                .addContent(" = ")
                .addContent(RpcClientTypes.GRPC_CLIENT)
                .addContent(".create(it -> it.baseUri(")
                .addContent(uriVariableName)
                .addContentLine("));")
                .addContentLine("}");
    }

    private void grpcClientSupplierParameter(Parameter.Builder param, Optional<String> clientName) {
        clientName.ifPresent(name -> param.addAnnotation(Annotation.create(SERVICE_ANNOTATION_NAMED, name)));
        param.type(optionalGrpcClientSupplierType());
    }

    private void marshallerSupplierParameter(Parameter.Builder param, String marshallerName) {
        param.addAnnotation(Annotation.create(SERVICE_ANNOTATION_NAMED, marshallerName));
        param.type(optionalMarshallerSupplierType());
    }

    private TypeName optionalGrpcClientSupplierType() {
        TypeName optionalGrpcClient = TypeName.builder()
                .from(TypeNames.OPTIONAL)
                .addTypeArgument(RpcClientTypes.GRPC_CLIENT)
                .build();
        return TypeName.builder()
                .from(TypeNames.SUPPLIER)
                .addTypeArgument(optionalGrpcClient)
                .build();
    }

    private TypeName optionalMarshallerSupplierType() {
        return TypeName.builder()
                .from(TypeNames.OPTIONAL)
                .addTypeArgument(RpcClientTypes.MARSHALLER_SUPPLIER)
                .build();
    }

    private void addMethod(Constructor.Builder constructor,
                           GrpcMethod method,
                           Map<String, MarshallerDependency> marshallerDependencies,
                           Map<TypeName, InterceptorDependency> interceptorDependencies) {
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
                .addContent(".class)");

        method.marshaller().ifPresent(marshaller -> {
            constructor.addContent(".marshallerSupplier(");
            addMarshallerReference(constructor, marshaller, marshallerDependencies);
            constructor.addContent(")");
        });

        method.interceptors().forEach(interceptor -> constructor.addContent(".intercept(")
                .addContent(interceptorDependencies.get(interceptor.type()).variableName())
                .addContent(")"));

        constructor.addContentLine(".build())");
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

                    if (method.type() == MethodType.CLIENT_STREAMING
                            && !method.parameters().isEmpty()
                            && isStream(method.parameters().getFirst().typeName())) {
                        it.addContent("try (var requestStream = ")
                                .addContent(method.parameters().getFirst().name())
                                .addContentLine(") {");
                        addClientMethodReturn(it, method, "requestStream.iterator()");
                        it.addContentLine("}");
                    } else {
                        addClientMethodReturn(it, method, null);
                    }
                }));
    }

    private void addClientMethodReturn(Method.Builder methodBuilder,
                                       GrpcMethod method,
                                       String requestAccessOverride) {
        if (method.type() == MethodType.SERVER_STREAMING && isStream(method.returnType())) {
            methodBuilder.addContent("return java.util.stream.StreamSupport.stream("
                                             + "java.util.Spliterators.spliteratorUnknownSize(serviceClient.")
                    .addContent(method.type().clientMethodName())
                    .addContent("(")
                    .addContentLiteral(method.grpcMethodName())
                    .addContent(", ");
            addRequestAccess(methodBuilder, method, requestAccessOverride);
            methodBuilder.addContentLine("), java.util.Spliterator.ORDERED), false);");
            return;
        }

        methodBuilder.addContent("return serviceClient.")
                .addContent(method.type().clientMethodName())
                .addContent("(")
                .addContentLiteral(method.grpcMethodName())
                .addContent(", ");
        addRequestAccess(methodBuilder, method, requestAccessOverride);
        methodBuilder.addContentLine(");");
    }

    private void addRequestAccess(Method.Builder methodBuilder,
                                  GrpcMethod method,
                                  String requestAccessOverride) {
        if (method.parameters().isEmpty()) {
            methodBuilder.addContent(RpcClientTypes.PROTO_EMPTY)
                    .addContent(".getDefaultInstance()");
            return;
        }

        if (requestAccessOverride != null) {
            methodBuilder.addContent(requestAccessOverride);
            return;
        }

        if (method.type() == MethodType.CLIENT_STREAMING && isIterable(method.parameters().getFirst().typeName())) {
            methodBuilder.addContent(method.parameters().getFirst().name())
                    .addContent(".iterator()");
            return;
        }

        methodBuilder.addContent(method.parameters().getFirst().name());
    }

    private Endpoint toEndpoint(RegistryRoundContext roundContext, TypeInfo typeInfo) {
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
        clientName.filter(RpcClientExtension::isConfigExpression)
                .ifPresent(it -> {
                    throw new CodegenException("Declarative gRPC client clientName must be a static service registry name"
                                                       + " and does not support configuration expressions",
                                               typeInfo.originatingElementValue());
                });

        Optional<MarshallerConfig> typeMarshaller = marshaller(typeAnnotations);
        List<InterceptorConfig> typeInterceptors = interceptors(roundContext,
                                                                typeInfo,
                                                                Optional.empty(),
                                                                typeAnnotations);

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
            grpcMethods.add(grpcMethod(origin.method(),
                                       methodAnnotation,
                                       marshaller(annotations).or(() -> typeMarshaller),
                                       interceptors(roundContext,
                                                    typeInfo,
                                                    Optional.of(origin.method()),
                                                    annotations)));
        });

        if (grpcMethods.isEmpty()) {
            throw new CodegenException("Declarative gRPC client " + typeInfo.typeName().fqName()
                                               + " does not declare any supported gRPC methods",
                                       typeInfo.originatingElementValue());
        }

        return new Endpoint(typeInfo.typeName(),
                            endpointAnnotation.stringValue().orElse(""),
                            endpointAnnotation.stringValue("configKey")
                                    .filter(not(String::isBlank))
                                    .orElseGet(() -> typeInfo.typeName().fqName()),
                            clientName,
                            serviceName,
                            typeInterceptors,
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

    private GrpcMethod grpcMethod(TypedElementInfo method,
                                  MethodAnnotation methodAnnotation,
                                  Optional<MarshallerConfig> marshaller,
                                  List<InterceptorConfig> interceptors) {
        String grpcMethodName = methodAnnotation.annotation()
                .stringValue()
                .filter(not(String::isBlank))
                .orElse(method.elementName());

        return switch (methodAnnotation.type()) {
            case UNARY -> unaryMethod(method, grpcMethodName, marshaller, interceptors);
            case SERVER_STREAMING -> serverStreamingMethod(method, grpcMethodName, marshaller, interceptors);
            case CLIENT_STREAMING -> clientStreamingMethod(method, grpcMethodName, marshaller, interceptors);
            case BIDIRECTIONAL -> bidirectionalMethod(method, grpcMethodName, marshaller, interceptors);
        };
    }

    private GrpcMethod unaryMethod(TypedElementInfo method,
                                   String grpcMethodName,
                                   Optional<MarshallerConfig> marshaller,
                                   List<InterceptorConfig> interceptors) {
        List<TypedElementInfo> parameters = method.parameterArguments();
        if (parameters.size() > 1) {
            throw new CodegenException("Declarative gRPC unary client method must have zero or one request parameter",
                                       method.originatingElementValue());
        }

        TypeName requestType = parameters.isEmpty()
                ? RpcClientTypes.PROTO_EMPTY
                : parameters.getFirst().typeName();
        TypeName responseType = method.typeName();

        if (voidType(responseType) || isIterator(responseType) || isStream(responseType) || isStreamObserver(responseType)) {
            throw new CodegenException("Declarative gRPC unary client method must return a single response type",
                                       method.originatingElementValue());
        }
        if (!parameters.isEmpty() && (isIterator(requestType) || isStream(requestType) || isStreamObserver(requestType))) {
            throw new CodegenException("Declarative gRPC unary client request parameter must not be an iterator,"
                                               + " stream, or stream observer",
                                       method.originatingElementValue());
        }

        return new GrpcMethod(MethodType.UNARY,
                              method.elementName(),
                              method.typeName(),
                              toParameters(parameters),
                              requestType,
                              responseType,
                              grpcMethodName,
                              marshaller,
                              interceptors);
    }

    private GrpcMethod serverStreamingMethod(TypedElementInfo method,
                                             String grpcMethodName,
                                             Optional<MarshallerConfig> marshaller,
                                             List<InterceptorConfig> interceptors) {
        List<TypedElementInfo> parameters = method.parameterArguments();
        if (parameters.size() > 1) {
            throw new CodegenException("Declarative gRPC server streaming client method must have zero or one request"
                                               + " parameter",
                                       method.originatingElementValue());
        }

        TypeName requestType = parameters.isEmpty()
                ? RpcClientTypes.PROTO_EMPTY
                : parameters.getFirst().typeName();
        if (!parameters.isEmpty() && (isIterator(requestType) || isStream(requestType) || isStreamObserver(requestType))) {
            throw new CodegenException("Declarative gRPC server streaming client request parameter must not be an"
                                               + " iterator, stream, or stream observer",
                                       method.originatingElementValue());
        }

        TypeName responseType = iteratorOrStreamType(method.typeName(),
                                                     method,
                                                     "Declarative gRPC server streaming client method must return "
                                                             + RpcClientTypes.ITERATOR.fqName()
                                                             + "<ResponseT> or "
                                                             + RpcClientTypes.STREAM.fqName()
                                                             + "<ResponseT>");

        return new GrpcMethod(MethodType.SERVER_STREAMING,
                              method.elementName(),
                              method.typeName(),
                              toParameters(parameters),
                              requestType,
                              responseType,
                              grpcMethodName,
                              marshaller,
                              interceptors);
    }

    private GrpcMethod clientStreamingMethod(TypedElementInfo method,
                                             String grpcMethodName,
                                             Optional<MarshallerConfig> marshaller,
                                             List<InterceptorConfig> interceptors) {
        List<TypedElementInfo> parameters = method.parameterArguments();
        if (parameters.size() != 1) {
            throw new CodegenException("Declarative gRPC client streaming client method must have exactly one request"
                                               + " iterator, iterable, or stream parameter",
                                       method.originatingElementValue());
        }

        TypeName requestType = iteratorOrIterableOrStreamType(parameters.getFirst().typeName(),
                                                              method,
                                                              "Declarative gRPC client streaming client request parameter"
                                                                      + " must be "
                                                                      + RpcClientTypes.ITERATOR.fqName()
                                                                      + "<RequestT>, "
                                                                      + RpcClientTypes.ITERABLE.fqName()
                                                                      + "<RequestT>, or "
                                                                      + RpcClientTypes.STREAM.fqName()
                                                                      + "<RequestT>");
        TypeName responseType = method.typeName();

        if (voidType(responseType) || isIterator(responseType) || isStream(responseType) || isStreamObserver(responseType)) {
            throw new CodegenException("Declarative gRPC client streaming client method must return a single response type",
                                       method.originatingElementValue());
        }

        return new GrpcMethod(MethodType.CLIENT_STREAMING,
                              method.elementName(),
                              method.typeName(),
                              toParameters(parameters),
                              requestType,
                              responseType,
                              grpcMethodName,
                              marshaller,
                              interceptors);
    }

    private GrpcMethod bidirectionalMethod(TypedElementInfo method,
                                           String grpcMethodName,
                                           Optional<MarshallerConfig> marshaller,
                                           List<InterceptorConfig> interceptors) {
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
                              grpcMethodName,
                              marshaller,
                              interceptors);
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

    private TypeName iteratorOrStreamType(TypeName typeName, TypedElementInfo method, String message) {
        if ((!isIterator(typeName) && !isStream(typeName)) || typeName.typeArguments().size() != 1) {
            throw new CodegenException(message, method.originatingElementValue());
        }
        return typeName.typeArguments().getFirst();
    }

    private TypeName iteratorOrIterableOrStreamType(TypeName typeName, TypedElementInfo method, String message) {
        if ((!isIterator(typeName) && !isIterable(typeName) && !isStream(typeName))
                || typeName.typeArguments().size() != 1) {
            throw new CodegenException(message, method.originatingElementValue());
        }
        return typeName.typeArguments().getFirst();
    }

    private boolean isIterable(TypeName typeName) {
        return typeName.fqName().equals(RpcClientTypes.ITERABLE.fqName());
    }

    private boolean isIterator(TypeName typeName) {
        return typeName.fqName().equals(RpcClientTypes.ITERATOR.fqName());
    }

    private boolean isStream(TypeName typeName) {
        return typeName.fqName().equals(RpcClientTypes.STREAM.fqName());
    }

    private boolean isStreamObserver(TypeName typeName) {
        return typeName.fqName().equals(RpcClientTypes.STREAM_OBSERVER.fqName());
    }

    private boolean voidType(TypeName typeName) {
        return TypeNames.PRIMITIVE_VOID.equals(typeName) || TypeNames.BOXED_VOID.equals(typeName);
    }

    private Optional<MarshallerConfig> marshaller(Set<Annotation> annotations) {
        return Annotations.findFirst(RpcClientTypes.ANNOTATION_MARSHALLER, annotations)
                .map(annotation -> new MarshallerConfig(annotation.stringValue()
                                                                .filter(not(String::isBlank))
                                                                .orElse(DEFAULT_MARSHALLER_NAME)));
    }

    private List<InterceptorConfig> interceptors(RegistryRoundContext roundContext,
                                                 TypeInfo clientType,
                                                 Optional<TypedElementInfo> method,
                                                 Set<Annotation> annotations) {
        List<TypeName> interceptorTypes = Annotations.findFirst(RpcClientTypes.ANNOTATION_INTERCEPTORS, annotations)
                .flatMap(Annotation::typeValues)
                .orElseGet(List::of);

        interceptorTypes.forEach(it -> validateClientInterceptor(roundContext, clientType, method, it));

        return interceptorTypes.stream()
                .map(InterceptorConfig::new)
                .toList();
    }

    private void validateClientInterceptor(RegistryRoundContext roundContext,
                                           TypeInfo clientType,
                                           Optional<TypedElementInfo> method,
                                           TypeName interceptorType) {
        Optional<TypeInfo> maybeInterceptor = roundContext.typeInfo(interceptorType)
                .or(() -> ctx.typeInfo(interceptorType));

        if (maybeInterceptor.isEmpty()) {
            return;
        }

        TypeInfo interceptorInfo = maybeInterceptor.get();
        Object originatingElement = method.map(TypedElementInfo::originatingElementValue)
                .orElseGet(clientType::originatingElementValue);
        String location = method.map(it -> clientType.typeName().fqName() + "." + it.signature().text())
                .orElseGet(() -> clientType.typeName().fqName());

        if (interceptorInfo.findInHierarchy(RpcClientTypes.CLIENT_INTERCEPTOR).isEmpty()) {
            throw new CodegenException("Declarative gRPC client interceptor " + interceptorType.fqName()
                                               + " must implement " + RpcClientTypes.CLIENT_INTERCEPTOR.fqName()
                                               + ": " + location,
                                       originatingElement);
        }

        if (!isService(interceptorInfo)) {
            throw new CodegenException("Declarative gRPC client interceptor " + interceptorType.fqName()
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

    private Map<String, MarshallerDependency> marshallerDependencies(Endpoint endpoint) {
        Map<String, MarshallerDependency> result = new LinkedHashMap<>();
        endpoint.methods().stream()
                .map(GrpcMethod::marshaller)
                .flatMap(Optional::stream)
                .filter(not(MarshallerConfig::builtIn))
                .forEach(it -> result.computeIfAbsent(it.name(), this::marshallerDependency));
        return result;
    }

    private Map<TypeName, InterceptorDependency> interceptorDependencies(Endpoint endpoint) {
        Map<TypeName, InterceptorDependency> result = new LinkedHashMap<>();
        endpoint.interceptors().forEach(it -> result.computeIfAbsent(it.type(), this::clientInterceptorDependency));
        endpoint.methods().forEach(method -> method.interceptors()
                .forEach(it -> result.computeIfAbsent(it.type(), this::clientInterceptorDependency)));
        return result;
    }

    private MarshallerDependency marshallerDependency(String name) {
        String baseName = dependencyName("marshallerSupplier", name);
        return new MarshallerDependency(name, baseName + "_optional", baseName);
    }

    private InterceptorDependency clientInterceptorDependency(TypeName typeName) {
        return new InterceptorDependency(typeName, dependencyName("clientInterceptor", typeName.fqName()));
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
                .addContentLiteral("Declarative gRPC client " + endpoint.type().fqName()
                                           + " requires a @Service.Named(\"" + dependency.name() + "\") "
                                           + RpcClientTypes.MARSHALLER_SUPPLIER.fqName() + " service")
                .addContentLine("));");
    }

    private void addMarshallerReference(Constructor.Builder constructor,
                                        MarshallerConfig marshaller,
                                        Map<String, MarshallerDependency> marshallerDependencies) {
        if (marshaller.builtIn()) {
            constructor.addContent(RpcClientTypes.MARSHALLER_SUPPLIER)
                    .addContent(".create()");
            return;
        }

        constructor.addContent(marshallerDependencies.get(marshaller.name()).variableName());
    }

    private String dependencyName(String prefix, String value) {
        return prefix + "_" + CodegenUtil.toConstantName(value).toLowerCase(Locale.ROOT);
    }

    private record Endpoint(TypeName type,
                            String uri,
                            String configKey,
                            Optional<String> clientName,
                            String serviceName,
                            List<InterceptorConfig> interceptors,
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
                              String grpcMethodName,
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

    private static boolean isConfigExpression(String value) {
        return value.contains("${");
    }
}
