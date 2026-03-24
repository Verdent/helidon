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

package io.helidon.declarative.codegen.grpc;

import java.util.List;

import io.helidon.codegen.apt.AptProcessor;
import io.helidon.codegen.testing.TestCompiler;
import io.helidon.common.Generated;
import io.helidon.common.GenericType;
import io.helidon.common.types.Annotation;
import io.helidon.common.types.ElementKind;
import io.helidon.common.types.EnumValue;
import io.helidon.common.types.ResolvedType;
import io.helidon.common.types.TypeName;
import io.helidon.common.types.TypedElementInfo;
import io.helidon.config.Config;
import io.helidon.config.ConfigBuilderSupport;
import io.helidon.grpc.api.Grpc;
import io.helidon.webclient.grpc.RpcClient;
import io.helidon.webserver.grpc.RpcServer;
import io.helidon.grpc.core.MarshallerSupplier;
import io.helidon.service.registry.Dependency;
import io.helidon.service.registry.DependencyContext;
import io.helidon.service.registry.FactoryType;
import io.helidon.service.registry.InterceptionInvoker;
import io.helidon.service.registry.InterceptionMetadata;
import io.helidon.service.registry.Lookup;
import io.helidon.service.registry.Qualifier;
import io.helidon.service.registry.Service;
import io.helidon.service.registry.ServiceDescriptor;
import io.helidon.service.registry.ServiceRegistry;
import io.helidon.webclient.grpc.GrpcClient;
import io.helidon.webclient.grpc.GrpcClientMethodDescriptor;
import io.helidon.webclient.grpc.GrpcServiceClient;
import io.helidon.webclient.grpc.GrpcServiceDescriptor;
import io.helidon.webserver.WebServer;
import io.helidon.webserver.grpc.GrpcEntryPoint;
import io.helidon.webserver.grpc.GrpcRouteRegistration;

import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.ClientCall;
import io.grpc.ClientInterceptor;
import io.grpc.Metadata;
import io.grpc.MethodDescriptor;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.stub.StreamObserver;

public final class GrpcCodegenTestSupport {
    private static final List<Class<?>> CLASSPATH = List.of(
            Generated.class,
            GenericType.class,
            Annotation.class,
            ElementKind.class,
            EnumValue.class,
            ResolvedType.class,
            TypeName.class,
            TypedElementInfo.class,
            Config.class,
            ConfigBuilderSupport.class,
            Grpc.class,
            RpcClient.class,
            RpcServer.class,
            MarshallerSupplier.class,
            Dependency.class,
            DependencyContext.class,
            FactoryType.class,
            InterceptionInvoker.class,
            InterceptionMetadata.class,
            Lookup.class,
            Qualifier.class,
            Service.class,
            ServiceDescriptor.class,
            ServiceRegistry.class,
            GrpcClient.class,
            GrpcClientMethodDescriptor.class,
            GrpcEntryPoint.class,
            GrpcRouteRegistration.class,
            GrpcServiceClient.class,
            GrpcServiceDescriptor.class,
            WebServer.class,
            CallOptions.class,
            Channel.class,
            ClientCall.class,
            ClientInterceptor.class,
            Metadata.class,
            MethodDescriptor.class,
            ServerCall.class,
            ServerCallHandler.class,
            ServerInterceptor.class,
            com.google.protobuf.Descriptors.FileDescriptor.class,
            StreamObserver.class
    );

    private GrpcCodegenTestSupport() {
    }

    public static TestCompiler.Builder compilerBuilder() {
        return TestCompiler.builder()
                .currentRelease()
                .procOnly()
                .addClasspath(CLASSPATH)
                .addProcessor(AptProcessor::new);
    }

    public static String diagnostics(TestCompiler.Result result) {
        return String.join("\n", result.diagnostics());
    }
}
