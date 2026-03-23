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

package io.helidon.webserver.grpc;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import io.helidon.common.Weighted;
import io.helidon.common.Weights;
import io.helidon.common.types.Annotation;
import io.helidon.common.types.TypedElementInfo;
import io.helidon.service.registry.Interception;
import io.helidon.service.registry.InterceptionContext;
import io.helidon.service.registry.Service;
import io.helidon.service.registry.ServiceDescriptor;
import io.helidon.service.registry.ServiceInstance;

import io.grpc.stub.ServerCalls;
import io.grpc.stub.StreamObserver;

@SuppressWarnings("deprecation")
@Service.Singleton
class GrpcEntryPointsImpl implements GrpcEntryPoint.EntryPoints {
    private final boolean noInterceptors;
    private final List<Interception.EntryPointInterceptor> interceptors;

    @Service.Inject
    GrpcEntryPointsImpl(List<ServiceInstance<Interception.EntryPointInterceptor>> entryPointInterceptors) {
        this.noInterceptors = entryPointInterceptors.isEmpty();
        this.interceptors = merge(entryPointInterceptors);
    }

    @Override
    public <ReqT, ResT> ServerCalls.UnaryMethod<ReqT, ResT> unary(ServiceDescriptor<?> descriptor,
                                                                  List<Annotation> typeAnnotations,
                                                                  TypedElementInfo methodInfo,
                                                                  ServerCalls.UnaryMethod<ReqT, ResT> actualHandler) {
        if (noInterceptors) {
            return actualHandler;
        }

        InterceptionContext ctx = InterceptionContext.builder()
                .typeAnnotations(typeAnnotations)
                .elementInfo(methodInfo)
                .serviceInfo(descriptor)
                .build();

        return (request, responseObserver) -> {
            Interception.Interceptor.Chain<Void> chain = new UnaryInvocation<>(ctx, interceptors, actualHandler);
            try {
                chain.proceed(new Object[] {request, responseObserver});
            } catch (Throwable thrown) {
                responseObserver.onError(thrown);
            }
        };
    }

    private static List<Interception.EntryPointInterceptor> merge(List<ServiceInstance<Interception.EntryPointInterceptor>> entryPoints) {
        List<WeightedInterceptor> merged = new ArrayList<>();
        entryPoints.stream()
                .map(it -> new WeightedInterceptor(it.get(), it.weight()))
                .forEach(merged::add);
        Weights.sort(merged);

        return merged.stream()
                .map(WeightedInterceptor::interceptor)
                .collect(Collectors.toUnmodifiableList());
    }

    private record WeightedInterceptor(Interception.EntryPointInterceptor interceptor,
                                       double weight) implements Weighted {
    }

    private static final class UnaryInvocation<ReqT, ResT> implements Interception.Interceptor.Chain<Void> {
        private final InterceptionContext ctx;
        private final List<Interception.EntryPointInterceptor> interceptors;
        private final ServerCalls.UnaryMethod<ReqT, ResT> actualHandler;

        private int interceptorPos;

        private UnaryInvocation(InterceptionContext ctx,
                                List<Interception.EntryPointInterceptor> interceptors,
                                ServerCalls.UnaryMethod<ReqT, ResT> actualHandler) {
            this.ctx = ctx;
            this.interceptors = interceptors;
            this.actualHandler = actualHandler;
        }

        @Override
        @SuppressWarnings("unchecked")
        public Void proceed(Object[] args) throws Exception {
            if (interceptorPos < interceptors.size()) {
                var interceptor = interceptors.get(interceptorPos);
                interceptorPos++;
                try {
                    interceptor.proceed(ctx, this, args);
                    return null;
                } catch (Exception e) {
                    interceptorPos--;
                    throw e;
                }
            }

            actualHandler.invoke((ReqT) args[0], (StreamObserver<ResT>) args[1]);
            return null;
        }

        @Override
        public String toString() {
            return String.valueOf(ctx.elementInfo());
        }
    }
}
