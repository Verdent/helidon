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
    private static final StreamObserver<Object> NOOP_OBSERVER = new StreamObserver<>() {
        @Override
        public void onNext(Object value) {
        }

        @Override
        public void onError(Throwable t) {
        }

        @Override
        public void onCompleted() {
        }
    };

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

        InterceptionContext ctx = createContext(descriptor, typeAnnotations, methodInfo);

        return (request, responseObserver) -> {
            Interception.Interceptor.Chain<Void> chain = new RequestResponseInvocation<>(ctx, interceptors, actualHandler::invoke);
            try {
                chain.proceed(new Object[] {request, responseObserver});
            } catch (Throwable thrown) {
                responseObserver.onError(thrown);
            }
        };
    }

    @Override
    public <ReqT, ResT> ServerCalls.ServerStreamingMethod<ReqT, ResT> serverStreaming(ServiceDescriptor<?> descriptor,
                                                                                      List<Annotation> typeAnnotations,
                                                                                      TypedElementInfo methodInfo,
                                                                                      ServerCalls.ServerStreamingMethod<ReqT, ResT> actualHandler) {
        if (noInterceptors) {
            return actualHandler;
        }

        InterceptionContext ctx = createContext(descriptor, typeAnnotations, methodInfo);

        return (request, responseObserver) -> {
            Interception.Interceptor.Chain<Void> chain = new RequestResponseInvocation<>(ctx, interceptors, actualHandler::invoke);
            try {
                chain.proceed(new Object[] {request, responseObserver});
            } catch (Throwable thrown) {
                responseObserver.onError(thrown);
            }
        };
    }

    @Override
    public <ReqT, ResT> ServerCalls.ClientStreamingMethod<ReqT, ResT> clientStreaming(ServiceDescriptor<?> descriptor,
                                                                                      List<Annotation> typeAnnotations,
                                                                                      TypedElementInfo methodInfo,
                                                                                      ServerCalls.ClientStreamingMethod<ReqT, ResT> actualHandler) {
        if (noInterceptors) {
            return actualHandler;
        }

        InterceptionContext ctx = createContext(descriptor, typeAnnotations, methodInfo);

        return responseObserver -> {
            Interception.Interceptor.Chain<StreamObserver<ReqT>> chain =
                    new ResponseObserverInvocation<>(ctx, interceptors, actualHandler::invoke);
            try {
                return chain.proceed(new Object[] {responseObserver});
            } catch (Throwable thrown) {
                responseObserver.onError(thrown);
                return noopObserver();
            }
        };
    }

    @Override
    public <ReqT, ResT> ServerCalls.BidiStreamingMethod<ReqT, ResT> bidirectional(ServiceDescriptor<?> descriptor,
                                                                                   List<Annotation> typeAnnotations,
                                                                                   TypedElementInfo methodInfo,
                                                                                   ServerCalls.BidiStreamingMethod<ReqT, ResT> actualHandler) {
        if (noInterceptors) {
            return actualHandler;
        }

        InterceptionContext ctx = createContext(descriptor, typeAnnotations, methodInfo);

        return responseObserver -> {
            Interception.Interceptor.Chain<StreamObserver<ReqT>> chain =
                    new ResponseObserverInvocation<>(ctx, interceptors, actualHandler::invoke);
            try {
                return chain.proceed(new Object[] {responseObserver});
            } catch (Throwable thrown) {
                responseObserver.onError(thrown);
                return noopObserver();
            }
        };
    }

    private static InterceptionContext createContext(ServiceDescriptor<?> descriptor,
                                                     List<Annotation> typeAnnotations,
                                                     TypedElementInfo methodInfo) {
        return InterceptionContext.builder()
                .typeAnnotations(typeAnnotations)
                .elementInfo(methodInfo)
                .serviceInfo(descriptor)
                .build();
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

    private static final class RequestResponseInvocation<ReqT, ResT> implements Interception.Interceptor.Chain<Void> {
        private final InterceptionContext ctx;
        private final List<Interception.EntryPointInterceptor> interceptors;
        private final RequestResponseHandler<ReqT, ResT> actualHandler;

        private int interceptorPos;

        private RequestResponseInvocation(InterceptionContext ctx,
                                          List<Interception.EntryPointInterceptor> interceptors,
                                          RequestResponseHandler<ReqT, ResT> actualHandler) {
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

    private static final class ResponseObserverInvocation<ReqT, ResT>
            implements Interception.Interceptor.Chain<StreamObserver<ReqT>> {
        private final InterceptionContext ctx;
        private final List<Interception.EntryPointInterceptor> interceptors;
        private final ResponseObserverHandler<ReqT, ResT> actualHandler;

        private int interceptorPos;

        private ResponseObserverInvocation(InterceptionContext ctx,
                                           List<Interception.EntryPointInterceptor> interceptors,
                                           ResponseObserverHandler<ReqT, ResT> actualHandler) {
            this.ctx = ctx;
            this.interceptors = interceptors;
            this.actualHandler = actualHandler;
        }

        @Override
        @SuppressWarnings("unchecked")
        public StreamObserver<ReqT> proceed(Object[] args) throws Exception {
            if (interceptorPos < interceptors.size()) {
                var interceptor = interceptors.get(interceptorPos);
                interceptorPos++;
                try {
                    return interceptor.proceed(ctx, this, args);
                } catch (Exception e) {
                    interceptorPos--;
                    throw e;
                }
            }

            return actualHandler.invoke((StreamObserver<ResT>) args[0]);
        }

        @Override
        public String toString() {
            return String.valueOf(ctx.elementInfo());
        }
    }

    @FunctionalInterface
    private interface RequestResponseHandler<ReqT, ResT> {
        void invoke(ReqT request, StreamObserver<ResT> responseObserver);
    }

    @FunctionalInterface
    private interface ResponseObserverHandler<ReqT, ResT> {
        StreamObserver<ReqT> invoke(StreamObserver<ResT> responseObserver);
    }

    @SuppressWarnings("unchecked")
    private static <T> StreamObserver<T> noopObserver() {
        return (StreamObserver<T>) NOOP_OBSERVER;
    }
}
