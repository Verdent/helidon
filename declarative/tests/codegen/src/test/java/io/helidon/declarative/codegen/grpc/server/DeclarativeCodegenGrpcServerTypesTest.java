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

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import io.helidon.common.types.TypeName;
import io.helidon.webserver.grpc.RpcServer;
import io.helidon.grpc.core.MarshallerSupplier;
import io.helidon.webserver.grpc.GrpcEntryPoint;
import io.helidon.webserver.grpc.GrpcRouteRegistration;
import io.helidon.webserver.grpc.GrpcServiceDescriptor;

import io.grpc.ServerInterceptor;
import io.grpc.stub.ServerCalls;
import io.grpc.stub.StreamObserver;
import org.hamcrest.collection.IsEmptyCollection;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.fail;

class DeclarativeCodegenGrpcServerTypesTest {
    @Test
    void testTypes() {
        Field[] declaredFields = RpcServerTypes.class.getDeclaredFields();

        Set<String> toCheck = new HashSet<>();
        Set<String> checked = new HashSet<>();
        Map<String, Field> fields = new HashMap<>();

        for (Field declaredField : declaredFields) {
            String name = declaredField.getName();

            if (!declaredField.getType().equals(TypeName.class)) {
                continue;
            }
            assertThat(name + " must be static", Modifier.isStatic(declaredField.getModifiers()), is(true));
            assertThat(name + " must not be public", Modifier.isPublic(declaredField.getModifiers()), is(false));
            assertThat(name + " must be final", Modifier.isFinal(declaredField.getModifiers()), is(true));

            toCheck.add(name);
            fields.put(name, declaredField);
        }

        checkField(toCheck, checked, fields, "ANNOTATION_ENDPOINT", RpcServer.Endpoint.class);
        checkField(toCheck, checked, fields, "ANNOTATION_LISTENER", RpcServer.Listener.class);
        checkField(toCheck, checked, fields, "ANNOTATION_SERVICE_NAME", RpcServer.ServiceName.class);
        checkField(toCheck, checked, fields, "ANNOTATION_INTERCEPTORS", RpcServer.Interceptors.class);
        checkField(toCheck, checked, fields, "ANNOTATION_MARSHALLER", RpcServer.Marshaller.class);
        checkField(toCheck, checked, fields, "ANNOTATION_PROTO", RpcServer.Proto.class);
        checkField(toCheck, checked, fields, "ANNOTATION_UNARY", RpcServer.Unary.class);
        checkField(toCheck, checked, fields, "ANNOTATION_SERVER_STREAMING", RpcServer.ServerStreaming.class);
        checkField(toCheck, checked, fields, "ANNOTATION_CLIENT_STREAMING", RpcServer.ClientStreaming.class);
        checkField(toCheck, checked, fields, "ANNOTATION_BIDIRECTIONAL", RpcServer.Bidirectional.class);
        checkField(toCheck, checked, fields, "SERVER_INTERCEPTOR", ServerInterceptor.class);
        checkField(toCheck, checked, fields, "MARSHALLER_SUPPLIER", MarshallerSupplier.class);
        checkField(toCheck, checked, fields, "GRPC_ROUTE_REGISTRATION", GrpcRouteRegistration.class);
        checkField(toCheck, checked, fields, "GRPC_SERVICE_DESCRIPTOR", GrpcServiceDescriptor.class);
        checkField(toCheck, checked, fields, "GRPC_ENTRY_POINTS", GrpcEntryPoint.EntryPoints.class);
        checkField(toCheck, checked, fields, "WEB_SERVER", io.helidon.webserver.WebServer.class);
        checkField(toCheck, checked, fields, "GRPC_UNARY_METHOD", ServerCalls.UnaryMethod.class);
        checkField(toCheck, checked, fields, "GRPC_SERVER_STREAMING_METHOD", ServerCalls.ServerStreamingMethod.class);
        checkField(toCheck, checked, fields, "GRPC_CLIENT_STREAMING_METHOD", ServerCalls.ClientStreamingMethod.class);
        checkField(toCheck, checked, fields, "GRPC_BIDI_STREAMING_METHOD", ServerCalls.BidiStreamingMethod.class);
        checkField(toCheck,
                   checked,
                   fields,
                   "PROTO_FILE_DESCRIPTOR",
                   com.google.protobuf.Descriptors.FileDescriptor.class);
        checkField(toCheck, checked, fields, "STREAM_OBSERVER", StreamObserver.class);

        assertThat("If the collection is not empty, please add appropriate checkField line to this test",
                   toCheck,
                   IsEmptyCollection.empty());
    }

    private void checkField(Set<String> namesToCheck,
                            Set<String> checkedNames,
                            Map<String, Field> namesToFields,
                            String name,
                            Class<?> expectedType) {
        Field field = namesToFields.get(name);
        assertThat("Field " + name + " does not exist in the class", field, notNullValue());
        try {
            namesToCheck.remove(name);
            if (checkedNames.add(name)) {
                TypeName value = (TypeName) field.get(null);
                assertThat("Field " + name, value.fqName(), is(expectedType.getCanonicalName()));
            } else {
                fail("Field " + name + " is checked more than once");
            }
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }
}
