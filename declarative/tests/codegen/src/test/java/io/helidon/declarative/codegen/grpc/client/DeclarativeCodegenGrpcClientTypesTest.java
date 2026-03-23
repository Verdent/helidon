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

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import io.helidon.common.types.TypeName;
import io.helidon.grpc.api.RpcClient;
import io.helidon.webclient.grpc.GrpcClient;
import io.helidon.webclient.grpc.GrpcClientMethodDescriptor;
import io.helidon.webclient.grpc.GrpcServiceClient;
import io.helidon.webclient.grpc.GrpcServiceDescriptor;

import io.grpc.stub.StreamObserver;
import org.hamcrest.collection.IsEmptyCollection;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.fail;

class DeclarativeCodegenGrpcClientTypesTest {
    @Test
    void testTypes() {
        Field[] declaredFields = RpcClientTypes.class.getDeclaredFields();

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

        checkField(toCheck, checked, fields, "ANNOTATION_ENDPOINT", RpcClient.Endpoint.class);
        checkField(toCheck, checked, fields, "ANNOTATION_CLIENT_QUALIFIER", RpcClient.Client.class);
        checkField(toCheck, checked, fields, "ANNOTATION_SERVICE_NAME", RpcClient.ServiceName.class);
        checkField(toCheck, checked, fields, "ANNOTATION_UNARY", RpcClient.Unary.class);
        checkField(toCheck, checked, fields, "ANNOTATION_SERVER_STREAMING", RpcClient.ServerStreaming.class);
        checkField(toCheck, checked, fields, "ANNOTATION_CLIENT_STREAMING", RpcClient.ClientStreaming.class);
        checkField(toCheck, checked, fields, "ANNOTATION_BIDIRECTIONAL", RpcClient.Bidirectional.class);
        checkField(toCheck, checked, fields, "GRPC_CLIENT", GrpcClient.class);
        checkField(toCheck, checked, fields, "GRPC_SERVICE_CLIENT", GrpcServiceClient.class);
        checkField(toCheck, checked, fields, "GRPC_SERVICE_DESCRIPTOR", GrpcServiceDescriptor.class);
        checkField(toCheck, checked, fields, "GRPC_CLIENT_METHOD_DESCRIPTOR", GrpcClientMethodDescriptor.class);
        checkField(toCheck, checked, fields, "ITERATOR", Iterator.class);
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
