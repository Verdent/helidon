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

import java.util.Optional;
import java.util.Set;

import io.helidon.codegen.CodegenContext;
import io.helidon.codegen.CodegenOptions;
import io.helidon.codegen.spi.TypeMapper;
import io.helidon.codegen.spi.TypeMapperProvider;
import io.helidon.common.Weight;
import io.helidon.common.Weighted;
import io.helidon.common.types.Annotation;
import io.helidon.common.types.TypeInfo;
import io.helidon.service.codegen.ServiceCodegenTypes;

/**
 * Type mapper that materializes the default service scope for declarative gRPC endpoints.
 * If no explicit service definition is declared, endpoints default to {@code @Service.Singleton},
 * which keeps the generated route registration aligned with REST while still allowing
 * explicit alternative scopes such as {@code @Service.PerLookup}.
 */
@Weight(Weighted.DEFAULT_WEIGHT - 10)
public class RpcServerTypeMapperProvider implements TypeMapperProvider {
    /**
     * Public constructor required by {@link java.util.ServiceLoader}.
     */
    public RpcServerTypeMapperProvider() {
    }

    @Override
    public TypeMapper create(CodegenOptions options) {
        return new RpcServerTypeMapper();
    }

    private static class RpcServerTypeMapper implements TypeMapper {
        private static final Annotation DEFAULT_SCOPE = Annotation.create(ServiceCodegenTypes.SERVICE_ANNOTATION_SINGLETON);

        @Override
        public boolean supportsType(TypeInfo type) {
            return type.hasAnnotation(RpcServerTypes.ANNOTATION_ENDPOINT);
        }

        @Override
        public Optional<TypeInfo> map(CodegenContext ctx, TypeInfo typeInfo) {
            if (hasExplicitServiceDefinition(typeInfo)) {
                return Optional.of(typeInfo);
            }

            return Optional.of(TypeInfo.builder(typeInfo)
                                       .addAnnotation(DEFAULT_SCOPE)
                                       .build());
        }

        private static boolean hasExplicitServiceDefinition(TypeInfo typeInfo) {
            if (typeInfo.hasAnnotation(ServiceCodegenTypes.SERVICE_ANNOTATION_PROVIDER)
                    || typeInfo.hasAnnotation(ServiceCodegenTypes.SERVICE_ANNOTATION_DESCRIBE)
                    || typeInfo.hasAnnotation(ServiceCodegenTypes.SERVICE_ANNOTATION_PER_INSTANCE)) {
                return true;
            }

            for (Annotation annotation : typeInfo.annotations()) {
                if (annotation.typeName().equals(RpcServerTypes.ANNOTATION_ENDPOINT)) {
                    // Ignore the endpoint marker itself so the mapper can materialize the default scope.
                    continue;
                }
                if (annotation.hasMetaAnnotation(ServiceCodegenTypes.SERVICE_ANNOTATION_PROVIDER)
                        || annotation.hasMetaAnnotation(ServiceCodegenTypes.SERVICE_ANNOTATION_SCOPE)) {
                    return true;
                }
            }
            return false;
        }
    }
}
