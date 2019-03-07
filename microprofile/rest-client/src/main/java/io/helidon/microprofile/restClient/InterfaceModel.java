package io.helidon.microprofile.restClient;

import java.lang.annotation.Annotation;
import java.lang.reflect.Parameter;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import javax.ws.rs.Consumes;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.ext.ParamConverter;
import javax.ws.rs.ext.ParamConverterProvider;

import org.eclipse.microprofile.rest.client.RestClientDefinitionException;
import org.eclipse.microprofile.rest.client.annotation.ClientHeaderParam;
import org.eclipse.microprofile.rest.client.annotation.RegisterClientHeaders;
import org.eclipse.microprofile.rest.client.ext.ClientHeadersFactory;
import org.eclipse.microprofile.rest.client.ext.ResponseExceptionMapper;

/**
 * Created by David Kral.
 */
public class InterfaceModel {

    private final Class<?> restClientClass;
    private final String[] produces;
    private final String[] consumes;
    private final String path;
    private final ClientHeadersFactory clientHeadersFactory;

    private final List<ClientHeaderParamModel> clientHeaders;
    private final List<ResponseExceptionMapper> responseExceptionMappers;
    private final List<ParamConverterProvider> paramConverterProviders;

    private InterfaceModel(Builder builder) {
        this.restClientClass = builder.restClientClass;
        this.path = builder.pathValue;
        this.produces = builder.produces;
        this.consumes = builder.consumes;
        this.clientHeaders = builder.clientHeaders;
        this.clientHeadersFactory = builder.clientHeadersFactory;
        this.responseExceptionMappers = new ArrayList<>();
        this.paramConverterProviders = new ArrayList<>();
    }

    public Class<?> getRestClientClass() {
        return restClientClass;
    }

    public String[] getProduces() {
        return produces;
    }

    public String[] getConsumes() {
        return consumes;
    }

    public String getPath() {
        return path;
    }

    public Optional<ClientHeadersFactory> getClientHeadersFactory() {
        return Optional.ofNullable(clientHeadersFactory);
    }

    public List<ClientHeaderParamModel> getClientHeaders() {
        return clientHeaders;
    }

    public List<ResponseExceptionMapper> getResponseExceptionMappers() {
        return responseExceptionMappers;
    }

    public List<ParamConverterProvider> getParamConverterProviders() {
        return paramConverterProviders;
    }

    Object resolveParamValue(Object arg, Type type, Annotation[] annotations) {
        for (ParamConverterProvider paramConverterProvider : paramConverterProviders) {
            ParamConverter<Object> converter = paramConverterProvider
                    .getConverter((Class<Object>) type, null, annotations);
            if (converter != null) {
                return converter.toString(arg);
            }
        }
        return arg;
    }

    static InterfaceModel from(Class<?> restClientClass) {
        return new Builder(restClientClass)
                .pathValue(restClientClass.getAnnotation(Path.class))
                .produces(restClientClass.getAnnotation(Produces.class))
                .consumes(restClientClass.getAnnotation(Consumes.class))
                .clientHeaders(restClientClass.getAnnotationsByType(ClientHeaderParam.class))
                .clientHeadersFactory(restClientClass.getAnnotation(RegisterClientHeaders.class))
                .build();
    }

    private static class Builder implements io.helidon.common.Builder<InterfaceModel> {

        private final Class<?> restClientClass;

        private String pathValue;
        private String[] produces;
        private String[] consumes;
        private ClientHeadersFactory clientHeadersFactory;
        private List<ClientHeaderParamModel> clientHeaders;

        private Builder(Class<?> restClientClass) {
            this.restClientClass = restClientClass;
        }

        /**
         * Path value from {@link Path} annotation. If annotation is null, empty String is set as path.
         *
         * @param path {@link Path} annotation
         * @return updated Builder instance
         */
        Builder pathValue(Path path) {
            this.pathValue = path != null ? path.value() : "";
            //if only / is added to path like this "localhost:80/test" it makes invalid path "localhost:80/test/"
            this.pathValue = pathValue.equals("/") ? "" : pathValue;
            return this;
        }

        /**
         * Extracts MediaTypes from {@link Produces} annotation.
         * If annotation is null, new String array with {@link MediaType#WILDCARD} is set.
         *
         * @param produces {@link Produces} annotation
         * @return updated Builder instance
         */
        Builder produces(Produces produces) {
            this.produces = produces != null ? produces.value() : new String[] {MediaType.WILDCARD};
            return this;
        }

        /**
         * Extracts MediaTypes from {@link Consumes} annotation.
         * If annotation is null, new String array with {@link MediaType#WILDCARD} is set.
         *
         * @param consumes {@link Consumes} annotation
         * @return updated Builder instance
         */
        Builder consumes(Consumes consumes) {
            this.consumes = consumes != null ? consumes.value() : new String[] {MediaType.WILDCARD};
            return this;
        }

        /**
         * Process data from {@link ClientHeaderParam} annotation to extract methods and values.
         *
         * @param clientHeaderParams {@link ClientHeaderParam} annotations
         * @return updated Builder instance
         */
        Builder clientHeaders(ClientHeaderParam[] clientHeaderParams) {
            clientHeaders = Arrays.stream(clientHeaderParams)
                    .map(clientHeaderParam -> new ClientHeaderParamModel(restClientClass, clientHeaderParam))
                    .collect(Collectors.toList());
            return this;
        }

        Builder clientHeadersFactory(RegisterClientHeaders registerClientHeaders) {
            clientHeadersFactory = registerClientHeaders != null
                    ? ReflectionUtil.createInstance(registerClientHeaders.value())
                    : null;
            return this;
        }

        @Override
        public InterfaceModel build() {
            validateHeaderDuplicityNames();
            return new InterfaceModel(this);
        }

        private void validateHeaderDuplicityNames() {
            ArrayList<String> names = new ArrayList<>();
            for (ClientHeaderParamModel clientHeaderParamModel : clientHeaders) {
                String headerName = clientHeaderParamModel.getHeaderName();
                if (names.contains(headerName)) {
                    throw new RestClientDefinitionException("Header name cannot be registered more then once on the same target."
                                                                    + "See " + restClientClass.getName());
                }
                names.add(headerName);
            }
        }
    }
}
