package io.helidon.microprofile.restClient;

import java.lang.invoke.MethodHandles;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.ext.ParamConverter;
import javax.ws.rs.ext.ParamConverterProvider;

import io.helidon.common.CollectionsHelper;

import org.eclipse.microprofile.rest.client.RestClientDefinitionException;
import org.eclipse.microprofile.rest.client.annotation.ClientHeaderParam;
import org.eclipse.microprofile.rest.client.ext.ResponseExceptionMapper;

/**
 * Created by David Kral.
 */
public class MethodModel {

    private static final String INVOKED_METHOD = "org.eclipse.microprofile.rest.client.invokedMethod";

    private final ClassModel classModel;

    private final Class<?> returnType;
    private final String httpMethod;
    private final String path;
    private final String[] produces;
    private final String[] consumes;
    private final List<ParameterModel> parameterModels;
    private List<ClientHeaderParamModel> clientHeaders;

    private MethodModel(Builder builder) {
        this.classModel = builder.classModel;
        this.returnType = builder.returnType;
        this.httpMethod = builder.httpMethod;
        this.path = builder.pathValue;
        this.produces = builder.produces;
        this.consumes = builder.consumes;
        this.parameterModels = builder.parameterModels;
        this.clientHeaders = builder.clientHeaders;
    }

    public Object invokeMethod(WebTarget classLevelTarget, Method method, Object[] args) throws Throwable {
        WebTarget methodLevelTarget = classLevelTarget.path(path);
        Object entity = null;
        Map<String, Object> parametersToResolve = new HashMap<>();
        for (ParameterModel parameterModel : parameterModels) {
            if (parameterModel.getPathParamName().isPresent()) {
                Object paramValue = resolveParamValue(args[parameterModel.getParamPosition()], parameterModel.getParameter());
                parametersToResolve.put(parameterModel.getPathParamName().get(), paramValue);
            } else if (parameterModel.isEntity()) {
                entity = args[parameterModel.getParamPosition()];
            }
        }
        methodLevelTarget = methodLevelTarget.resolveTemplates(parametersToResolve);
        Invocation.Builder builder = methodLevelTarget
                .request(produces)
                .property(INVOKED_METHOD, method)
                .headers(addCustomHeaders(args));

        Response response;

        if (entity != null
                && !httpMethod.equals(GET.class.getSimpleName())
                && !httpMethod.equals(DELETE.class.getSimpleName())) {
            //TODO upravit
            response = builder.method(httpMethod, Entity.entity(entity, consumes[0]));//CONSUMES
        } else {
            response = builder.method(httpMethod);
        }

        evaluateResponse(response, method);

        if (method.getReturnType().equals(Void.class)) {
            return null;
        } else if (method.getReturnType().equals(Response.class)) {
            return response;
        }
        return response.readEntity(method.getReturnType());
    }

    private Object resolveParamValue(Object arg, Parameter parameter) {
        for (ParamConverterProvider paramConverterProvider : classModel.getParamConverterProviders()) {
            ParamConverter<Object> converter = paramConverterProvider
                    .getConverter((Class<Object>) parameter.getType(), null, parameter.getAnnotations());
            if (converter != null) {
                return converter.toString(arg);
            }
        }
        return arg;
    }

    private MultivaluedMap<String, Object> addCustomHeaders(Object[] args)
            throws Throwable {
        MultivaluedMap<String, Object> customHeaders = new MultivaluedHashMap<>();
        customHeaders.putAll(createMultivaluedHeadersMap(classModel.getClientHeaders()));
        customHeaders.putAll(createMultivaluedHeadersMap(clientHeaders));
        return customHeaders;
    }

    private <T> MultivaluedMap<String, Object> createMultivaluedHeadersMap(List<ClientHeaderParamModel> clientHeaders)
            throws Throwable {
        MultivaluedMap<String, Object> customHeaders = new MultivaluedHashMap<>();
        for (ClientHeaderParamModel clientHeaderParamModel : clientHeaders) {
            if (clientHeaderParamModel.getComputeMethod() == null) {
                customHeaders
                        .put(clientHeaderParamModel.getHeaderName(), Arrays.asList(clientHeaderParamModel.getHeaderValue()));
            } else {
                try {
                    Method method = clientHeaderParamModel.getComputeMethod();
                    if (method.isDefault()) {
                        //method is interface default
                        //we need to create instance of the interface to be able to call default method
                        T instance = (T) Proxy.newProxyInstance(
                                Thread.currentThread().getContextClassLoader(),
                                new Class[] {classModel.getRestClientClass()},
                                (proxy, m, args) -> {
                                    Constructor<MethodHandles.Lookup> constructor = MethodHandles.Lookup.class
                                            .getDeclaredConstructor(Class.class);
                                    constructor.setAccessible(true);
                                    return constructor.newInstance(classModel.getRestClientClass())
                                            .in(classModel.getRestClientClass())
                                            .unreflectSpecial(m, classModel.getRestClientClass())
                                            .bindTo(proxy)
                                            .invokeWithArguments(args);
                                });
                        if (method.getParameterCount() > 0) {
                            customHeaders.put(clientHeaderParamModel.getHeaderName(),
                                              createList(method.invoke(instance, clientHeaderParamModel.getHeaderName())));
                        } else {
                            customHeaders.put(clientHeaderParamModel.getHeaderName(),
                                              createList(method.invoke(instance, null)));
                        }
                    } else {
                        //Method is static
                        if (method.getParameterCount() > 0) {
                            customHeaders.put(clientHeaderParamModel.getHeaderName(),
                                              createList(method.invoke(null, clientHeaderParamModel.getHeaderName())));
                        } else {
                            customHeaders.put(clientHeaderParamModel.getHeaderName(),
                                              createList(method.invoke(null, null)));
                        }
                    }
                } catch (IllegalAccessException e) {
                    //TODO what kind of exception to throw?
                    e.printStackTrace();
                } catch (InvocationTargetException e) {
                    if (clientHeaderParamModel.isRequired()) {
                        throw e.getCause();
                    }
                }
            }
        }
        return customHeaders;
    }

    private static List<Object> createList(Object value) {
        if (value instanceof String[]) {
            String[] array = (String[]) value;
            return Arrays.asList(array);
        }
        return CollectionsHelper.listOf(value);
    }

    private void evaluateResponse(Response response, Method method) throws Throwable {
        ResponseExceptionMapper lowestMapper = null;
        Throwable throwable = null;
        for (ResponseExceptionMapper responseExceptionMapper : classModel.getResponseExceptionMappers()) {
            if (responseExceptionMapper.handles(response.getStatus(), response.getHeaders())) {
                if (lowestMapper == null || lowestMapper.getPriority() > responseExceptionMapper.getPriority()) {
                    lowestMapper = responseExceptionMapper;
                    Throwable tmp = lowestMapper.toThrowable(response);
                    if (tmp != null) {
                        throwable = tmp;
                    }
                }
            }
        }
        if (throwable != null) {
            if (throwable instanceof RuntimeException || throwable instanceof Error) {
                throw throwable;
            }
            for (Class<?> exception : method.getExceptionTypes()) {
                if (throwable.getClass().isAssignableFrom(exception)) {
                    throw new WebApplicationException(throwable);
                }
            }
        }
    }

    static MethodModel from(ClassModel classModel, Method method) {
        return new Builder(classModel, method)
                .returnType(method.getReturnType())
                .httpMethod(parseHttpMethod(classModel, method))
                .pathValue(method.getAnnotation(Path.class))
                .produces(method.getAnnotation(Produces.class))
                .consumes(method.getAnnotation(Consumes.class))
                .parameters(parameterModels(method))
                .clientHeaders(method.getAnnotationsByType(ClientHeaderParam.class))
                .build();
    }

    private static String parseHttpMethod(ClassModel classModel, Method method) {
        List<Class<?>> httpAnnotations = InterfaceUtil.getHttpAnnotations(method);
        if (httpAnnotations.size() > 1) {
            throw new RestClientDefinitionException("Method can't have more then one annotation of @HttpMethod type. " +
                                                            "See " + classModel.getRestClientClass().getName() +
                                                            "::" + method.getName());
        }
        return httpAnnotations.get(0).getSimpleName();
    }

    private static List<ParameterModel> parameterModels(Method method) {
        ArrayList<ParameterModel> parameterModels = new ArrayList<>();
        Parameter[] parameters = method.getParameters();
        for (int i = 0; i < parameters.length; i++) {
            parameterModels.add(ParameterModel.from(parameters[i], i));
        }
        return parameterModels;
    }

    private static class Builder implements io.helidon.common.Builder<MethodModel> {

        private final ClassModel classModel;
        private final Method method;

        private Class<?> returnType;
        private String httpMethod;
        private String pathValue;
        private String[] produces;
        private String[] consumes;
        private List<ParameterModel> parameterModels;
        private List<ClientHeaderParamModel> clientHeaders;

        private Builder(ClassModel classModel, Method method) {
            this.classModel = classModel;
            this.method = method;
        }

        /**
         * Return type of the method.
         *
         * @param returnType Method return type
         * @return updated Builder instance
         */
        public Builder returnType(Class<?> returnType) {
            this.returnType = returnType;
            return this;
        }

        /**
         * HTTP method of the method.
         *
         * @param httpMethod HTTP method of the method
         * @return updated Builder instance
         */
        public Builder httpMethod(String httpMethod) {
            this.httpMethod = httpMethod;
            return this;
        }

        /**
         * Path value from {@link Path} annotation. If annotation is null, empty String is set as path.
         *
         * @param path {@link Path} annotation
         * @return updated Builder instance
         */
        public Builder pathValue(Path path) {
            this.pathValue = path != null ? path.value() : "";
            return this;
        }

        /**
         * Extracts MediaTypes from {@link Produces} annotation.
         * If annotation is null, value from {@link ClassModel} is set.
         *
         * @param produces {@link Produces} annotation
         * @return updated Builder instance
         */
        Builder produces(Produces produces) {
            this.produces = produces == null ? classModel.getProduces() : produces.value();
            return this;
        }

        /**
         * Extracts MediaTypes from {@link Consumes} annotation.
         * If annotation is null, value from {@link ClassModel} is set.
         *
         * @param consumes {@link Consumes} annotation
         * @return updated Builder instance
         */
        Builder consumes(Consumes consumes) {
            this.consumes = consumes == null ? classModel.getConsumes() : consumes.value();
            return this;
        }

        /**
         * {@link List} of transformed method parameters.
         *
         * @param parameterModels {@link List} of parameters
         * @return updated Builder instance
         */
        Builder parameters(List<ParameterModel> parameterModels) {
            this.parameterModels = parameterModels;
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
                    .map(clientHeaderParam -> new ClientHeaderParamModel(classModel.getRestClientClass(), clientHeaderParam))
                    .collect(Collectors.toList());
            return this;
        }

        @Override
        public MethodModel build() {
            validateParameters();
            validateHeaderDuplicityNames();
            return new MethodModel(this);
        }

        private void validateParameters() {
            UriBuilder uriBuilder = UriBuilder.fromUri(classModel.getPath()).path(pathValue);
            List<String> parameters = InterfaceUtil.parseParameters(uriBuilder.toTemplate());
            List<String> methodPathParameters = parameterModels.stream()
                    .filter(parameterModel -> !parameterModel.isEntity())
                    .map(parameterModel -> parameterModel.getPathParamName().get())
                    .collect(Collectors.toList());
            for (String parameterName : methodPathParameters) {
                if (!parameters.contains(parameterName)) {
                    throw new RestClientDefinitionException("Parameter name " + parameterName + " on "
                                                                    + classModel.getRestClientClass().getName()
                                                                    + "::" + method.getName()
                                                                    + " doesn't match any @Path variable name.");
                }
                parameters.remove(parameterName);
            }
            if (!parameters.isEmpty()) {
                throw new RestClientDefinitionException("Some variable names does not have matching @PathParam " +
                                                                "defined on method " + classModel.getRestClientClass().getName()
                                                                + "::" + method.getName());
            }
        }

        private void validateHeaderDuplicityNames() {
            ArrayList<String> names = new ArrayList<>();
            for (ClientHeaderParamModel clientHeaderParamModel : clientHeaders) {
                String headerName = clientHeaderParamModel.getHeaderName();
                if (names.contains(headerName)) {
                    throw new RestClientDefinitionException("Header name cannot be registered more then once on the same target."
                                                                    + "See " + classModel.getRestClientClass().getName());
                }
                names.add(headerName);
            }
        }
    }
}
