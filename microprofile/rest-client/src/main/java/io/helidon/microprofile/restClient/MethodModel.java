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
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import javax.ws.rs.Consumes;
import javax.ws.rs.CookieParam;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

import io.helidon.common.CollectionsHelper;

import org.eclipse.microprofile.rest.client.RestClientDefinitionException;
import org.eclipse.microprofile.rest.client.annotation.ClientHeaderParam;
import org.eclipse.microprofile.rest.client.ext.ResponseExceptionMapper;

/**
 * Created by David Kral.
 */
public class MethodModel {

    private static final String INVOKED_METHOD = "org.eclipse.microprofile.rest.client.invokedMethod";

    private final InterfaceModel classModel;

    private final Class<?> returnType;
    private final String httpMethod;
    private final String path;
    private final String[] produces;
    private final String[] consumes;
    private final List<ParamModel> parameterModels;
    private final List<ClientHeaderParamModel> clientHeaders;

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

        AtomicReference<Object> entity = new AtomicReference<>();
        AtomicReference<WebTarget> webTargetAtomicReference = new AtomicReference<>(methodLevelTarget);
        parameterModels.stream()
                .filter(parameterModel -> parameterModel.handles(PathParam.class))
                .forEach(parameterModel ->
                                 webTargetAtomicReference.set((WebTarget)
                                                                      parameterModel.handleParameter(webTargetAtomicReference.get(),
                                                                                                     PathParam.class,
                                                                                                     args[parameterModel.getParamPosition()])));

        parameterModels.stream()
                .filter(ParamModel::isEntity)
                .findFirst()
                .ifPresent(parameterModel -> entity.set(args[parameterModel.getParamPosition()]));

        WebTarget webTarget = webTargetAtomicReference.get();
        webTarget = addQueryParams(webTarget, args);

        Invocation.Builder builder = webTarget
                .request(produces)
                .property(INVOKED_METHOD, method)
                .headers(addCustomHeaders(args));
        builder = addCookies(builder, args);

        Response response;

        if (entity.get() != null
                && !httpMethod.equals(GET.class.getSimpleName())
                && !httpMethod.equals(DELETE.class.getSimpleName())) {
            response = builder.method(httpMethod, Entity.entity(entity.get(), consumes[0]));
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

    private WebTarget addQueryParams(WebTarget webTarget, Object[] args) {
        Map<String, Object[]> queryParams = new HashMap<>();
        WebTarget toReturn = webTarget;
        parameterModels.stream()
                .filter(parameterModel -> parameterModel.handles(QueryParam.class))
                .forEach(parameterModel -> parameterModel.handleParameter(queryParams,
                                                                          QueryParam.class,
                                                                          args[parameterModel.getParamPosition()]));

        for (Map.Entry<String, Object[]> entry : queryParams.entrySet()) {
            toReturn = toReturn.queryParam(entry.getKey(), entry.getValue());
        }
        return toReturn;
    }

    private Invocation.Builder addCookies(Invocation.Builder builder, Object[] args) {
        Map<String, String> cookies = new HashMap<>();
        Invocation.Builder toReturn = builder;
        parameterModels.stream()
                .filter(parameterModel -> parameterModel.handles(CookieParam.class))
                .forEach(parameterModel -> parameterModel.handleParameter(cookies,
                                                                          CookieParam.class,
                                                                          args[parameterModel.getParamPosition()]));

        for (Map.Entry<String, String> entry : cookies.entrySet()) {
            toReturn = toReturn.cookie(entry.getKey(), entry.getValue());
        }
        return toReturn;
    }

    private MultivaluedMap<String, Object> addCustomHeaders(Object[] args) throws Throwable {
        MultivaluedMap<String, Object> result = new MultivaluedHashMap<>();
        for (Map.Entry<String, List<String>> entry : resolveCustomHeaders(args).entrySet()) {
            result.add(entry.getKey(), entry.getValue());
        }
        for (String produce : produces) {
            result.add(HttpHeaders.ACCEPT, produce);
        }
        //TODO check this. Added because of ProducesConsumesTest.java
        result.add(HttpHeaders.CONTENT_TYPE, consumes[0]);
        return result;
    }

    private MultivaluedMap<String, String> resolveCustomHeaders(Object[] args)
            throws Throwable {
        MultivaluedMap<String, String> customHeaders = new MultivaluedHashMap<>();
        customHeaders.putAll(createMultivaluedHeadersMap(classModel.getClientHeaders()));
        customHeaders.putAll(createMultivaluedHeadersMap(clientHeaders));
        parameterModels.stream()
                .filter(parameterModel -> parameterModel.handles(HeaderParam.class))
                .forEach(parameterModel -> parameterModel.handleParameter(customHeaders,
                                                                          HeaderParam.class,
                                                                          args[parameterModel.getParamPosition()]));

        MultivaluedMap<String, String> inbound = new MultivaluedHashMap<>();
        HeadersContext.get().ifPresent(headersContext -> inbound.putAll(headersContext.inboundHeaders()));

        AtomicReference<MultivaluedMap<String, String>> toReturn = new AtomicReference<>(customHeaders);
        classModel.getClientHeadersFactory().ifPresent(clientHeadersFactory -> toReturn
                .set(clientHeadersFactory.update(inbound, customHeaders)));
        return toReturn.get();
    }

    private <T> MultivaluedMap<String, String> createMultivaluedHeadersMap(List<ClientHeaderParamModel> clientHeaders)
            throws Throwable {
        MultivaluedMap<String, String> customHeaders = new MultivaluedHashMap<>();
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

    private static List<String> createList(Object value) {
        if (value instanceof String[]) {
            String[] array = (String[]) value;
            return Arrays.asList(array);
        }
        String s = (String) value;
        return CollectionsHelper.listOf(s);
    }

    private void evaluateResponse(Response response, Method method) throws Throwable {
        ResponseExceptionMapper lowestMapper = null;
        Throwable throwable = null;
        for (ResponseExceptionMapper responseExceptionMapper : classModel.getResponseExceptionMappers()) {
            if (responseExceptionMapper.handles(response.getStatus(), response.getHeaders())) {
                if (lowestMapper == null
                        || throwable == null
                        || lowestMapper.getPriority() > responseExceptionMapper.getPriority()) {
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

    static MethodModel from(InterfaceModel classModel, Method method) {
        return new Builder(classModel, method)
                .returnType(method.getReturnType())
                .httpMethod(parseHttpMethod(classModel, method))
                .pathValue(method.getAnnotation(Path.class))
                .produces(method.getAnnotation(Produces.class))
                .consumes(method.getAnnotation(Consumes.class))
                .parameters(parameterModels(classModel, method))
                .clientHeaders(method.getAnnotationsByType(ClientHeaderParam.class))
                .build();
    }

    private static String parseHttpMethod(InterfaceModel classModel, Method method) {
        List<Class<?>> httpAnnotations = InterfaceUtil.getHttpAnnotations(method);
        if (httpAnnotations.size() > 1) {
            throw new RestClientDefinitionException("Method can't have more then one annotation of @HttpMethod type. " +
                                                            "See " + classModel.getRestClientClass().getName() +
                                                            "::" + method.getName());
        }
        return httpAnnotations.get(0).getSimpleName();
    }

    private static List<ParamModel> parameterModels(InterfaceModel classModel, Method method) {
        ArrayList<ParamModel> parameterModels = new ArrayList<>();
        Parameter[] parameters = method.getParameters();
        for (int i = 0; i < parameters.length; i++) {
            parameterModels.add(ParamModel.from(classModel, parameters[i].getType(), parameters[i], i));
        }
        return parameterModels;
    }

    private static class Builder implements io.helidon.common.Builder<MethodModel> {

        private final InterfaceModel classModel;
        private final Method method;

        private Class<?> returnType;
        private String httpMethod;
        private String pathValue;
        private String[] produces;
        private String[] consumes;
        private List<ParamModel> parameterModels;
        private List<ClientHeaderParamModel> clientHeaders;

        private Builder(InterfaceModel classModel, Method method) {
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
            //if only / is added to path like this "localhost:80/test" it makes invalid path "localhost:80/test/"
            this.pathValue = pathValue.equals("/") ? "" : pathValue;
            return this;
        }

        /**
         * Extracts MediaTypes from {@link Produces} annotation.
         * If annotation is null, value from {@link InterfaceModel} is set.
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
         * If annotation is null, value from {@link InterfaceModel} is set.
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
        Builder parameters(List<ParamModel> parameterModels) {
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
                    .filter(parameterModel -> parameterModel instanceof PathParamModel)
                    .map(parameterModel -> ((PathParamModel) parameterModel).getPathParamName())
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
