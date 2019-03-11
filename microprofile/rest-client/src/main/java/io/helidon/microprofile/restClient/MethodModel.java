package io.helidon.microprofile.restClient;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.lang.reflect.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import javax.json.JsonValue;
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
import javax.ws.rs.client.InvocationCallback;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.*;

import com.sun.xml.internal.ws.util.CompletedFuture;

import io.helidon.common.CollectionsHelper;

import org.eclipse.microprofile.rest.client.RestClientDefinitionException;
import org.eclipse.microprofile.rest.client.annotation.ClientHeaderParam;
import org.eclipse.microprofile.rest.client.ext.ResponseExceptionMapper;
import org.glassfish.jersey.message.internal.CompletableReader;

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
    private final RestClientModel subResourceModel;

    private MethodModel(Builder builder) {
        this.classModel = builder.classModel;
        this.returnType = builder.returnType;
        this.httpMethod = builder.httpMethod;
        this.path = builder.pathValue;
        this.produces = builder.produces;
        this.consumes = builder.consumes;
        this.parameterModels = builder.parameterModels;
        this.clientHeaders = builder.clientHeaders;
        if (httpMethod.isEmpty()) {
            subResourceModel = RestClientModel.from(returnType);
            InterfaceModel subResourceClassModel = subResourceModel.getClassModel();
            subResourceClassModel.getResponseExceptionMappers().addAll(classModel.getResponseExceptionMappers());
            subResourceClassModel.getParamConverterProviders().addAll(classModel.getParamConverterProviders());
        } else {
            subResourceModel = null;
        }
    }

    public Object invokeMethod(WebTarget classLevelTarget, Method method, Object[] args) {
        WebTarget methodLevelTarget = classLevelTarget.path(path);

        AtomicReference<Object> entity = new AtomicReference<>();
        AtomicReference<WebTarget> webTargetAtomicReference = new AtomicReference<>(methodLevelTarget);
        parameterModels.stream()
                .filter(parameterModel -> parameterModel.handles(PathParam.class))
                .forEach(parameterModel ->
                                 webTargetAtomicReference.set((WebTarget)
                                                                      parameterModel
                                                                              .handleParameter(webTargetAtomicReference.get(),
                                                                                               PathParam.class,
                                                                                               args[parameterModel
                                                                                                       .getParamPosition()])));

        parameterModels.stream()
                .filter(ParamModel::isEntity)
                .findFirst()
                .ifPresent(parameterModel -> entity.set(args[parameterModel.getParamPosition()]));

        WebTarget webTarget = webTargetAtomicReference.get();
        if (httpMethod.isEmpty()) {
            //sub resource method
            return subResourceProxy(webTarget, returnType);
        }
        webTarget = addQueryParams(webTarget, args);

        Invocation.Builder builder = webTarget
                .request(produces)
                .property(INVOKED_METHOD, method)
                .headers(addCustomHeaders(args));
        builder = addCookies(builder, args);

        Object response;

        if (CompletionStage.class.isAssignableFrom(method.getReturnType())) {
            response = asynchronousCall(builder, entity.get(), method);
        } else {
            response = synchronousCall(builder, entity.get(), method);
        }
        return response;
    }

    private Object synchronousCall(Invocation.Builder builder, Object entity, Method method) {
        Response response;

        if (entity != null
                && !httpMethod.equals(GET.class.getSimpleName())
                && !httpMethod.equals(DELETE.class.getSimpleName())) {
            response = builder.method(httpMethod, Entity.entity(entity, consumes[0]));
        } else {
            response = builder.method(httpMethod);
        }

        evaluateResponse(response, method);

        if (returnType.equals(Void.class)) {
            return null;
        } else if (returnType.equals(Response.class)) {
            return response;
        }
        return response.readEntity(returnType);
    }

    private Future asynchronousCall(Invocation.Builder builder, Object entity, Method method) {
        ParameterizedType type = (ParameterizedType) method.getGenericReturnType();
        Type actualTypeArgument = type.getActualTypeArguments()[0]; //completionStage<actualTypeArgument>
        CompletableFuture<Object> result = new CompletableFuture<>();
        InvocationCallback<Response> callback = new InvocationCallback<Response>() {
            @Override
            public void completed(Response response) {
                try {
                    evaluateResponse(response, method);
                    if (returnType.equals(Void.class)) {
                        result.complete(null);
                    } else if (returnType.equals(Response.class)) {
                        result.complete(response);
                    } else {
                        result.complete(response.readEntity(new GenericType<>(actualTypeArgument)));
                    }
                } catch (Exception e) {
                    result.completeExceptionally(e);
                }
            }

            @Override
            public void failed(Throwable throwable) {
                result.completeExceptionally(throwable);
            }
        };
        if (entity != null
                && !httpMethod.equals(GET.class.getSimpleName())
                && !httpMethod.equals(DELETE.class.getSimpleName())) {
            builder.async().method(httpMethod, Entity.entity(entity, consumes[0]),
                                   callback);
        } else {
            builder.async().method(httpMethod, callback);
        }

        return result;
    }

    private <T> T subResourceProxy(WebTarget webTarget, Class<T> subResourceType) {
        return (T) Proxy.newProxyInstance(subResourceType.getClassLoader(),
                                          new Class[] {subResourceType},
                                          new ProxyInvocationHandler(webTarget, subResourceModel)
        );
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

    private MultivaluedMap<String, Object> addCustomHeaders(Object[] args) {
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

    private MultivaluedMap<String, String> resolveCustomHeaders(Object[] args) {
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

    private <T> MultivaluedMap<String, String> createMultivaluedHeadersMap(List<ClientHeaderParamModel> clientHeaders) {
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
                        T instance = (T) createInstance(classModel.getRestClientClass());
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
                    throw new RuntimeException(e);
                } catch (InvocationTargetException e) {
                    if (clientHeaderParamModel.isRequired()) {
                        if (e.getCause() instanceof RuntimeException) {
                            throw (RuntimeException) e.getCause();
                        }
                        throw new RuntimeException(e.getCause());
                    }
                }
            }
        }
        return customHeaders;
    }

    private <T> T createInstance(Class<T> restClientClass) {
        return (T) Proxy.newProxyInstance(
                Thread.currentThread().getContextClassLoader(),
                new Class[] {restClientClass},
                (proxy, m, args) -> {
                    Constructor<MethodHandles.Lookup> constructor = MethodHandles.Lookup.class
                            .getDeclaredConstructor(Class.class);
                    constructor.setAccessible(true);
                    return constructor.newInstance(restClientClass)
                            .in(restClientClass)
                            .unreflectSpecial(m, restClientClass)
                            .bindTo(proxy)
                            .invokeWithArguments(args);
                });
    }

    private static List<String> createList(Object value) {
        if (value instanceof String[]) {
            String[] array = (String[]) value;
            return Arrays.asList(array);
        }
        String s = (String) value;
        return CollectionsHelper.listOf(s);
    }

    private void evaluateResponse(Response response, Method method) {
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
            if (throwable instanceof RuntimeException) {
                throw (RuntimeException) throwable;
            } else if (throwable instanceof Error) {
                throw (Error) throwable;
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
                .returnType(method.getGenericReturnType())
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
        } else if (httpAnnotations.isEmpty()) {
            //Sub resource method
            return "";
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
        public Builder returnType(Type returnType) {
            if (returnType instanceof ParameterizedType) {
                this.returnType = (Class<?>) ((ParameterizedType) returnType).getActualTypeArguments()[0];
            } else {
                this.returnType = (Class<?>) returnType;
            }
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
            //TODO uklidit
            Optional<ParamModel> entity = parameterModels.stream()
                    .filter(ParamModel::isEntity)
                    .findFirst();
            if (JsonValue.class.isAssignableFrom(returnType)
                    || (
                    entity.isPresent() && entity.get().getType() instanceof Class
                            && JsonValue.class.isAssignableFrom((Class<?>) entity.get().getType()))) {
                this.consumes = new String[] {MediaType.APPLICATION_JSON};
            }
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
