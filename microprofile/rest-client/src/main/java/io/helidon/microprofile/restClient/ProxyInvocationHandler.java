package io.helidon.microprofile.restClient;

import org.eclipse.microprofile.rest.client.ext.ResponseExceptionMapper;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.*;
import javax.ws.rs.ext.ParamConverter;
import javax.ws.rs.ext.ParamConverterProvider;

/**
 * Created by David Kral.
 */
public class ProxyInvocationHandler implements InvocationHandler {

    private final Class<?> iClass;
    private final Client client;
    private final WebTarget target;
    private final Set<ResponseExceptionMapper> responseExceptionMappers;
    private final Set<ParamConverterProvider> paramConverterProviders;
    private final RestClientModel restClientModel;

    public ProxyInvocationHandler(Class<?> iClass,
                                  Client client,
                                  WebTarget target,
                                  Set<ResponseExceptionMapper> responseExceptionMappers,
                                  Set<ParamConverterProvider> paramConverterProviders,
                                  RestClientModel restClientModel) {
        this.client = client;
        this.target = target;
        this.iClass = iClass;
        this.responseExceptionMappers = responseExceptionMappers;
        this.paramConverterProviders = paramConverterProviders;
        this.restClientModel = restClientModel;
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        return restClientModel.invokeMethod(target, method, args);
        /*WebTarget methodWebTarget;
        Path p = method.getAnnotation(Path.class);
        if (p != null) {
            methodWebTarget = target.path(p.value());
        } else {
            methodWebTarget = target;
        }

        Object entity = null;
        Map<String, Object> parametersToResolve = new HashMap<>();
        int counter = 0;
        for (Parameter parameter : method.getParameters()) {
            Optional<String> paramName = resolveParamName(parameter);
            if (paramName.isPresent()) {
                Object paramValue = resolveParamValue(args[counter], parameter);

                parametersToResolve.put(paramName.get(), paramValue);
            } else {
                entity = args[counter];
            }
            counter++;
        }
        methodWebTarget = methodWebTarget.resolveTemplates(parametersToResolve);
        List<Class<?>> httpMethod = InterfaceUtil.getHttpAnnotations(method);

        Invocation.Builder builder = methodWebTarget
                .request(MediaType.TEXT_PLAIN)
                .property(INVOKED_METHOD, method)
                .headers(InterfaceUtil.parseHeaders(iClass, method, args));

        Response response;

        if (entity != null
                && !httpMethod.get(0).equals(GET.class)
                && !httpMethod.get(0).equals(DELETE.class)) {
            response = builder.method(httpMethod.get(0).getSimpleName(), Entity.entity(entity, MediaType.TEXT_PLAIN));//CONSUMES
        } else {
            response = builder.method(httpMethod.get(0).getSimpleName());
        }

        evaluateResponse(response, method);

        if (method.getReturnType().equals(Void.class)) {
            return null;
        } else if (method.getReturnType().equals(Response.class)) {
            return response;
        }
        return response.readEntity(method.getReturnType());*/
    }

    private Object resolveParamValue(Object arg, Parameter parameter) {
        for (ParamConverterProvider paramConverterProvider : paramConverterProviders) {
            ParamConverter<Object> converter = paramConverterProvider
                    .getConverter((Class<Object>) parameter.getType(), null, parameter.getAnnotations());
            if (converter != null) {
                return converter.toString(arg);
            }
        }
        return arg;
    }

    private Optional<String> resolveParamName(Parameter param) {
        PathParam pathParam = param.getAnnotation(PathParam.class);
        if (pathParam != null) {
            return Optional.of(pathParam.value());
        }
        return Optional.empty();
    }

    private void evaluateResponse(Response response, Method method) throws Throwable {
        ResponseExceptionMapper lowestMapper = null;
        Throwable throwable = null;
        for (ResponseExceptionMapper responseExceptionMapper : responseExceptionMappers) {
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

}
