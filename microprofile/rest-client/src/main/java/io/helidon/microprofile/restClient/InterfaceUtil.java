package io.helidon.microprofile.restClient;

import org.eclipse.microprofile.rest.client.RestClientDefinitionException;
import org.eclipse.microprofile.rest.client.annotation.ClientHeaderParam;

import javax.ws.rs.HeaderParam;
import javax.ws.rs.HttpMethod;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.UriBuilder;

import java.lang.annotation.Annotation;
import java.lang.invoke.MethodHandles;
import java.lang.reflect.AnnotatedElement;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.Parameter;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import io.helidon.common.CollectionsHelper;

/**
 * @author David Kral
 */
class InterfaceUtil {

    private static final String PARAMETER_PARSE_REGEXP = "(?<=\\{).+?(?=\\})";
    private static final Pattern PATTERN = Pattern.compile(PARAMETER_PARSE_REGEXP);

    static void validateInterface(Class<?> iClass) {
        checkHttpAnnotations(iClass);
        checkPathParameters(iClass);
        checkClientHeaderParams(iClass);
    }

    private static void checkHttpAnnotations(Class<?> iClass) {
        for (Method method : iClass.getMethods()) {
            List<Class<?>> httpAnnotations = getHttpAnnotations(method);
            if (httpAnnotations.size() > 1) {
                throw new RestClientDefinitionException("Method can't have more then one annotation of @HttpMethod type. " +
                                                                "See " + iClass.getName() + "::" + method.getName());
            }
        }
    }

    private static void checkPathParameters(Class<?> iClass) {
        Path classLevelPath = iClass.getAnnotation(Path.class);
        for (Method method : iClass.getMethods()) {
            UriBuilder uriBuilder;
            Path methodLevelPath = method.getAnnotation(Path.class);
            if (classLevelPath != null && methodLevelPath != null) {
                uriBuilder = UriBuilder.fromUri(classLevelPath.value() + "/" + methodLevelPath.value());
            } else if (methodLevelPath != null) {
                uriBuilder = UriBuilder.fromUri(methodLevelPath.value());
            } else if (classLevelPath != null) {
                uriBuilder = UriBuilder.fromUri(classLevelPath.value());
            } else {
                continue;
            }
            List<String> parameters = parseParameters(uriBuilder.toTemplate());
            for (Parameter parameter : method.getParameters()) {
                PathParam pathParamAnnotation = parameter.getAnnotation(PathParam.class);
                if (pathParamAnnotation != null) {
                    if (!parameters.contains(pathParamAnnotation.value())) {
                        throw new RestClientDefinitionException("Parameter name " + pathParamAnnotation.value() + " on "
                                                                        + iClass.getName() + "::" + method.getName()
                                                                        + " doesn't match any @Path variable name.");
                    }
                    parameters.remove(pathParamAnnotation.value());
                }
            }
            if (!parameters.isEmpty()) {
                throw new RestClientDefinitionException("Some variable names does not have matching @PathParam " +
                                                                "defined on method " + iClass.getName()
                                                                + "::" + method.getName());
            }
        }
    }

    private static List<String> parseParameters(String template) {
        List<String> allMatches = new ArrayList<>();
        Matcher m = PATTERN.matcher(template);
        while (m.find()) {
            allMatches.add(m.group());
        }
        return allMatches;
    }

    private static void checkClientHeaderParams(Class<?> iClass) {
        checkAnnotatedElement(iClass, iClass);
        for (Method method : iClass.getMethods()) {
            checkAnnotatedElement(iClass, method);
        }
    }

    private static void checkAnnotatedElement(Class<?> iClass, AnnotatedElement annotatedElement) {
        ClientHeaderParam[] clientHeaderParams = annotatedElement.getAnnotationsByType(ClientHeaderParam.class);
        ArrayList<String> names = new ArrayList<>();
        for (ClientHeaderParam clientHeaderParam : clientHeaderParams) {
            String headerName = clientHeaderParam.name();
            if (names.contains(headerName)) {
                throw new RestClientDefinitionException("Header name cannot be registered more then once on the same target."
                                                                + "See " + iClass.getName());
            }
            names.add(headerName);
            String[] value = clientHeaderParam.value();
            List<String> computeMethodNames = parseParameters(Arrays.toString(clientHeaderParam.value()));
            /*if more than one string is specified as the value attribute, and one of the strings is a
              compute method (surrounded by curly braces), then the implementation will throw a
              RestClientDefinitionException*/
            if (value.length > 1 && computeMethodNames.size() > 0) {
                throw new RestClientDefinitionException("@ClientHeaderParam annotation should not contain compute method "
                                                                + "when multiple values are present in value attribute. "
                                                                + "See " + iClass.getName());
            }
            if (computeMethodNames.size() == 1) {
                String methodName = computeMethodNames.get(0);
                if (getAnnotationComputeMethod(iClass, methodName).size() != 1) {
                    throw new RestClientDefinitionException("No valid compute method found for name: " + methodName);
                }
            }
        }
    }

    private static List<Method> getAnnotationComputeMethod(Class<?> iClass, String methodName) {
        if (methodName.contains(".")) {
            return getStaticComputeMethod(methodName);
        }
        return getComputeMethod(iClass, methodName);
    }

    private static List<Method> getStaticComputeMethod(String methodName) {
        int lastIndex = methodName.lastIndexOf(".");
        String className = methodName.substring(0, lastIndex);
        String staticMethodName = methodName.substring(lastIndex + 1);
        try {
            Class<?> classWithStaticMethod = Class.forName(className);
            return getComputeMethod(classWithStaticMethod, staticMethodName);
        } catch (ClassNotFoundException e) {
            throw new RestClientDefinitionException("Class which should contain compute method does not exist: " + className);
        }
    }

    private static List<Method> getComputeMethod(Class<?> iClass, String methodName) {
        return Arrays.stream(iClass.getMethods())
                // filter out methods with specified name only
                .filter(method -> method.getName().equals(methodName))
                // filter out other methods than default and static
                .filter(method -> method.isDefault() || Modifier.isStatic(method.getModifiers()))
                // filter out methods without required return type
                .filter(method -> method.getReturnType().equals(String.class)
                        || method.getReturnType().equals(String[].class))
                // filter out methods without required parameter types
                .filter(method -> method.getParameterTypes().length == 0 || (
                        method.getParameterTypes().length == 1
                                && method.getParameterTypes()[0].equals(String.class)))
                .collect(Collectors.toList());
    }

    static List<Class<?>> getHttpAnnotations(AnnotatedElement annotatedElement) {
        return Arrays.stream(annotatedElement.getDeclaredAnnotations())
                .filter(annotation -> annotation.annotationType().getAnnotation(HttpMethod.class) != null)
                .map(Annotation::annotationType)
                .collect(Collectors.toList());
    }

    static MultivaluedMap<String, Object> parseHeaders(Class<?> iClass, Method method, Object[] args) throws Throwable {
        MultivaluedMap<String, Object> clientHeaders = new MultivaluedHashMap<>();
        clientHeaders.putAll(parseElementHeaders(iClass, iClass));
        clientHeaders.putAll(parseElementHeaders(iClass, method));
        clientHeaders.putAll(parseHeadersFromMethodParameters(method, args));
        return clientHeaders;
    }

    private static <T> MultivaluedMap<String, Object> parseElementHeaders(Class<T> iClass, AnnotatedElement annotatedElement)
            throws Throwable {
        MultivaluedMap<String, Object> headers = new MultivaluedHashMap<>();
        ClientHeaderParam[] clientHeaderParams = annotatedElement.getAnnotationsByType(ClientHeaderParam.class);
        for (ClientHeaderParam clientHeaderParam : clientHeaderParams) {
            String headerName = clientHeaderParam.name();
            String[] value = clientHeaderParam.value();
            List<String> computeMethodNames = parseParameters(Arrays.toString(clientHeaderParam.value()));
            try {
                if (computeMethodNames.size() == 1) {
                    String methodName = computeMethodNames.get(0);
                    Method method = getAnnotationComputeMethod(iClass, methodName).get(0);
                    if (methodName.contains(".")) {
                        //method is static
                        if (method.getParameterTypes().length != 0) {
                            headers.put(headerName, createList(method.invoke(null, headerName)));
                        } else {
                            headers.put(headerName, createList(method.invoke(null, null)));
                        }
                    } else {
                        //method is interface default
                        //we need to create instance of the interface to be able to call default method
                        T instance = (T) Proxy.newProxyInstance(
                                Thread.currentThread().getContextClassLoader(),
                                new Class[] {iClass},
                                (proxy, m, args) -> {
                                    Constructor<MethodHandles.Lookup> constructor = MethodHandles.Lookup.class
                                            .getDeclaredConstructor(Class.class);
                                    constructor.setAccessible(true);
                                    return constructor.newInstance(iClass)
                                            .in(iClass)
                                            .unreflectSpecial(m, iClass)
                                            .bindTo(proxy)
                                            .invokeWithArguments(args);
                                });
                        if (method.getParameterTypes().length != 0) {
                            headers.put(headerName, createList(method.invoke(instance, headerName)));
                        } else {
                            headers.put(headerName, createList(method.invoke(instance)));
                        }
                    }
                } else {
                    headers.put(headerName, Arrays.asList(value));
                }
            } catch (IllegalAccessException e) {
                //TODO what kind of exception to throw?
                e.printStackTrace();
            } catch (InvocationTargetException e) {
                if (clientHeaderParam.required()) {
                    throw e.getCause();
                }
            }
        }
        return headers;
    }

    private static MultivaluedMap<String, Object> parseHeadersFromMethodParameters(Method method, Object[] args) {
        MultivaluedMap<String, Object> headers = new MultivaluedHashMap<>();
        Parameter[] parameters = method.getParameters();
        for (int i = 0; i < parameters.length; i++) {
            Parameter parameter = parameters[i];
            HeaderParam headerParam = parameter.getAnnotation(HeaderParam.class);
            if (headerParam != null) {
                headers.addAll(headerParam.value(), Arrays.asList(args[i]));
            }
        }
        return headers;
    }

    private static List<Object> createList(Object value) {
        if (value instanceof String[]) {
            String[] array = (String[]) value;
            return Arrays.asList(array);
        }
        return CollectionsHelper.listOf(value);
    }
}
