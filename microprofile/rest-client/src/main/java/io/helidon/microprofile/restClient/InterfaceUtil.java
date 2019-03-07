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


    public static List<String> parseParameters(String template) {
        List<String> allMatches = new ArrayList<>();
        Matcher m = PATTERN.matcher(template);
        while (m.find()) {
            allMatches.add(m.group());
        }
        return allMatches;
    }

    static Method parseComputeMethod(Class<?> iClass, String[] headerValue) {
        List<String> computeMethodNames = InterfaceUtil.parseParameters(Arrays.toString(headerValue));
        /*if more than one string is specified as the value attribute, and one of the strings is a
          compute method (surrounded by curly braces), then the implementation will throw a
          RestClientDefinitionException*/
        if (headerValue.length > 1 && computeMethodNames.size() > 0) {
            throw new RestClientDefinitionException("@ClientHeaderParam annotation should not contain compute method "
                                                            + "when multiple values are present in value attribute. "
                                                            + "See " + iClass.getName());
        }
        if (computeMethodNames.size() == 1) {
            String methodName = computeMethodNames.get(0);
            List<Method> computeMethods = getAnnotationComputeMethod(iClass, methodName);
            if (computeMethods.size() != 1) {
                throw new RestClientDefinitionException("No valid compute method found for name: " + methodName);
            }
            return computeMethods.get(0);
        }
        return null;
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
}
