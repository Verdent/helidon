package io.helidon.microprofile.restClient;

import org.eclipse.microprofile.rest.client.RestClientDefinitionException;
import org.eclipse.microprofile.rest.client.annotation.ClientHeaderParam;

import javax.ws.rs.HttpMethod;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.core.UriBuilder;

import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedElement;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.Parameter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

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
            UriBuilder uriBuilder = null;
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
                        throw new RestClientDefinitionException("Parameter name " + pathParamAnnotation.value()
                                                                        + " on " + iClass.getName() + "::" + method
                                .getName() + " doesn't match any @Path variable name.");
                    }
                    parameters.remove(pathParamAnnotation.value());
                }
            }
            if (!parameters.isEmpty()) {
                throw new RestClientDefinitionException("Some variable names does not have matching @PathParam " +
                                                                "defined on method " + iClass.getName() + "::" + method
                        .getName());
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
                throw new RestClientDefinitionException("ClientHeaderParam annotation should not contain compute method "
                                                                + "when multiple values are present in value attribute. "
                                                                + "See " + iClass.getName());
            }
            if (computeMethodNames.size() == 1) {
                String methodName = computeMethodNames.get(0);
                if (!checkComputationMethodValidity(iClass, methodName)) {
                    throw new RestClientDefinitionException("No valid compute method found for name: " + methodName);
                }
            }
        }
    }

    private static boolean checkComputationMethodValidity(Class<?> iClass, String methodName) {
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
                .collect(Collectors.toList()).size() == 1;
    }

    public static List<Class<?>> getHttpAnnotations(AnnotatedElement annotatedElement) {
        return Arrays.stream(annotatedElement.getDeclaredAnnotations())
                .filter(annotation -> annotation.annotationType().getAnnotation(HttpMethod.class) != null)
                .map(Annotation::annotationType)
                .collect(Collectors.toList());
    }

}
