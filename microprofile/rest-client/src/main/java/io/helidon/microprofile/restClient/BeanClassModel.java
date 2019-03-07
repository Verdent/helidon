package io.helidon.microprofile.restClient;

import java.lang.annotation.Annotation;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.ws.rs.CookieParam;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.PathParam;
import javax.ws.rs.QueryParam;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MultivaluedMap;

/**
 * Created by David Kral.
 */
public class BeanClassModel {

    private final Class<?> beanClass;
    private final Map<String, Field> pathFields;
    private final Map<String, Field> headerFields;
    private final Map<String, Field> cookieFields;
    private final Map<String, Field> queryFields;

    public BeanClassModel(Builder builder) {
        this.beanClass = builder.beanClass;
        this.pathFields = builder.pathFields;
        this.headerFields = builder.headerFields;
        this.cookieFields = builder.cookieFields;
        this.queryFields = builder.queryFields;
    }

    public static BeanClassModel fromClass(Class<?> beanClass) {
        return new Builder(beanClass)
                .processPathFields()
                .processHeaderFields()
                .processCookieFields()
                .processQueryFields()
                .build();
    }


    public WebTarget resolvePath(InterfaceModel interfaceModel, WebTarget webTarget, Object instance)
            throws IllegalAccessException {
        WebTarget toReturn = webTarget;
        for (Map.Entry<String, Field> entry : pathFields.entrySet()) {
            Field field = entry.getValue();
            field.setAccessible(true);
            Object resolvedValue = interfaceModel.resolveParamValue(field.get(instance),
                                                                    field.getType(),
                                                                    field.getAnnotations());
            toReturn = webTarget.resolveTemplate(entry.getKey(), resolvedValue);
            field.setAccessible(false);
        }
        return toReturn;
    }

    public MultivaluedMap<String, Object> resolveHeaders(InterfaceModel interfaceModel,
                                                         MultivaluedMap<String, Object> headers,
                                                         Object instance) throws IllegalAccessException {
        MultivaluedMap<String, Object> toReturn = headers;
        for (Map.Entry<String, Field> entry : headerFields.entrySet()) {
            Field field = entry.getValue();
            field.setAccessible(true);
            Object resolvedValue = interfaceModel.resolveParamValue(field.get(instance),
                                                                    field.getType(),
                                                                    field.getAnnotations());
            toReturn.add(entry.getKey(), resolvedValue);
            field.setAccessible(false);
        }
        return toReturn;
    }

    public Map<String, String> resolveCookies(InterfaceModel interfaceModel,
                                                         Map<String, String> cookies,
                                                         Object instance) throws IllegalAccessException {
        Map<String, String> toReturn = cookies;
        for (Map.Entry<String, Field> entry : cookieFields.entrySet()) {
            Field field = entry.getValue();
            field.setAccessible(true);
            Object resolvedValue = interfaceModel.resolveParamValue(field.get(instance),
                                                                    field.getType(),
                                                                    field.getAnnotations());
            toReturn.put(entry.getKey(), (String) resolvedValue);
            field.setAccessible(false);
        }
        return toReturn;
    }

    public Map<String, Object[]> resolveQuery(InterfaceModel interfaceModel,
                                              Map<String, Object[]> query,
                                              Object instance) throws IllegalAccessException {
        Map<String, Object[]> toReturn = query;
        for (Map.Entry<String, Field> entry : queryFields.entrySet()) {
            Field field = entry.getValue();
            field.setAccessible(true);
            Object resolvedValue = interfaceModel.resolveParamValue(field.get(instance),
                                                                    field.getType(),
                                                                    field.getAnnotations());
            if (resolvedValue instanceof Object[]) {
                toReturn.put(entry.getKey(), (Object[]) resolvedValue);
            } else {
                toReturn.put(entry.getKey(), new Object[] {resolvedValue});
            }
            field.setAccessible(false);
        }
        return toReturn;
    }


    private static class Builder implements io.helidon.common.Builder<BeanClassModel> {

        private final Class<?> beanClass;
        private Map<String, Field> pathFields = new HashMap<>();
        private Map<String, Field> headerFields = new HashMap<>();
        private Map<String, Field> cookieFields = new HashMap<>();
        private Map<String, Field> queryFields = new HashMap<>();

        private Builder(Class<?> beanClass) {
            this.beanClass = beanClass;
        }

        /**
         * Parses all {@link PathParam} annotated fields from bean class.
         *
         * @return updated builder instance
         */
        public Builder processPathFields() {
            pathFields = Stream.of(beanClass.getDeclaredFields())
                    .filter(field -> field.isAnnotationPresent(PathParam.class))
                    .collect(Collectors.toMap(field -> field.getAnnotation(PathParam.class).value(), Function.identity()));
            return this;
        }

        /**
         * Parses all {@link HeaderParam} annotated fields from bean class.
         *
         * @return updated builder instance
         */
        public Builder processHeaderFields() {
            headerFields = Stream.of(beanClass.getDeclaredFields())
                    .filter(field -> field.isAnnotationPresent(HeaderParam.class))
                    .collect(Collectors.toMap(field -> field.getAnnotation(HeaderParam.class).value(), Function.identity()));
            return this;
        }

        /**
         * Parses all {@link CookieParam} annotated fields from bean class.
         *
         * @return updated builder instance
         */
        public Builder processCookieFields() {
            cookieFields = Stream.of(beanClass.getDeclaredFields())
                    .filter(field -> field.isAnnotationPresent(CookieParam.class))
                    .collect(Collectors.toMap(field -> field.getAnnotation(CookieParam.class).value(), Function.identity()));
            return this;
        }

        /**
         * Parses all {@link QueryParam} annotated fields from bean class.
         *
         * @return updated builder instance
         */
        public Builder processQueryFields() {
            queryFields = Stream.of(beanClass.getDeclaredFields())
                    .filter(field -> field.isAnnotationPresent(QueryParam.class))
                    .collect(Collectors.toMap(field -> field.getAnnotation(QueryParam.class).value(), Function.identity()));
            return this;
        }

        @Override
        public BeanClassModel build() {
            return new BeanClassModel(this);
        }
    }



}
