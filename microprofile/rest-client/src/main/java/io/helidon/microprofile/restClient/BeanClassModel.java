package io.helidon.microprofile.restClient;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
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
    private final List<ParamModel> parameterModels;

    public BeanClassModel(Builder builder) {
        this.beanClass = builder.beanClass;
        this.parameterModels = builder.parameterModels;
    }

    public static BeanClassModel fromClass(InterfaceModel interfaceModel, Class<?> beanClass) {
        return new Builder(interfaceModel, beanClass)
                .processPathFields()
                .processHeaderFields()
                .processCookieFields()
                .processQueryFields()
                .build();
    }

    public WebTarget resolvePath(WebTarget webTarget, Object instance) {
        AtomicReference<WebTarget> toReturn = new AtomicReference<>(webTarget);
        parameterModels.stream()
                .filter(paramModel -> paramModel.handles(PathParam.class))
                .forEach(parameterModel -> {
                    Field field = (Field) parameterModel.getAnnotatedElement();
                    toReturn.set((WebTarget) parameterModel.handleParameter(webTarget,
                                                                            PathParam.class,
                                                                            resolveValueFromField(field, instance)));
                });
        return toReturn.get();
    }

    public MultivaluedMap<String, Object> resolveHeaders(MultivaluedMap<String, Object> headers,
                                                         Object instance) {
        parameterModels.stream()
                .filter(paramModel -> paramModel.handles(HeaderParam.class))
                .forEach(parameterModel -> {
                    Field field = (Field) parameterModel.getAnnotatedElement();
                    parameterModel.handleParameter(headers,
                                                   HeaderParam.class,
                                                   resolveValueFromField(field, instance));
                });
        return headers;
    }

    public Map<String, String> resolveCookies(Map<String, String> cookies,
                                              Object instance) {
        parameterModels.stream()
                .filter(paramModel -> paramModel.handles(CookieParam.class))
                .forEach(parameterModel -> {
                    Field field = (Field) parameterModel.getAnnotatedElement();
                    parameterModel.handleParameter(cookies,
                                                   CookieParam.class,
                                                   resolveValueFromField(field, instance));
                });
        return cookies;
    }

    public Map<String, Object[]> resolveQuery(Map<String, Object[]> query,
                                              Object instance) {
        parameterModels.stream()
                .filter(paramModel -> paramModel.handles(QueryParam.class))
                .forEach(parameterModel -> {
                    Field field = (Field) parameterModel.getAnnotatedElement();
                    parameterModel.handleParameter(query,
                                                   QueryParam.class,
                                                   resolveValueFromField(field, instance));
                });
        return query;
    }

    private Object resolveValueFromField(Field field, Object instance) {
        try {
            Object toReturn;
            field.setAccessible(true);
            toReturn = field.get(instance);
            field.setAccessible(false);
            return toReturn;
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }

    private static class Builder implements io.helidon.common.Builder<BeanClassModel> {

        private final InterfaceModel interfaceModel;
        private final Class<?> beanClass;
        private ArrayList<ParamModel> parameterModels = new ArrayList<>();

        private Builder(InterfaceModel interfaceModel, Class<?> beanClass) {
            this.interfaceModel = interfaceModel;
            this.beanClass = beanClass;
        }

        /**
         * Parses all {@link PathParam} annotated fields from bean class.
         *
         * @return updated builder instance
         */
        public Builder processPathFields() {
            Stream.of(beanClass.getDeclaredFields())
                    .filter(field -> field.isAnnotationPresent(PathParam.class))
                    .forEach(field -> parameterModels.add(ParamModel.from(interfaceModel, field.getType(), field, -1)));
            return this;
        }

        /**
         * Parses all {@link HeaderParam} annotated fields from bean class.
         *
         * @return updated builder instance
         */
        public Builder processHeaderFields() {
            Stream.of(beanClass.getDeclaredFields())
                    .filter(field -> field.isAnnotationPresent(HeaderParam.class))
                    .forEach(field -> parameterModels.add(ParamModel.from(interfaceModel, field.getType(), field, -1)));
            return this;
        }

        /**
         * Parses all {@link CookieParam} annotated fields from bean class.
         *
         * @return updated builder instance
         */
        public Builder processCookieFields() {
            Stream.of(beanClass.getDeclaredFields())
                    .filter(field -> field.isAnnotationPresent(CookieParam.class))
                    .forEach(field -> parameterModels.add(ParamModel.from(interfaceModel, field.getType(), field, -1)));
            return this;
        }

        /**
         * Parses all {@link QueryParam} annotated fields from bean class.
         *
         * @return updated builder instance
         */
        public Builder processQueryFields() {
            Stream.of(beanClass.getDeclaredFields())
                    .filter(field -> field.isAnnotationPresent(QueryParam.class))
                    .forEach(field -> parameterModels.add(ParamModel.from(interfaceModel, field.getType(), field, -1)));
            return this;
        }

        @Override
        public BeanClassModel build() {
            return new BeanClassModel(this);
        }
    }

}
