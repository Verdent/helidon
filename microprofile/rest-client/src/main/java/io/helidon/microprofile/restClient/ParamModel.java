package io.helidon.microprofile.restClient;

import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedElement;
import java.lang.reflect.Parameter;
import java.lang.reflect.Type;
import java.util.Objects;

import javax.ws.rs.BeanParam;
import javax.ws.rs.CookieParam;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.PathParam;
import javax.ws.rs.QueryParam;

/**
 * Created by David Kral.
 */
public abstract class ParamModel<T> {

    protected final InterfaceModel interfaceModel;
    private final Type type;
    private final AnnotatedElement annotatedElement;
    private final int paramPosition;
    private final boolean entity;
    private final boolean methodParam;

    protected ParamModel(Builder builder) {
        this.interfaceModel = builder.interfaceModel;
        this.type = builder.type;
        this.annotatedElement = builder.annotatedElement;
        this.entity = builder.entity;
        this.paramPosition = builder.paramPosition;
        this.methodParam = builder.methodParam;
    }

    public Type getType() {
        return type;
    }

    public AnnotatedElement getAnnotatedElement() {
        return annotatedElement;
    }

    public int getParamPosition() {
        return paramPosition;
    }

    public boolean isEntity() {
        return entity;
    }

    public boolean isMethodParam() {
        return methodParam;
    }

    public abstract T handleParameter(T requestPart, Class<?> annotationClass, Object[] args) throws IllegalAccessException;

    public abstract boolean handles(Class<Annotation> annotation);

    static ParamModel from(InterfaceModel classModel, Type type, AnnotatedElement annotatedElement, int position) {
        return new Builder(classModel, type, annotatedElement)
                .pathParamName(annotatedElement.getAnnotation(PathParam.class))
                .headerParamName(annotatedElement.getAnnotation(HeaderParam.class))
                .beanParam(annotatedElement.getAnnotation(BeanParam.class))
                .cookieParam(annotatedElement.getAnnotation(CookieParam.class))
                .queryParam(annotatedElement.getAnnotation(QueryParam.class))
                .paramPosition(position)
                .build();
    }

    protected static class Builder implements io.helidon.common.Builder<ParamModel> {

        private InterfaceModel interfaceModel;
        private Type type;
        private AnnotatedElement annotatedElement;
        private String pathParamName;
        private String headerParamName;
        private String cookieParamName;
        private String queryParamName;
        private boolean beanParam;
        private boolean entity;
        private boolean methodParam;
        private int paramPosition;

        private Builder(InterfaceModel interfaceModel, Type type, AnnotatedElement annotatedElement) {
            this.interfaceModel = interfaceModel;
            this.type = type;
            this.annotatedElement = annotatedElement;
            this.methodParam = annotatedElement instanceof Parameter;
        }

        /**
         * Path parameter name.
         *
         * @param pathParam {@link PathParam} annotation
         * @return updated Builder instance
         */
        public Builder pathParamName(PathParam pathParam) {
            this.pathParamName = pathParam == null ? null : pathParam.value();
            return this;
        }

        /**
         * Header parameter name.
         *
         * @param headerParam {@link HeaderParam} annotation
         * @return updated Builder instance
         */
        public Builder headerParamName(HeaderParam headerParam) {
            this.headerParamName = headerParam == null ? null : headerParam.value();
            return this;
        }

        /**
         * Bean parameter identifier.
         *
         * @param beanParam {@link BeanParam} annotation
         * @return updated Builder instance
         */
        public Builder beanParam(BeanParam beanParam) {
            this.beanParam = beanParam != null;
            return this;
        }

        /**
         * Cookie parameter.
         *
         * @param cookieParam {@link CookieParam} annotation
         * @return updated Builder instance
         */
        public Builder cookieParam(CookieParam cookieParam) {
            this.cookieParamName = cookieParam == null ? null : cookieParam.value();
            return this;
        }

        /**
         * Query parameter.
         *
         * @param queryParam {@link QueryParam} annotation
         * @return updated Builder instance
         */
        public Builder queryParam(QueryParam queryParam) {
            this.queryParamName = queryParam == null ? null : queryParam.value();
            return this;
        }

        /**
         * Position of parameter in method parameters
         *
         * @param paramPosition Parameter position
         * @return updated Builder instance
         */
        public Builder paramPosition(int paramPosition) {
            this.paramPosition = paramPosition;
            return this;
        }

        public String pathParamName() {
            return pathParamName;
        }

        public String headerParamName() {
            return headerParamName;
        }

        public String cookieParamName() {
            return cookieParamName;
        }

        public String queryParamName() {
            return queryParamName;
        }

        @Override
        public ParamModel build() {
            if (pathParamName != null) {
                return new PathParamModel(this);
            } else if (headerParamName != null) {
                return new HeaderParamModel(this);
            } else if (beanParam) {
                return new BeanParamModel(this);
            } else if (cookieParamName != null) {
                return new CookieParamModel(this);
            } else if (cookieParamName != null) {
                return new CookieParamModel(this);
            }
            entity = true;
            return new ParamModel(this) {
                @Override
                public Object handleParameter(Object requestPart, Class annotationClass, Object[] args) {
                    return requestPart;
                }

                @Override
                public boolean handles(Class annotation) {
                    return false;
                }
            };
        }
    }

}
