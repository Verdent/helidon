package io.helidon.microprofile.restClient;

import java.lang.reflect.Parameter;
import java.util.Optional;

import javax.ws.rs.HeaderParam;
import javax.ws.rs.PathParam;
import javax.ws.rs.client.Invocation;

/**
 * Created by David Kral.
 */
public abstract class ParameterModel<T> {

    protected final ClassModel classModel;
    private final Parameter parameter;
    private final int paramPosition;
    private final boolean entity;

    protected ParameterModel(Builder builder) {
        this.classModel = builder.classModel;
        this.parameter = builder.parameter;
        this.entity = builder.entity;
        this.paramPosition = builder.paramPosition;
    }

    public Parameter getParameter() {
        return parameter;
    }

    public int getParamPosition() {
        return paramPosition;
    }

    public boolean isEntity() {
        return entity;
    }

    public abstract T handleParameter(T requestPart, Object[] args);

    static ParameterModel from(ClassModel classModel, Parameter parameter, int position) {
        return new Builder(classModel, parameter)
                .pathParamName(parameter.getAnnotation(PathParam.class))
                .headerParamName(parameter.getAnnotation(HeaderParam.class))
                .paramPosition(position)
                .build();
    }

    protected static class Builder implements io.helidon.common.Builder<ParameterModel> {

        private ClassModel classModel;
        private Parameter parameter;
        protected String pathParamName;
        protected String headerParamName;
        private boolean entity;
        private int paramPosition;

        private Builder(ClassModel classModel, Parameter parameter) {
            this.classModel = classModel;
            this.parameter = parameter;
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
         * Position of parameter in method parameters
         *
         * @param paramPosition Parameter position
         * @return updated Builder instance
         */
        public Builder paramPosition(int paramPosition) {
            this.paramPosition = paramPosition;
            return this;
        }

        @Override
        public ParameterModel build() {
            entity = pathParamName == null;
            if (pathParamName != null) {
                return new PathParamModel(this);
            } else if (headerParamName != null) {
                return new HeaderParamModel(this);
            }
            return new ParameterModel(this) {
                @Override
                public Object handleParameter(Object requestPart, Object[] args) {
                    return null;
                }
            };
        }
    }

}
