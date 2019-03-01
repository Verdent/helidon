package io.helidon.microprofile.restClient;

import java.lang.reflect.Parameter;
import java.util.Optional;

import javax.ws.rs.PathParam;

/**
 * Created by David Kral.
 */
public class ParameterModel {

    private final Parameter parameter;
    private final String pathParamName;
    //private final String headerName;
    private final int paramPosition;
    private final boolean entity;

    private ParameterModel(Builder builder) {
        this.parameter = builder.parameter;
        this.pathParamName = builder.pathParamName;
        this.entity = builder.entity;
        this.paramPosition = builder.paramPosition;
    }

    public Parameter getParameter() {
        return parameter;
    }

    public Optional<String> getPathParamName() {
        return Optional.ofNullable(pathParamName);
    }

    public int getParamPosition() {
        return paramPosition;
    }

    public boolean isEntity() {
        return entity;
    }

    static ParameterModel from(Parameter parameter, int position) {
        return new Builder(parameter)
                .pathParamName(parameter.getAnnotation(PathParam.class))
                .paramPosition(position)
                .build();
    }

    private static class Builder implements io.helidon.common.Builder<ParameterModel> {

        private Parameter parameter;
        private String pathParamName;
        private boolean entity;
        private int paramPosition;

        private Builder(Parameter parameter) {
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
            return new ParameterModel(this);
        }
    }

}
