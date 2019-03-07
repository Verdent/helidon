package io.helidon.microprofile.restClient;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

import javax.ws.rs.client.WebTarget;

/**
 * Created by David Kral.
 */
public class RestClientModel {

    private final InterfaceModel classModel;
    private final Map<Method, MethodModel> methodModels;

    private RestClientModel(Builder builder) {
        this.classModel = builder.classModel;
        this.methodModels = builder.methodModels;
    }

    public InterfaceModel getClassModel() {
        return classModel;
    }

    public Object invokeMethod(WebTarget baseWebTarget, Method method, Object[] args) throws Throwable {
        WebTarget classLevelTarget = baseWebTarget.path(classModel.getPath());
        MethodModel methodModel = methodModels.get(method);
        return methodModel.invokeMethod(classLevelTarget, method, args);
    }

    public static RestClientModel from(Class<?> restClientClass) {
        InterfaceModel classModel = InterfaceModel.from(restClientClass);
        return new Builder()
                .classModel(classModel)
                .methodModels(parseMethodModels(classModel))
                .build();
    }

    private static Map<Method, MethodModel> parseMethodModels(InterfaceModel classModel) {
        Map<Method, MethodModel> methodMap = new HashMap<>();
        for (Method method : classModel.getRestClientClass().getMethods()) {
            if (InterfaceUtil.getHttpAnnotations(method).size() > 0) {
                //Skip method processing if method does not have HTTP annotation
                methodMap.put(method, MethodModel.from(classModel, method));
            }
        }
        return methodMap;
    }

    private static class Builder implements io.helidon.common.Builder<RestClientModel> {

        private InterfaceModel classModel;
        private Map<Method, MethodModel> methodModels;

        private Builder() {
        }

        /**
         * Rest client class converted to {@link InterfaceModel}
         *
         * @param classModel {@link InterfaceModel} instance
         * @return Updated Builder instance
         */
        public Builder classModel(InterfaceModel classModel) {
            this.classModel = classModel;
            return this;
        }

        /**
         * Rest client class methods converted to {@link Map} of {@link MethodModel}
         *
         * @param methodModels Method models
         * @return Updated Builder instance
         */
        public Builder methodModels(Map<Method, MethodModel> methodModels) {
            this.methodModels = methodModels;
            return this;
        }

        @Override
        public RestClientModel build() {
            return new RestClientModel(this);
        }
    }
}
