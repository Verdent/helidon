package io.helidon.microprofile.restClient;

import java.lang.annotation.Annotation;
import java.util.Map;

import javax.ws.rs.QueryParam;

/**
 * @author David Kral
 */
class QueryParamModel extends ParamModel<Map<String, Object[]>> {

    private final String queryParamName;

    QueryParamModel(Builder builder) {
        super(builder);
        queryParamName = builder.queryParamName();
    }

    public String getQueryParamName() {
        return queryParamName;
    }

    @Override
    public Map<String, Object[]> handleParameter(Map<String, Object[]> requestPart,
                                                 Class<?> annotationClass,
                                                 Object instance) {
        Object resolvedValue = interfaceModel.resolveParamValue(instance,
                                                                getType(),
                                                                getAnnotatedElement().getAnnotations());
        if (resolvedValue instanceof Object[]) {
            requestPart.put(queryParamName, (Object[]) resolvedValue);
        } else {
            requestPart.put(queryParamName, new Object[] {resolvedValue});
        }
        return requestPart;
    }

    @Override
    public boolean handles(Class<Annotation> annotation) {
        return QueryParam.class.equals(annotation);
    }

}
