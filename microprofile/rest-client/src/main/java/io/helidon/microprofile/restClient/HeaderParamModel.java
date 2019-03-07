package io.helidon.microprofile.restClient;

import javax.ws.rs.HeaderParam;
import javax.ws.rs.core.MultivaluedMap;

import java.lang.annotation.Annotation;
import java.util.Collections;

/**
 * @author David Kral
 */
class HeaderParamModel extends ParamModel<MultivaluedMap<String, Object>> {

    private String headerParamName;

    protected HeaderParamModel(Builder builder) {
        super(builder);
        this.headerParamName = builder.headerParamName();
    }

    @Override
    public MultivaluedMap<String, Object> handleParameter(MultivaluedMap<String, Object> requestPart,
                                                          Class<?> annotationClass, Object instance) {
        Object resolvedValue = interfaceModel.resolveParamValue(instance,
                                                                getType(),
                                                                getAnnotatedElement().getAnnotations());
        requestPart.put(headerParamName, Collections.singletonList(resolvedValue));
        return requestPart;
    }

    @Override
    public boolean handles(Class<Annotation> annotation) {
        return HeaderParam.class.equals(annotation);
    }
}
