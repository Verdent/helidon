package io.helidon.microprofile.restClient;

import java.lang.annotation.Annotation;

import javax.ws.rs.PathParam;
import javax.ws.rs.client.WebTarget;

/**
 * @author David Kral
 */
class PathParamModel extends ParamModel<WebTarget> {

    private final String pathParamName;

    PathParamModel(Builder builder) {
        super(builder);
        pathParamName = builder.pathParamName();
    }

    public String getPathParamName() {
        return pathParamName;
    }

    @Override
    public WebTarget handleParameter(WebTarget requestPart, Class<?> annotationClass, Object[] args) {
        Object resolvedValue = interfaceModel.resolveParamValue(args[getParamPosition()],
                                                                getParameter().getType(),
                                                                getParameter().getAnnotations());
        return requestPart.resolveTemplate(pathParamName, resolvedValue);
    }

    @Override
    public boolean handles(Class<Annotation> annotation) {
        return PathParam.class.equals(annotation);
    }

}
