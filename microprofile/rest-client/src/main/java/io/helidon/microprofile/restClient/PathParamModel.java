package io.helidon.microprofile.restClient;

import javax.ws.rs.client.WebTarget;

/**
 * @author David Kral
 */
class PathParamModel extends ParameterModel<WebTarget> {

    private final String pathParamName;

    PathParamModel(Builder builder) {
        super(builder);
        pathParamName = builder.pathParamName;
    }

    public String getPathParamName() {
        return pathParamName;
    }

    @Override
    public WebTarget handleParameter(WebTarget requestPart, Object[] args) {
        Object resolvedValue = classModel.resolveParamValue(args[getParamPosition()], getParameter());
        return requestPart.resolveTemplate(pathParamName, resolvedValue);
    }


}
