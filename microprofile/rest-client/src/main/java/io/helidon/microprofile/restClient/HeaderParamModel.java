package io.helidon.microprofile.restClient;

import javax.ws.rs.core.MultivaluedMap;
import java.util.Collections;

/**
 * @author David Kral
 */
class HeaderParamModel extends ParameterModel<MultivaluedMap<String, Object>> {

    private String headerParamName;

    protected HeaderParamModel(Builder builder) {
        super(builder);
        this.headerParamName = builder.headerParamName;
    }

    @Override
    public MultivaluedMap<String, Object> handleParameter(MultivaluedMap<String, Object> requestPart, Object[] args) {
        Object resolvedValue = classModel.resolveParamValue(args[getParamPosition()], getParameter());
        requestPart.put(headerParamName, Collections.singletonList(resolvedValue));
        return requestPart;
    }
}
