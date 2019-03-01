package io.helidon.microprofile.restClient;

import java.lang.reflect.Method;

import org.eclipse.microprofile.rest.client.annotation.ClientHeaderParam;

/**
 * Created by David Kral.
 */
public class ClientHeaderParamModel {

    private final String headerName;
    private final String[] headerValue;
    private final Method computeMethod;
    private final boolean required;

    ClientHeaderParamModel(Class<?> iClass, ClientHeaderParam clientHeaderParam) {
        headerName = clientHeaderParam.name();
        headerValue = clientHeaderParam.value();
        computeMethod = InterfaceUtil.parseComputeMethod(iClass, headerValue);
        required = clientHeaderParam.required();
    }

    public String getHeaderName() {
        return headerName;
    }

    public String[] getHeaderValue() {
        return headerValue;
    }

    public Method getComputeMethod() {
        return computeMethod;
    }

    public boolean isRequired() {
        return required;
    }
}
