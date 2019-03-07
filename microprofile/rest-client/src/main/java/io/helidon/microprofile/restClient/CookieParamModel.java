package io.helidon.microprofile.restClient;

import java.lang.annotation.Annotation;
import java.util.Map;

import javax.ws.rs.CookieParam;

/**
 * @author David Kral
 */
class CookieParamModel extends ParamModel<Map<String, String>> {

    private final String cookieParamName;

    CookieParamModel(Builder builder) {
        super(builder);
        cookieParamName = builder.cookieParamName();
    }

    @Override
    public Map<String, String> handleParameter(Map<String, String> requestPart, Class<?> annotationClass, Object[] args) {
        requestPart.put(cookieParamName, (String) args[getParamPosition()]);
        return requestPart;
    }

    @Override
    public boolean handles(Class<Annotation> annotation) {
        return CookieParam.class.equals(annotation);
    }

    public String getCookieParamName() {
        return cookieParamName;
    }

}
