package io.helidon.microprofile.restClient;

import java.lang.annotation.Annotation;
import java.util.Map;

import javax.ws.rs.CookieParam;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.PathParam;
import javax.ws.rs.QueryParam;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MultivaluedMap;

/**
 * @author David Kral
 */
class BeanParamModel extends ParamModel<Object> {

    private BeanClassModel beanClassModel;

    BeanParamModel(Builder builder) {
        super(builder);
        beanClassModel = BeanClassModel.fromClass(interfaceModel, (Class<?>) getType());
    }

    @Override
    public Object handleParameter(Object requestPart, Class<?> annotationClass, Object instance) {
        if (PathParam.class.equals(annotationClass)) {
            return beanClassModel.resolvePath((WebTarget) requestPart, instance);
        } else if (HeaderParam.class.equals(annotationClass)) {
            return beanClassModel.resolveHeaders((MultivaluedMap<String, Object>) requestPart, instance);
        } else if (CookieParam.class.equals(annotationClass)) {
            return beanClassModel.resolveCookies((Map<String, String>) requestPart, instance);
        } else if (QueryParam.class.equals(annotationClass)) {
            return beanClassModel.resolveQuery((Map<String, Object[]>) requestPart, instance);
        }
        return null;
    }

    @Override
    public boolean handles(Class<Annotation> annotation) {
        return PathParam.class.equals(annotation)
                || HeaderParam.class.equals(annotation)
                || CookieParam.class.equals(annotation)
                || QueryParam.class.equals(annotation);
    }

}
