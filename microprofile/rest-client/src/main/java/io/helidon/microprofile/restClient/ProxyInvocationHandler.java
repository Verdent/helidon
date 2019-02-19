package io.helidon.microprofile.restClient;

import java.lang.annotation.Annotation;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.util.List;

import javax.ws.rs.Path;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 * Created by David Kral.
 */
public class ProxyInvocationHandler implements InvocationHandler {

    private static final String INVOKED_METHOD = "org.eclipse.microprofile.rest.client.invokedMethod";

    private final Client client;
    private final WebTarget target;

    public ProxyInvocationHandler(Client client, WebTarget target) {
        this.client = client;
        this.target = target;
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        WebTarget methodWebTarget;
        Path p = method.getAnnotation(Path.class);
        if (p != null) {
            methodWebTarget = target.path(p.value());
        } else {
            methodWebTarget = target;
        }
        List<Class<?>> httpMethod = InterfaceUtil.getHttpAnnotations(method);
        //client.property(INVOKED_METHOD, method);
        return methodWebTarget
                .request(MediaType.TEXT_PLAIN)
                .method(httpMethod.get(0).getSimpleName(), method.getReturnType());
    }

}
