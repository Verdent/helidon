package io.helidon.microprofile.restClient;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;

import javax.ws.rs.Path;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 * Created by David Kral.
 */
public class ProxyInvocationHandler implements InvocationHandler {

    private WebTarget target;

    public ProxyInvocationHandler(WebTarget target) {
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
        Invocation.Builder invocationBuilder = methodWebTarget.request(MediaType.TEXT_PLAIN);
        Response response = invocationBuilder.get();

        return 42;
    }

}
