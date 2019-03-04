package io.helidon.microprofile.restClient;

import javax.ws.rs.client.WebTarget;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;

/**
 * Created by David Kral.
 */
public class ProxyInvocationHandler implements InvocationHandler {

    private final WebTarget target;
    private final RestClientModel restClientModel;

    public ProxyInvocationHandler(WebTarget target,
                                  RestClientModel restClientModel) {
        this.target = target;
        this.restClientModel = restClientModel;
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        return restClientModel.invokeMethod(target, method, args);
    }

}
