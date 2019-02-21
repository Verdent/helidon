package io.helidon.microprofile.restClient;

import java.lang.reflect.Proxy;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Configuration;

import org.eclipse.microprofile.rest.client.RestClientBuilder;
import org.eclipse.microprofile.rest.client.RestClientDefinitionException;
import org.eclipse.microprofile.rest.client.annotation.RegisterProviders;
import org.glassfish.jersey.client.JerseyClientBuilder;

/**
 * Created by David Kral.
 */
public class HelidonRestClientBuilderImpl implements RestClientBuilder {

    private static final String CONFIG_DISABLE_DEFAULT_MAPPER = "microprofile.rest.client.disable.default.mapper";
    private static final String CONFIG_PROVIDERS = "/mp-rest/providers:";

    private URI uri;
    private JerseyClientBuilder jerseyClientBuilder;

    public HelidonRestClientBuilderImpl() {
        jerseyClientBuilder = new JerseyClientBuilder();
    }

    @Override
    public RestClientBuilder baseUrl(URL url) {
        try {
            this.uri = url.toURI();
            return this;
        } catch (URISyntaxException e) {
            throw new RuntimeException(e.getMessage());
        }
    }

    @Override
    public RestClientBuilder connectTimeout(long timeout, TimeUnit unit) {
        jerseyClientBuilder.connectTimeout(timeout, unit);
        return this;
    }

    @Override
    public RestClientBuilder readTimeout(long timeout, TimeUnit unit) {
        jerseyClientBuilder.readTimeout(timeout, unit);
        return this;
    }

    @Override
    public RestClientBuilder executorService(ExecutorService executor) {
        jerseyClientBuilder.executorService(executor);
        return this;
    }

    @Override
    public <T> T build(Class<T> clazz) throws IllegalStateException, RestClientDefinitionException {

        InterfaceUtil.validateInterface(clazz);

        RegisterProviders registerProviders = clazz.getAnnotation(RegisterProviders.class);
        if (registerProviders != null) {
            List<Object> providerClasses = new ArrayList<>(Arrays.asList(registerProviders.value()));
        }

        Object disableDefaultMapper = jerseyClientBuilder.getConfiguration().getProperty(CONFIG_DISABLE_DEFAULT_MAPPER);
        if (disableDefaultMapper == null || disableDefaultMapper.equals(Boolean.FALSE)) {
            register(new DefaultHelidonResponseExceptionMapper());
        }

        Client client = jerseyClientBuilder.build();
        WebTarget webTarget = client.target(uri);

        return (T) Proxy.newProxyInstance(clazz.getClassLoader(),
                new Class[]{clazz},
                new ProxyInvocationHandler(clazz, client, webTarget)
        );
    }

    @Override
    public Configuration getConfiguration() {
        return jerseyClientBuilder.getConfiguration();
    }

    @Override
    public RestClientBuilder property(String name, Object value) {
        jerseyClientBuilder.property(name, value);
        return this;
    }

    @Override
    public RestClientBuilder register(Class<?> aClass) {
        jerseyClientBuilder.register(createInstance(aClass));
        return this;
    }

    @Override
    public RestClientBuilder register(Class<?> aClass, int i) {
        jerseyClientBuilder.register(createInstance(aClass), i);
        return this;
    }

    @Override
    public RestClientBuilder register(Class<?> aClass, Class<?>... classes) {
        jerseyClientBuilder.register(createInstance(aClass), classes);
        return this;
    }

    @Override
    public RestClientBuilder register(Class<?> aClass, Map<Class<?>, Integer> map) {
        jerseyClientBuilder.register(createInstance(aClass), map);
        return this;
    }

    @Override
    public RestClientBuilder register(Object o) {
        jerseyClientBuilder.register(o);
        return this;
    }

    @Override
    public RestClientBuilder register(Object o, int i) {
        jerseyClientBuilder.register(o, i);
        return this;
    }

    @Override
    public RestClientBuilder register(Object o, Class<?>... classes) {
        jerseyClientBuilder.register(o, classes);
        return this;
    }

    @Override
    public RestClientBuilder register(Object o, Map<Class<?>, Integer> map) {
        jerseyClientBuilder.register(o, map);
        return this;
    }

    private <T> T createInstance(Class<T> tClass) {
        try {
            return tClass.newInstance();
        } catch (Throwable t) {
            throw new RuntimeException("No default constructor in class " + tClass + " present. Class cannot be registered!", t);
        }
    }
}
