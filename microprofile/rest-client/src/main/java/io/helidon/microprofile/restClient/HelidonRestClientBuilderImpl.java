package io.helidon.microprofile.restClient;

import java.lang.reflect.Proxy;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

import javax.ws.rs.Path;
import javax.ws.rs.Priorities;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Configuration;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.ext.ParamConverterProvider;

import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import org.eclipse.microprofile.rest.client.RestClientBuilder;
import org.eclipse.microprofile.rest.client.RestClientDefinitionException;
import org.eclipse.microprofile.rest.client.annotation.RegisterClientHeaders;
import org.eclipse.microprofile.rest.client.annotation.RegisterProvider;
import org.eclipse.microprofile.rest.client.ext.ResponseExceptionMapper;
import org.eclipse.microprofile.rest.client.spi.RestClientListener;
import org.glassfish.jersey.client.JerseyClientBuilder;
import org.glassfish.jersey.internal.inject.AbstractBinder;
import org.glassfish.jersey.process.internal.RequestScoped;

/**
 * Created by David Kral.
 */
public class HelidonRestClientBuilderImpl implements RestClientBuilder {

    private static final String CONFIG_DISABLE_DEFAULT_MAPPER = "microprofile.rest.client.disable.default.mapper";
    private static final String CONFIG_PROVIDERS = "/mp-rest/providers";
    private static final String PROVIDER_SEPARATOR = ",";

    private URI uri;
    private JerseyClientBuilder jerseyClientBuilder;
    private final Set<ResponseExceptionMapper> responseExceptionMappers;
    private final Set<ParamConverterProvider> paramConverterProviders;
    private final Config config;

    public HelidonRestClientBuilderImpl() {
        jerseyClientBuilder = new JerseyClientBuilder();
        responseExceptionMappers = new HashSet<>();
        paramConverterProviders = new HashSet<>();
        config = ConfigProvider.getConfig();
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

        RestClientModel restClientModel = RestClientModel.from(clazz);

        if (uri == null) {
            throw new IllegalStateException("Base uri/url cannot be null!");
        }

        //InterfaceUtil.validateInterface(clazz);

        //Provider registration part
        Object providersFromJerseyConfig = jerseyClientBuilder.getConfiguration().getProperty(clazz.getName() + CONFIG_PROVIDERS);
        if (providersFromJerseyConfig instanceof String && !((String) providersFromJerseyConfig).isEmpty()) {
            String[] providerArray = ((String) providersFromJerseyConfig).split(PROVIDER_SEPARATOR);
            for (String provider : providerArray) {
                try {
                    Class<?> providerClass = Class.forName(provider);
                    register(providerClass);
                } catch (ClassNotFoundException e) {
                    throw new IllegalStateException("Class with name " + provider + " not found");
                }
            }
        }
        Optional<String> providersFromConfig = config.getOptionalValue(clazz.getName() + CONFIG_PROVIDERS, String.class);
        if (providersFromConfig.isPresent() && !providersFromConfig.get().isEmpty()) {
            String[] providerArray = providersFromConfig.get().split(PROVIDER_SEPARATOR);
            for (String provider : providerArray) {
                try {
                    Class<?> providerClass = Class.forName(provider);
                    register(providerClass);
                } catch (ClassNotFoundException e) {
                    throw new IllegalStateException("Class with name " + provider + " not found");
                }
            }
        }
        RegisterProvider[] registerProviders = clazz.getAnnotationsByType(RegisterProvider.class);
        for (RegisterProvider registerProvider : registerProviders) {
            register(registerProvider.value(), registerProvider.priority() < 0 ? Priorities.USER : registerProvider.priority());
        }

        for (RestClientListener restClientListener : ServiceLoader.load(RestClientListener.class)) {
            restClientListener.onNewClient(clazz, this);
        }

        //We need to check first if default exception mapper was not disabled by property on builder.
        Object disableDefaultMapperJersey = jerseyClientBuilder.getConfiguration().getProperty(CONFIG_DISABLE_DEFAULT_MAPPER);
        if (disableDefaultMapperJersey != null && disableDefaultMapperJersey.equals(Boolean.FALSE)) {
            register(new DefaultHelidonResponseExceptionMapper());
        } else if (disableDefaultMapperJersey == null) {
            //If property was not set on Jersey ClientBuilder, we need to check config.
            Optional<Boolean> disableDefaultMapperConfig = config.getOptionalValue(CONFIG_DISABLE_DEFAULT_MAPPER, boolean.class);
            if (!disableDefaultMapperConfig.isPresent() || !disableDefaultMapperConfig.get()) {
                register(new DefaultHelidonResponseExceptionMapper());
            }
        }

        Client client = jerseyClientBuilder.build();
        WebTarget webTarget = client.target(this.uri);

        restClientModel.getClassModel().getResponseExceptionMappers().addAll(responseExceptionMappers);
        restClientModel.getClassModel().getParamConverterProviders().addAll(paramConverterProviders);


        return (T) Proxy.newProxyInstance(clazz.getClassLoader(),
                                          new Class[] {clazz},
                                          new ProxyInvocationHandler(webTarget, restClientModel)
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
        register(ReflectionUtil.createInstance(aClass));
        //jerseyClientBuilder.register(aClass);
        return this;
    }

    @Override
    public RestClientBuilder register(Class<?> aClass, int i) {
        register(ReflectionUtil.createInstance(aClass), i);
        //jerseyClientBuilder.register(aClass, i);
        return this;
    }

    @Override
    public RestClientBuilder register(Class<?> aClass, Class<?>... classes) {
        register(ReflectionUtil.createInstance(aClass), classes);
        //jerseyClientBuilder.register(aClass, classes);
        return this;
    }

    @Override
    public RestClientBuilder register(Class<?> aClass, Map<Class<?>, Integer> map) {
        register(ReflectionUtil.createInstance(aClass), map);
        //jerseyClientBuilder.register(aClass, map);
        return this;
    }

    @Override
    public RestClientBuilder register(Object o) {
        if (o instanceof ResponseExceptionMapper) {
            ResponseExceptionMapper mapper = (ResponseExceptionMapper) o;
            responseExceptionMappers.add(mapper);
            jerseyClientBuilder.register(mapper, mapper.getPriority());
        } else if (o instanceof ParamConverterProvider) {
            paramConverterProviders.add((ParamConverterProvider) o);
            jerseyClientBuilder.register(o);
        } else {
            jerseyClientBuilder.register(o);
        }
        return this;
    }

    @Override
    public RestClientBuilder register(Object o, int i) {
        if (o instanceof ResponseExceptionMapper) {
            ResponseExceptionMapper mapper = (ResponseExceptionMapper) o;
            responseExceptionMappers.add(mapper);
            jerseyClientBuilder.register(mapper, mapper.getPriority());
        } else if (o instanceof ParamConverterProvider) {
            paramConverterProviders.add((ParamConverterProvider) o);
            jerseyClientBuilder.register(o, i);
        } else {
            jerseyClientBuilder.register(o, i);
        }
        return this;
    }

    @Override
    public RestClientBuilder register(Object o, Class<?>... classes) {
        if (o instanceof ResponseExceptionMapper) {
            ResponseExceptionMapper mapper = (ResponseExceptionMapper) o;
            responseExceptionMappers.add(mapper);
        } else if (o instanceof ParamConverterProvider) {
            paramConverterProviders.add((ParamConverterProvider) o);
        }
        jerseyClientBuilder.register(o, classes);
        return this;
    }

    @Override
    public RestClientBuilder register(Object o, Map<Class<?>, Integer> map) {
        if (o instanceof ResponseExceptionMapper) {
            ResponseExceptionMapper mapper = (ResponseExceptionMapper) o;
            responseExceptionMappers.add(mapper);
        } else if (o instanceof ParamConverterProvider) {
            paramConverterProviders.add((ParamConverterProvider) o);
        }
        jerseyClientBuilder.register(o, map);
        return this;
    }
}
