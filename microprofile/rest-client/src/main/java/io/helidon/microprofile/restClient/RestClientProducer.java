package io.helidon.microprofile.restClient;

import java.lang.annotation.Annotation;
import java.lang.reflect.Type;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.context.Dependent;
import javax.enterprise.context.spi.CreationalContext;
import javax.enterprise.inject.spi.Bean;
import javax.enterprise.inject.spi.BeanManager;
import javax.enterprise.inject.spi.DeploymentException;
import javax.enterprise.inject.spi.InjectionPoint;

import io.helidon.common.CollectionsHelper;
import io.helidon.common.OptionalHelper;

import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import org.eclipse.microprofile.rest.client.RestClientBuilder;
import org.eclipse.microprofile.rest.client.inject.RegisterRestClient;
import org.eclipse.microprofile.rest.client.inject.RestClient;

/**
 * Created by David Kral.
 */
class RestClientProducer implements Bean<Object> {

    private static final String CONFIG_URL = "/mp-rest/url";
    private static final String CONFIG_URI = "/mp-rest/uri";
    private static final String CONFIG_SCOPE = "/mp-rest/scope";
    private static final String CONFIG_CONNECTION_TIMEOUT = "/mp-rest/connectTimeout";
    private static final String CONFIG_READ_TIMEOUT = "/mp-rest/readTimeout";

    private final BeanManager beanManager;
    private final Class<?> interfaceType;
    private final Config config;
    private final String baseUrl;

    RestClientProducer(Class<?> interfaceType, BeanManager beanManager) {
        this.interfaceType = interfaceType;
        this.beanManager = beanManager;
        this.config = ConfigProvider.getConfig();
        this.baseUrl = getBaseUrl(interfaceType);
    }

    private String getBaseUrl(Class<?> interfaceType) {
        return OptionalHelper.from(config.getOptionalValue(getName() + CONFIG_URL, String.class))
                .or(() -> config.getOptionalValue(getName() + CONFIG_URI, String.class))
                .asOptional()
                .orElseGet(() -> {
                    RegisterRestClient registerRestClient = interfaceType.getAnnotation(RegisterRestClient.class);
                    if (registerRestClient != null) {
                        return registerRestClient.baseUri();
                    }
                    throw new DeploymentException("This interface has to be annotated with @RegisterRestClient annotation.");
                });
    }

    @Override
    public Class<?> getBeanClass() {
        return interfaceType;
    }

    @Override
    public Set<InjectionPoint> getInjectionPoints() {
        return CollectionsHelper.setOf();
    }

    @Override
    public boolean isNullable() {
        return false;
    }

    @Override
    public Object create(CreationalContext<Object> creationalContext) {
        try {
            RestClientBuilder restClientBuilder = RestClientBuilder.newBuilder().baseUrl(new URL(baseUrl));
            config.getOptionalValue(interfaceType.getName() + CONFIG_CONNECTION_TIMEOUT, Long.class)
                    .ifPresent(aLong -> restClientBuilder.connectTimeout(aLong, TimeUnit.MILLISECONDS));
            config.getOptionalValue(interfaceType.getName() + CONFIG_READ_TIMEOUT, Long.class)
                    .ifPresent(aLong -> restClientBuilder.readTimeout(aLong, TimeUnit.MILLISECONDS));
            //TODO zmenit
            return restClientBuilder.build(interfaceType);
        } catch (MalformedURLException e) {
            throw new IllegalStateException("URL is not in valid format: " + baseUrl);
        }
    }

    @Override
    public void destroy(Object instance, CreationalContext<Object> creationalContext) {
    }

    @Override
    public Set<Type> getTypes() {
        return CollectionsHelper.setOf(interfaceType);
    }

    @Override
    public Set<Annotation> getQualifiers() {
        return CollectionsHelper.setOf(RestClient.LITERAL);
    }

    @Override
    public Class<? extends Annotation> getScope() {
        //TODO change
        return resolveScope();
    }

    @Override
    public String getName() {
        return interfaceType.getName();
    }

    @Override
    public Set<Class<? extends Annotation>> getStereotypes() {
        //TODO co jsou stereotypes
        return CollectionsHelper.setOf();
    }

    @Override
    public boolean isAlternative() {
        return false;
    }

    //TODO upravit
    private Class<? extends Annotation> resolveScope() {
        String configScope = config.getOptionalValue(interfaceType.getName() + CONFIG_SCOPE, String.class).orElse(null);

        if (configScope != null) {
            try {
                return (Class<? extends Annotation>) Class.forName(configScope);
            } catch (Exception e) {
                throw new IllegalArgumentException("Invalid scope from config: " + configScope, e);
            }
        }

        List<Annotation> possibleScopes = Arrays.stream(interfaceType.getDeclaredAnnotations())
                .filter(annotation -> beanManager.isScope(annotation.annotationType()))
                .collect(Collectors.toList());

        if (possibleScopes.isEmpty()) {
            return Dependent.class;
        } else if (possibleScopes.size() == 1) {
            return possibleScopes.get(0).annotationType();
        } else {
            throw new IllegalArgumentException("Ambiguous scope definition on " + interfaceType + ": " + possibleScopes);
        }
    }
}
