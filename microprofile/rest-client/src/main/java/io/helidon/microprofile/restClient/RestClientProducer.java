package io.helidon.microprofile.restClient;

import java.lang.annotation.Annotation;
import java.lang.reflect.Type;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collections;
import java.util.Set;

import javax.enterprise.context.spi.CreationalContext;
import javax.enterprise.inject.spi.Bean;
import javax.enterprise.inject.spi.BeanManager;
import javax.enterprise.inject.spi.DeploymentException;
import javax.enterprise.inject.spi.InjectionPoint;

import io.helidon.common.CollectionsHelper;

import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import org.eclipse.microprofile.rest.client.RestClientBuilder;
import org.eclipse.microprofile.rest.client.inject.RegisterRestClient;

/**
 * Created by David Kral.
 */
class RestClientProducer implements Bean<Object> {

    private static final String CONFIG_URL = "/mp-rest/url";
    private static final String CONFIG_URI = "/mp-rest/uri";
    private static final String CONFIG_SCOPE = "/mp-rest/scope";

    private final Class<?> interfaceType;
    private final Config config;
    private final String baseUrl;

    RestClientProducer(Class<?> interfaceType, BeanManager beanManager) {
        this.interfaceType = interfaceType;
        this.config = ConfigProvider.getConfig();
        this.baseUrl = getBaseUrl(interfaceType);
    }

    private String getBaseUrl(Class<?> interfaceType) {
        String url = config
                .getOptionalValue(getName() + CONFIG_URL, String.class)
                .orElse(config.getValue(getName() + CONFIG_URI, String.class));
        if (url != null) {
            return url;
        }
        RegisterRestClient registerRestClient = interfaceType.getAnnotation(RegisterRestClient.class);
        if (registerRestClient != null) {
            return registerRestClient.baseUri();
        }
        throw new DeploymentException("This interface has to be annotated with @RegisterRestClient annotation.");
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
            return RestClientBuilder.newBuilder().baseUrl(new URL(baseUrl)).build(interfaceType);
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
        //TODO tady nevim co dat
        return null;
    }

    @Override
    public Class<? extends Annotation> getScope() {
        //TODO dodelat ziskani scopu
        return null;
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
}
