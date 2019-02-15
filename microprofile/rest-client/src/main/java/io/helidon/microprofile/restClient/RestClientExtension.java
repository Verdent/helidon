package io.helidon.microprofile.restClient;

import java.util.LinkedList;
import java.util.List;

import javax.enterprise.event.Observes;
import javax.enterprise.inject.spi.AfterBeanDiscovery;
import javax.enterprise.inject.spi.BeanManager;
import javax.enterprise.inject.spi.DeploymentException;
import javax.enterprise.inject.spi.Extension;
import javax.enterprise.inject.spi.ProcessAnnotatedType;
import javax.enterprise.inject.spi.WithAnnotations;

import org.eclipse.microprofile.rest.client.inject.RegisterRestClient;

/**
 * Created by David Kral.
 */
public class RestClientExtension implements Extension {

    private List<Class<?>> interfaces = new LinkedList<>();

    public void collectClientRegistrations(@Observes @WithAnnotations({RegisterRestClient.class}) ProcessAnnotatedType<?> processAnnotatedType) {
        Class<?> typeDef = processAnnotatedType.getAnnotatedType().getJavaClass();
        if (typeDef.isInterface()) {
            interfaces.add(typeDef);
        } else {
            throw new DeploymentException("RegisterRestClient annotation has to be on interface! " + typeDef + " is not "
                                                  + "interface.");
        }
    }

    public void restClientRegistration(@Observes AfterBeanDiscovery abd, BeanManager bm) {
        interfaces.forEach(type -> abd.addBean(new RestClientProducer(type, bm)));
    }

}
