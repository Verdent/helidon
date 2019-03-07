package io.helidon.microprofile.restClient;

import java.lang.annotation.Retention;
import java.lang.annotation.Target;
import java.lang.reflect.Type;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import javax.enterprise.event.Observes;
import javax.enterprise.inject.Default;
import javax.enterprise.inject.spi.AfterBeanDiscovery;
import javax.enterprise.inject.spi.BeanManager;
import javax.enterprise.inject.spi.DeploymentException;
import javax.enterprise.inject.spi.Extension;
import javax.enterprise.inject.spi.InjectionPoint;
import javax.enterprise.inject.spi.ProcessAnnotatedType;
import javax.enterprise.inject.spi.ProcessInjectionPoint;
import javax.enterprise.inject.spi.WithAnnotations;
import javax.enterprise.util.AnnotationLiteral;
import javax.inject.Qualifier;

import org.eclipse.microprofile.rest.client.inject.RegisterRestClient;
import org.eclipse.microprofile.rest.client.inject.RestClient;

import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

/**
 * Created by David Kral.
 */
public class RestClientExtension implements Extension {

    private Set<Class<?>> interfaces = new HashSet<>();

    public void collectClientRegistrations(@Observes @WithAnnotations({RegisterRestClient.class}) ProcessAnnotatedType<?> processAnnotatedType) {
        Class<?> typeDef = processAnnotatedType.getAnnotatedType().getJavaClass();
        if (typeDef.isInterface()) {
            interfaces.add(typeDef);
        } else {
            throw new DeploymentException("RegisterRestClient annotation has to be on interface! " + typeDef + " is not "
                                                  + "interface.");
        }
    }

    public void collectClientProducer(@Observes ProcessInjectionPoint<?, ?> pip) {
        RestClient restClient = pip.getInjectionPoint().getAnnotated().getAnnotation(RestClient.class);
        if (restClient != null) {
            InjectionPoint ip = pip.getInjectionPoint();
            Class<?> type = (Class<?>) ip.getType();

            RestClientLiteral q = new RestClientLiteral(type);

            pip.configureInjectionPoint().addQualifier(q);
        }
    }

    public void restClientRegistration(@Observes AfterBeanDiscovery abd, BeanManager bm) {
        interfaces.forEach(type -> abd.addBean(new RestClientProducer(new RestClientLiteral(type), type, bm)));
        interfaces.forEach(type -> abd.addBean(new RestClientProducer(null, type, bm)));
    }

    @Qualifier
    @Retention(RUNTIME)
    @Target({METHOD, FIELD})
    @interface MpRestClientQualifier {

        Class<?> interfaceType();

    }

    static class RestClientLiteral extends AnnotationLiteral<MpRestClientQualifier> implements MpRestClientQualifier {

        private final Class<?> interfaceType;

        RestClientLiteral(Class<?> interfaceType) {
            this.interfaceType = interfaceType;
        }

        @Override
        public Class<?> interfaceType() {
            return interfaceType;
        }

        @Override
        public String toString() {
            return "RestClientLiteral{"
                    + "interfaceType=" + interfaceType
                    + '}';
        }

    }

}
