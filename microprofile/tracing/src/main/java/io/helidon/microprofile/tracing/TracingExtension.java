package io.helidon.microprofile.tracing;

import javax.enterprise.event.Observes;
import javax.enterprise.inject.spi.BeanManager;
import javax.enterprise.inject.spi.BeforeBeanDiscovery;
import javax.enterprise.inject.spi.Extension;

/**
 * Created by David Kral.
 */
public class TracingExtension implements Extension {

    public void observeBeforeBeanDiscovery(@Observes BeforeBeanDiscovery bbd, BeanManager manager) {
        //bbd.addAnnotatedType(manager.createAnnotatedType(TracerProducer.class));
    }

}
