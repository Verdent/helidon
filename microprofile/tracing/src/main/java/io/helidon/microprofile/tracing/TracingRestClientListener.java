package io.helidon.microprofile.tracing;

import javax.enterprise.inject.spi.CDI;

import io.opentracing.Tracer;
import io.opentracing.contrib.jaxrs2.client.ClientTracingFeature;
import org.eclipse.microprofile.opentracing.Traced;
import org.eclipse.microprofile.rest.client.RestClientBuilder;
import org.eclipse.microprofile.rest.client.spi.RestClientListener;

/**
 * Created by David Kral.
 */
public class TracingRestClientListener implements RestClientListener {
    @Override
    public void onNewClient(Class<?> serviceInterface, RestClientBuilder builder) {
        Traced traced = serviceInterface.getAnnotation(Traced.class);
        if (traced != null && !traced.value()) {
            return;
        }

        Tracer tracer = CDI.current().select(Tracer.class).get();
        new ClientTracingFeature.Builder(tracer)
                .withTraceSerialization(false)
                .build();
        /*builder.register(new SmallRyeClientTracingFeature(tracer));
        builder.register(new OpenTracingAsyncInterceptorFactory(tracer));*/
    }
}
