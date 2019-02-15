package io.helidon.microprofile.tracing;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Produces;

import io.opentracing.Tracer;
import io.opentracing.util.GlobalTracer;

/**
 * Created by David Kral.
 */
@ApplicationScoped
public class TracerProducer {

    @Produces
    public Tracer produceTracer() {
        return GlobalTracer.get();
    }

}
