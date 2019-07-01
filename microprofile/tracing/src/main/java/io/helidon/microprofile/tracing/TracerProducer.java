package io.helidon.microprofile.tracing;

import javax.enterprise.context.RequestScoped;
import javax.enterprise.inject.Default;
import javax.enterprise.inject.Produces;
import javax.inject.Singleton;

import io.helidon.common.context.Context;
import io.helidon.common.context.Contexts;

import io.opentracing.Tracer;
import io.opentracing.util.GlobalTracer;

/**
 * Created by David Kral.
 */
@RequestScoped
public class TracerProducer {

    @Produces
    public Tracer tracer() {
        return Contexts.context().orElseGet(Context::create).get(Tracer.class).orElseGet(GlobalTracer::get);
    }

}
