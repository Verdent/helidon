/*
 * Copyright (c) 2018 Oracle and/or its affiliates. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.helidon.microprofile.tracing;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.Optional;
import java.util.regex.Pattern;

import javax.annotation.PostConstruct;
import javax.annotation.Priority;
import javax.enterprise.context.ApplicationScoped;
import javax.ws.rs.ConstrainedTo;
import javax.ws.rs.RuntimeType;
import javax.ws.rs.container.ContainerRequestContext;

import io.helidon.tracing.jersey.AbstractTracingFilter;

import io.opentracing.Tracer;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import org.eclipse.microprofile.opentracing.Traced;
import org.glassfish.jersey.server.ExtendedUriInfo;
import org.glassfish.jersey.server.model.Invocable;
import org.glassfish.jersey.server.model.ResourceMethod;

/**
 * Adds tracing of Jersey calls using a post-matching filter.
 *  Microprofile Opentracing implementation.
 */
@ConstrainedTo(RuntimeType.SERVER)
@Priority(Integer.MIN_VALUE + 5)
@ApplicationScoped
public class MpTracingFilter extends AbstractTracingFilter  {
    private MpTracingHelper utils;

    /**
     * Post construct method, initialization procedures.
     */
    @PostConstruct
    public void postConstruct() {
        this.utils = MpTracingHelper.create();
    }

    @Override
    protected boolean tracingEnabled(ContainerRequestContext context) {
        //   openapi
        // first let us find if we should trace or not
        // this is handled by CDI extension for annotated resources
        Config config = ConfigProvider.getConfig();
        Optional<String> skipPatternConfig = config.getOptionalValue("mp.opentracing.server.skip-pattern", String.class);
        boolean skip = false;
        if (skipPatternConfig.isPresent()) {
            Pattern pattern = Pattern.compile(skipPatternConfig.get());
            String path = context.getUriInfo().getPath();
            if (path.charAt(0) != '/') {
                path = "/" + path;
            }
            skip = pattern.matcher(path).matches();
        }
        if (skip) {
            return false;
        }
        return findTraced(context).map(Traced::value).orElseGet(() -> utils.tracingEnabled());
    }

    @Override
    protected String spanName(ContainerRequestContext context) {
        return utils.operationName(context);
    }

    @Override
    protected void configureSpan(Tracer.SpanBuilder spanBuilder) {

    }

    private Optional<Traced> findTraced(ContainerRequestContext requestContext) {
        requestContext.getRequest().getMethod();
        Method m = getDefinitionMethod(requestContext);
        Annotation[] tracedAnnotations = m.getDeclaredAnnotationsByType(Traced.class);
        Traced traced = null;
        if (tracedAnnotations.length == 0) {
            Class<?> c = m.getDeclaringClass();
            tracedAnnotations = c.getDeclaredAnnotationsByType(Traced.class);
            if (tracedAnnotations.length > 0)  {
                traced = (Traced) tracedAnnotations[0];
            }
        } else {
            traced = (Traced) tracedAnnotations[0];
        }
        // TODO all annotated by "Traced" must be handled by CDI extension
        return Optional.ofNullable(traced);
    }

    private Method getDefinitionMethod(ContainerRequestContext requestContext) {
        if (!(requestContext.getUriInfo() instanceof ExtendedUriInfo)) {
            throw new IllegalStateException("Could not get Extended Uri Info. Incompatible version of Jersey?");
        }

        ExtendedUriInfo uriInfo = (ExtendedUriInfo) requestContext.getUriInfo();
        ResourceMethod matchedResourceMethod = uriInfo.getMatchedResourceMethod();
        Invocable invocable = matchedResourceMethod.getInvocable();
        return invocable.getDefinitionMethod();
    }
}
