package io.helidon.inject.processor;

import java.util.Collection;
import java.util.List;

import io.helidon.common.types.TypeInfo;
import io.helidon.inject.processor.spi.AnnotationTypeConvertor;

public class JavaxAnnotationConvertor implements AnnotationTypeConvertor {

    /**
     * Jakarta {@value} annotation.
     */
    public static final String JAKARTA_APPLICATION_SCOPED = "jakarta.enterprise.context.ApplicationScoped";
    /**
     * Jakarta {@value} annotation.
     */
    public static final String JAKARTA_INJECT = "jakarta.inject.Inject";
    /**
     * Jakarta {@value} annotation.
     */
    public static final String JAKARTA_MANAGED_BEAN = "jakarta.annotation.ManagedBean";
    /**
     * Jakarta {@value} annotation.
     */
    public static final String JAKARTA_POST_CONSTRUCT = "jakarta.annotation.PostConstruct";
    /**
     * Jakarta {@value} annotation.
     */
    public static final String JAKARTA_PRE_DESTROY = "jakarta.annotation.PreDestroy";
    /**
     * Jakarta {@value} annotation.
     */
    public static final String JAKARTA_PRIORITY = "jakarta.annotation.Priority";
    /**
     * Jakarta {@value} type.
     */
    public static final String JAKARTA_PROVIDER = "jakarta.inject.Provider";
    /**
     * Jakarta {@value} annotation.
     */
    public static final String JAKARTA_QUALIFIER = "jakarta.inject.Qualifier";
    /**
     * Jakarta {@value} annotation.
     */
    public static final String JAKARTA_RESOURCE = "jakarta.annotation.Resource";
    /**
     * Jakarta {@value} annotation.
     */
    public static final String JAKARTA_RESOURCES = "jakarta.annotation.Resources";
    /**
     * Jakarta {@value} annotation.
     */
    public static final String JAKARTA_SCOPE = "jakarta.inject.Scope";
    /**
     * Jakarta {@value} annotation.
     */
    public static final String JAKARTA_SINGLETON = "jakarta.inject.Singleton";
    /**
     * Jakarta CDI {@value} annotation.
     */
    public static final String JAKARTA_CDI_ACTIVATE_REQUEST_CONTEXT = "jakarta.enterprise.context.control.ActivateRequestContext";
    /**
     * Jakarta CDI {@value} annotation.
     */
    public static final String JAKARTA_CDI_ALTERNATIVE = "jakarta.enterprise.inject.Alternative";
    /**
     * Jakarta CDI {@value} annotation.
     */
    public static final String JAKARTA_CDI_BEFORE_DESTROYED = "jakarta.enterprise.context.BeforeDestroyed";
    /**
     * Jakarta CDI {@value} annotation.
     */
    public static final String JAKARTA_CDI_CONVERSATION_SCOPED = "jakarta.enterprise.context.ConversationScoped";
    /**
     * Jakarta CDI {@value} annotation.
     */
    public static final String JAKARTA_CDI_DEPENDENT = "jakarta.enterprise.context.Dependent";
    /**
     * Jakarta CDI {@value} annotation.
     */
    public static final String JAKARTA_CDI_DESTROYED = "jakarta.enterprise.context.Destroyed";
    /**
     * Jakarta CDI {@value} annotation.
     */
    public static final String JAKARTA_CDI_DISPOSES = "jakarta.enterprise.inject.Disposes";
    /**
     * Jakarta CDI {@value} annotation.
     */
    public static final String JAKARTA_CDI_INITIALIZED = "jakarta.enterprise.context.Initialized";
    /**
     * Jakarta CDI {@value} annotation.
     */
    public static final String JAKARTA_CDI_INTERCEPTED = "jakarta.enterprise.inject.Intercepted";
    /**
     * Jakarta CDI {@value} annotation.
     */
    public static final String JAKARTA_CDI_MODEL = "jakarta.enterprise.inject.Model";
    /**
     * Jakarta CDI {@value} annotation.
     */
    public static final String JAKARTA_CDI_NONBINDING = "jakarta.enterprise.util.Nonbinding";
    /**
     * Jakarta CDI {@value} annotation.
     */
    public static final String JAKARTA_CDI_NORMAL_SCOPE = "jakarta.enterprise.context.NormalScope";
    /**
     * Jakarta CDI {@value} annotation.
     */
    public static final String JAKARTA_CDI_OBSERVES = "jakarta.enterprise.event.Observes";
    /**
     * Jakarta CDI {@value} annotation.
     */
    public static final String JAKARTA_CDI_OBSERVES_ASYNC = "jakarta.enterprise.event.ObservesAsync";
    /**
     * Jakarta CDI {@value} annotation.
     */
    public static final String JAKARTA_CDI_PRODUCES = "jakarta.enterprise.inject.Produces";
    /**
     * Jakarta CDI {@value} annotation.
     */
    public static final String JAKARTA_CDI_REQUEST_SCOPED = "jakarta.enterprise.context.RequestScoped";
    /**
     * Jakarta CDI {@value} annotation.
     */
    public static final String JAKARTA_CDI_SESSION_SCOPED = "jakarta.enterprise.context.SessionScoped";
    /**
     * Jakarta CDI {@value} annotation.
     */
    public static final String JAKARTA_CDI_SPECIALIZES = "jakarta.enterprise.inject.Specializes";
    /**
     * Jakarta CDI {@value} annotation.
     */
    public static final String JAKARTA_CDI_STEREOTYPE = "jakarta.enterprise.inject.Stereotype";
    /**
     * Jakarta CDI {@value} annotation.
     */
    public static final String JAKARTA_CDI_TRANSIENT_REFERENCE = "jakarta.enterprise.inject.TransientReference";
    /**
     * Jakarta CDI {@value} annotation.
     */
    public static final String JAKARTA_CDI_TYPED = "jakarta.enterprise.inject.Typed";
    /**
     * Jakarta CDI {@value} annotation.
     */
    public static final String JAKARTA_CDI_VETOED = "jakarta.enterprise.inject.Vetoed";
    /**
     * Jakarta legacy {@value} annotation.
     */
    public static final String JAVAX_APPLICATION_SCOPED = "javax.enterprise.context.ApplicationScoped";
    /**
     * Jakarta legacy {@value} annotation.
     */
    public static final String JAVAX_INJECT = "javax.inject.Inject";
    /**
     * Jakarta legacy {@value} annotation.
     */
    public static final String JAVAX_POST_CONSTRUCT = "javax.annotation.PostConstruct";
    /**
     * Jakarta legacy {@value} annotation.
     */
    public static final String JAVAX_PRE_DESTROY = "javax.annotation.PreDestroy";
    /**
     * Jakarta legacy {@value} annotation.
     */
    public static final String JAVAX_QUALIFIER = "javax.inject.Qualifier";
    /**
     * Jakarta legacy {@value} annotation.
     */
    public static final String JAVAX_PRIORITY = "javax.annotation.Priority";
    /**
     * Jakarta legacy {@value} type.
     */
    public static final String JAVAX_PROVIDER = "javax.inject.Provider";
    /**
     * Jakarta legacy {@value} annotation.
     */
    public static final String JAVAX_SINGLETON = "javax.inject.Singleton";




    @Override
    public Collection<String> supportedAnnotations() {
        return List.of(JAVAX_SINGLETON,
                       JAVAX_PROVIDER,
                       JAVAX_PRIORITY,
                       JAVAX_QUALIFIER,
                       JAVAX_PRE_DESTROY,
                       JAVAX_POST_CONSTRUCT,
                       JAVAX_INJECT,
                       JAVAX_APPLICATION_SCOPED);
    }

    @Override
    public TypeInfo changeAnnotations(TypeInfo original) {
//        original.
        return null;
    }
}
