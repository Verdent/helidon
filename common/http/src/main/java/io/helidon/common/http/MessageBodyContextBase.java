/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package io.helidon.common.http;

import io.helidon.common.GenericType;
import io.helidon.common.http.MessageBody.Context;
import io.helidon.common.http.MessageBody.Filter;
import io.helidon.common.http.MessageBody.Filters;
import io.helidon.common.http.MessageBody.Operator;
import io.helidon.common.reactive.Flow.Publisher;
import io.helidon.common.reactive.Flow.Subscriber;
import io.helidon.common.reactive.Flow.Subscription;
import io.helidon.common.reactive.Mono;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Base message body context implementation.
 */
public abstract class MessageBodyContextBase implements Filters {

    private static final Logger LOGGER =
            Logger.getLogger(MessageBodyContextBase.class.getName());

    /**
     * Subscription event listener.
     */
    public static interface EventListener {

        /**
         * Response to an emitted subscription event.
         * @param event subscription event
         */
        void onEvent(Event event);
    }

    /**
     * Subscription event types.
     */
    public static enum EVENT_TYPE {

        /**
         * Emitted before {@link Subscriber#onSubscribe() }.
         */
        BEFORE_ONSUBSCRIBE,

        /**
         * Emitted after {@link Subscriber#onSubscribe }.
         */
        AFTER_ONSUBSCRIBE,

        /**
         * Emitted before {@link Subscriber#onNext() }.
         */
        BEFORE_ONNEXT,

        /**
         * Emitted after {@link Subscriber#onNext() }.
         */
        AFTER_ONNEXT,

        /**
         * Emitted after {@link Subscriber#onError() }.
         */
        BEFORE_ONERROR,

        /**
         * Emitted after {@link Subscriber#onError() }.
         */
        AFTER_ONERROR,

        /**
         * Emitted after {@link Subscriber#onComplete() }.
         */
        BEFORE_ONCOMPLETE,

        /**
         * Emitted after {@link Subscriber#onComplete() }.
         */
        AFTER_ONCOMPLETE
    }

    /**
     * Subscription event contract.
     */
    public static interface Event {

        /**
         * Get the event type of this event.
         * @return EVENT_TYPE
         */
        EVENT_TYPE eventType();

        /**
         * Get the type requested for conversion.
         * @return never {@code null}
         */
        Optional<GenericType<?>> entityType();

        /**
         * Fluent helper method to cast this event as a {@link ErrorEvent}. This
         * is safe to do when {@link #eventType()} returns
         * {@link EVENT_TYPE#BEFORE_ONERROR} or {@link EVENT_TYPE#AFTER_ONERROR}
         *
         * @return ErrorEvent
         * @throws IllegalStateException if this event is not an instance of
         * {@link ErrorEvent}
         */
        default ErrorEvent asErrorEvent() {
            if (!(this instanceof ErrorEvent)) {
                throw new IllegalStateException("Not an error event");
            }
            return (ErrorEvent) this;
        }
    }

    /**
     * A subscription event emitted for {@link EVENT_TYPE#BEFORE_ONERROR} or
     * {@link EVENT_TYPE#AFTER_ONERROR} that carries the received error.
     */
    public static interface ErrorEvent extends Event {

        /**
         * Get the subscription error of this event.
         * @return {@code Throwable}, never {@code null}
         */
        Throwable error();
    }

    private static final Event BEFORE_ONSUBSCRIBE = new EventImpl(
            EVENT_TYPE.BEFORE_ONSUBSCRIBE, Optional.empty());

    private static final Event BEFORE_ONNEXT = new EventImpl(
            EVENT_TYPE.BEFORE_ONNEXT, Optional.empty());

    private static final Event BEFORE_ONCOMPLETE = new EventImpl(
            EVENT_TYPE.BEFORE_ONCOMPLETE, Optional.empty());

    private static final Event AFTER_ONSUBSCRIBE = new EventImpl(
            EVENT_TYPE.AFTER_ONSUBSCRIBE, Optional.empty());

    private static final Event AFTER_ONNEXT = new EventImpl(
            EVENT_TYPE.AFTER_ONNEXT, Optional.empty());

    private static final Event AFTER_ONCOMPLETE = new EventImpl(
            EVENT_TYPE.AFTER_ONCOMPLETE, Optional.empty());

    private final MessageBodyOperators<FilterOperator, Context> filters;
    private final EventListener eventListener;

    /**
     * Create a non parented context.
     * @param eventListener subscription event listener
     */
    protected MessageBodyContextBase(EventListener eventListener) {
        this.filters = new MessageBodyOperators<>();
        this.eventListener = eventListener;
    }

    /**
     * Create a new parented content support instance.
     * @param parent content filters parent
     * @param eventListener event listener
     */
    protected MessageBodyContextBase(MessageBodyContextBase parent,
            EventListener eventListener) {

        Objects.requireNonNull(parent, "parent cannot be null!");
        this.filters = new MessageBodyOperators<>(parent.filters);
        this.eventListener = eventListener;
    }

    @Override
    public MessageBodyContextBase registerFilter(Filter filter) {
        Objects.requireNonNull(filter, "filter is null!");
        filters.registerLast(new FilterOperator(filter));
        return this;
    }

    @Deprecated
    @Override
    public void registerFilter(
            Function<Publisher<DataChunk>, Publisher<DataChunk>> function) {

        Objects.requireNonNull(function, "filter function is null!");
        filters.registerLast(new FilterOperator(new FunctionFilter(function)));
    }

    /**
     * Perform the filter chaining.
     * @param publisher input publisher
     * @param listener subscription listener
     * @return tail of the publisher chain
     */
    private Publisher<DataChunk> doApplyFilters(Publisher<DataChunk> publisher,
            EventListener listener) {

        if (publisher == null) {
            publisher = Mono.<DataChunk>empty();
        }
        try {
            Publisher<DataChunk> last = publisher;
            for (Filter filter : filters) {
                last.subscribe(filter);
                last = filter;
            }
            return new EventingPublisher(last, listener);
        } finally {
            filters.close();
        }
    }

    /**
     * Apply the filters on the given input publisher to form a publisher chain.
     * @param publisher input publisher
     * @return tail of the publisher chain
     */
    public Publisher<DataChunk> applyFilters(Publisher<DataChunk> publisher) {
        return doApplyFilters(publisher, eventListener);
    }

    /**
     * Apply the filters on the given input publisher to form a publisher chain.
     * @param publisher input publisher
     * @param type type information associated with the input publisher
     * @return tail of the publisher chain
     */
    protected Publisher<DataChunk> applyFilters(Publisher<DataChunk> publisher,
            GenericType<?> type) {

        Objects.requireNonNull(type, "type cannot be null!");
        if (eventListener != null) {
            return doApplyFilters(publisher,
                    new TypedEventListener(eventListener, type));
        } else {
            return doApplyFilters(publisher, eventListener);
        }
    }

    /**
     * Delegating publisher that subscribes a delegating
     * {@link EventingSubscriber} during {@link Publisher#subscribe }.
     */
    private static final class EventingPublisher
            implements Publisher<DataChunk> {

        private final Publisher<DataChunk> publisher;
        private final EventListener listener;

        EventingPublisher(Publisher<DataChunk> publisher,
                EventListener listener) {

            this.publisher = publisher;
            this.listener = listener;
        }

        @Override
        public void subscribe(Subscriber<? super DataChunk> subscriber) {
            publisher.subscribe(new EventingSubscriber(subscriber, listener));
        }
    }

    /**
     * Delegating subscriber that emits the events.
     */
    private static final class EventingSubscriber
            implements Subscriber<DataChunk> {

        private final Subscriber<? super DataChunk> delegate;
        private final EventListener listener;

        EventingSubscriber(Subscriber<? super DataChunk> delegate,
                EventListener listener) {

            this.delegate = delegate;
            this.listener = listener;
        }

        private void fireEvent(Event event) {
            if (listener != null) {
                try {
                    listener.onEvent(event);
                } catch (Throwable ex) {
                    LOGGER.log(Level.WARNING,
                            "An exception occurred in EventListener.onEvent",
                            ex);
                }
            }
        }

        @Override
        public void onSubscribe(Subscription subscription) {
            fireEvent(BEFORE_ONSUBSCRIBE);
            try {
                delegate.onSubscribe(subscription);
            } finally {
                fireEvent(AFTER_ONSUBSCRIBE);
            }
        }

        @Override
        public void onNext(DataChunk item) {
            fireEvent(BEFORE_ONNEXT);
            try {
                delegate.onNext(item);
            } finally {
                fireEvent(AFTER_ONNEXT);
            }
        }

        @Override
        public void onError(Throwable error) {
            fireEvent(new ErrorEventImpl(error, EVENT_TYPE.BEFORE_ONERROR));
            try {
                delegate.onError(error);
            } finally {
                fireEvent(new ErrorEventImpl(error, EVENT_TYPE.AFTER_ONERROR));
            }
        }

        @Override
        public void onComplete() {
            fireEvent(BEFORE_ONCOMPLETE);
            try {
                delegate.onComplete();
            } finally {
                fireEvent(AFTER_ONCOMPLETE);
            }
        }
    }

    /**
     * A filter adapter to support the old deprecated filter as function.
     */
    private static final class FunctionFilter implements Filter {

        private final Function<Publisher<DataChunk>, Publisher<DataChunk>> function;
        private Subscriber<? super DataChunk> subscriber;
        private Publisher<DataChunk> downstream;

        FunctionFilter(
                Function<Publisher<DataChunk>, Publisher<DataChunk>> function) {

            this.function = function;
        }

        @Override
        public void onSubscribe(Subscription subscription) {
            downstream = function.apply(new Publisher<DataChunk>() {
                @Override
                public void subscribe(Subscriber<? super DataChunk> subscriber) {
                    if (FunctionFilter.this.subscriber != null) {
                        throw new IllegalStateException("Already subscribed to!");
                    }
                    FunctionFilter.this.subscriber = subscriber;
                    subscriber.onSubscribe(subscription);
                }
            });
        }

        @Override
        public void onNext(DataChunk item) {
            this.subscriber.onNext(item);
        }

        @Override
        public void onError(Throwable throwable) {
            this.subscriber.onError(throwable);
        }

        @Override
        public void onComplete() {
            this.subscriber.onComplete();
        }

        @Override
        public void subscribe(Subscriber<? super DataChunk> subscriber) {
            if (downstream == null) {
                throw new IllegalStateException("Not ready!");
            }
            downstream.subscribe(subscriber);
        }
    }

    /**
     * {@link Operator} adapter for {@link Filter}.
     */
    private static final class FilterOperator
            implements Operator<Context>, Filter {

        private final Filter filter;

        FilterOperator(Filter filter) {
            this.filter = filter;
        }

        @Override
        public boolean accept(GenericType<?> type, Context scope) {
            return this.getClass().equals(type.rawType());
        }

        @Override
        public void onSubscribe(Subscription subscription) {
            filter.onSubscribe(subscription);
        }

        @Override
        public void onNext(DataChunk item) {
            filter.onNext(item);
        }

        @Override
        public void onError(Throwable throwable) {
            filter.onError(throwable);
        }

        @Override
        public void onComplete() {
            filter.onComplete();
        }

        @Override
        public void subscribe(Subscriber<? super DataChunk> subscriber) {
            filter.subscribe(subscriber);
        }
    }

    /**
     * Delegating listener that creates copies of the emitted events to add the
     * entityType.
     */
    private static final class TypedEventListener implements EventListener {

        private final EventListener delegate;
        private final Optional<GenericType<?>> entityType;

        TypedEventListener(EventListener delegate,
                GenericType<?> entityType) {

            this.delegate = delegate;
            this.entityType = Optional.of(entityType);
        }

        @Override
        public void onEvent(Event event) {
            Event copy;
            if (event instanceof ErrorEventImpl) {
                copy = new ErrorEventImpl((ErrorEventImpl) event, entityType);
            } else if (event instanceof EventImpl) {
                copy = new EventImpl((EventImpl) event, entityType);
            } else {
                throw new IllegalStateException("Unknown event type " + event);
            }
            delegate.onEvent(copy);
        }
    }

    /**
     * {@link Event} implementation.
     */
    private static class EventImpl implements Event {

        protected final EVENT_TYPE eventType;
        protected final Optional<GenericType<?>> entityType;

        EventImpl(EventImpl event, Optional<GenericType<?>> entityType) {
            this(event.eventType, entityType);
        }

        EventImpl(EVENT_TYPE eventType, Optional<GenericType<?>> entityType) {
            this.eventType = eventType;
            this.entityType = entityType;
        }

        @Override
        public Optional<GenericType<?>> entityType() {
            return entityType;
        }

        @Override
        public EVENT_TYPE eventType() {
            return eventType;
        }
    }

    /**
     * {@link ErrorEvent} implementation.
     */
    private static final class ErrorEventImpl extends EventImpl
            implements ErrorEvent {

        private final Throwable error;

        ErrorEventImpl(ErrorEventImpl event, Optional<GenericType<?>> entityType) {
            super(event.eventType, event.entityType);
            error = event.error;
        }

        ErrorEventImpl(Throwable error, EVENT_TYPE eventType) {
            super(eventType, Optional.empty());
            Objects.requireNonNull(error, "error cannot be null!");
            this.error = error;
        }

        @Override
        public Throwable error() {
            return error;
        }
    }
}
