package io.helidon.builder.processor.tools.model.newModel;

public class InnerClass extends AbstractClass {

    private InnerClass(Builder builder) {
        super(builder);
    }

    static Builder builder() {
        return new Builder();
    }

    public static final class Builder extends AbstractClass.Builder<Builder, InnerClass> {


        private Builder() {
        }

        @Override
        public InnerClass build() {
            return new InnerClass(this);
        }
    }
}
