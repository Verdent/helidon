package io.helidon.builder.processor.tools.model;

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

        @Override
        public Builder isStatic(boolean isStatic) {
            return super.isStatic(isStatic);
        }

    }
}
