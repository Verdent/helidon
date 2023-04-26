package io.helidon.builder.processor.tools.model;

import java.io.IOException;
import java.util.Set;

public class Javadoc {



    private Javadoc(Builder builder) {
    }

    public static Builder builder() {
        return new Builder();
    }

    void writeComponent(ModelWriter writer, Set<String> declaredTokens, ImportOrganizer imports) throws IOException {

    }

    public static final class Builder {

        private Builder() {
        }

        public Javadoc build() {
            return new Javadoc(this);
        }

    }
}
