package io.helidon.builder.processor.tools.model;

/**
 * TODO javadoc
 */
public enum AccessModifier {

    PUBLIC("public"),
    PRIVATE("private"),
    PROTECTED("protected"),
    PACKAGE_PRIVATE("");

    private final String modifierName;

    AccessModifier(String modifierName) {
        this.modifierName = modifierName;
    }

    public String modifierName() {
        return modifierName;
    }

}
