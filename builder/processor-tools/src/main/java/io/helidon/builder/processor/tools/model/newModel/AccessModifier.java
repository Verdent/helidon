package io.helidon.builder.processor.tools.model.newModel;

/**
 * TODO javadoc
 */
public enum AccessModifier {

    PUBLIC("public"),
    PROTECTED("protected"),
    PACKAGE_PRIVATE(""),
    PRIVATE("private");

    private final String modifierName;

    AccessModifier(String modifierName) {
        this.modifierName = modifierName;
    }

    public String modifierName() {
        return modifierName;
    }

}
