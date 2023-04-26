package io.helidon.builder.processor.tools.model;

import java.io.IOException;
import java.io.Writer;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

class ImportOrganizer {

    private final Map<String, String> imports;
    private final Set<String> staticImports;
    private final Set<String> exceptionImports;
    private final Set<String> forcedFullNames;
    private final String fullClassName;

    private ImportOrganizer(Builder builder) {
        this.imports = Map.copyOf(builder.imports);
        this.staticImports = new TreeSet<>(builder.staticImports);
        this.exceptionImports = Set.copyOf(builder.exceptionImports.keySet());
        this.forcedFullNames = Set.copyOf(builder.forcedFullNames);
        this.fullClassName = builder.typePackage + "." + builder.name;
    }

    static Builder builder(String typePackage, String name) {
        return new Builder(typePackage, name);
    }

    String typeName(Type type, boolean included) {
        if (type instanceof Token) {
            return type.typeName();
        }
        String fullTypeName = type.typeName();
        String simpleTypeName = type.simpleTypeName();
        if (!included) {
            return fullTypeName;
        } else if (forcedFullNames.contains(fullTypeName)) {
            if (type.isInnerType()) {
                return type.outerClass() + "." + type.simpleTypeName();
            }
            return fullTypeName;
        } else if (exceptionImports.contains(simpleTypeName)) {
            if (type.isInnerType()) {
                if (isTheSameAsCreatedClass(type)) {
                    return type.simpleTypeName();
                }
                return type.outerClass() + "." + type.simpleTypeName();
            }
            return simpleTypeName;
        }
        return imports.containsKey(simpleTypeName) ? simpleTypeName : fullTypeName;
    }

    private boolean isTheSameAsCreatedClass(Type type) {
        return fullClassName.equals(type.packageName() + "." + type.outerClass());
    }

    void writeImports(Writer writer) throws IOException {
        if (!imports.isEmpty()) {
            for (String importName : imports.values().stream().sorted().toList()) {
                writer.write("import " + importName + ";\n");
            }
            writer.write("\n");
        }
    }

    void writeStaticImports(Writer writer) throws IOException {
        if (!staticImports.isEmpty()) {
            for (String importName : staticImports) {
                writer.write("import static " + importName + ";\n");
            }
            writer.write("\n");
        }
    }

    static final class Builder {

        /**
         * Class imports.
         */
        private final Map<String, String> imports = new HashMap<>();

        /**
         * Class static imports.
         */
        private final Set<String> staticImports = new TreeSet<>();

        /**
         * Imports from "java.lang" package or classes within the same package.
         * They should be monitored for name collisions, but not included in class imports.
         */
        private final Map<String, Type> exceptionImports = new HashMap<>();

        /**
         * Set of inner classes of the current class.
         */
        private final Set<String> innerClasses = new HashSet<>();

        /**
         * Collection for class names with colliding simple names.
         * The first registered will be used as import. The later ones have to be used as full names.
         */
        private final Set<String> forcedFullNames = new HashSet<>();

        /**
         * Package of the created class.
         */
        private final String typePackage;
        /**
         * Name of the currently created class.
         */
        private final String name;
        /**
         * Full name of the created class.
         */
        private final String fullName;

        private Builder(String typePackage, String name) {
            this.typePackage = typePackage;
            this.name = name;
            if (typePackage == null || typePackage.isEmpty()) {
                fullName = name;
            } else {
                fullName = typePackage + "." + name;
            }
        }

        ImportOrganizer build() {
            return new ImportOrganizer(this);
        }

        public Builder addImport(Class<?> type) {
            return addImport(type.getName());
        }

        public Builder addImport(String type) {
            return addImport(Type.create(type));
        }

        public Builder addImport(Type type) {
            if (type.packageName().isEmpty()) {
                return this;
            }

            String typeName = type.typeName();
            String typePackage = type.packageName();
            String typeSimpleName = type.simpleTypeName();
            if (typePackage.equals("java.lang")) {
                processImportJavaLang(type, typeName, typeSimpleName);
            } else if (this.typePackage != null
                    && this.typePackage.equals(typePackage)) {
                processImportSamePackage(type, typeName, typeSimpleName);
            } else if (imports.containsKey(typeSimpleName) && !imports.get(typeSimpleName).equals(typeName)) {
                //If there is imported class with this simple name already, but it is not in the same package
                forcedFullNames.add(typeName);
            } else if (innerClasses.contains(typeSimpleName)) {
                forcedFullNames.add(typeName);
            } else if (exceptionImports.containsKey(typeSimpleName)) {
                if (exceptionImports.get(typeSimpleName).isInnerType()
                        && !typeName.startsWith(fullName + ".")) {
                    imports.put(typeSimpleName, typeName);
                } else {
                    forcedFullNames.add(typeName);
                }
            } else {
                imports.put(typeSimpleName, typeName);
            }
            return this;
        }

        private void processImportJavaLang(Type type, String typeName, String typeSimpleName) {
            //new class is from java.lang package
            if (imports.containsKey(typeSimpleName)) {
                //some other class with the same name is already being imported (but with the different package)
                //remove that previously added class from imports and place it to the list of forced full class names
                forcedFullNames.add(imports.remove(typeSimpleName));
            } else if (exceptionImports.containsKey(typeSimpleName)
                    && !exceptionImports.get(typeSimpleName).type().equals(typeName)) {
                //if there is already class with the same name, but different package, added among the imports,
                // and it does not need import specified (java.lang and the same package), remove it from the exception
                // list and add it among forced imports.
                forcedFullNames.add(typeName);
                return;
            }
            exceptionImports.put(typeSimpleName, type);
        }

        private void processImportSamePackage(Type type, String typeName, String typeSimpleName) {
            //            String toCheck = type.outerClass() == null ? typeSimpleName : type.outerClass();
            if (imports.containsKey(typeSimpleName)) {
                //There is a class among general imports which match the currently added class name.
                forcedFullNames.add(imports.remove(typeSimpleName));
                exceptionImports.put(typeSimpleName, type);
            } else if (innerClasses.contains(typeSimpleName)) {
                //There is inner class identified of this name for the currently created class.
                if (!exceptionImports.get(typeSimpleName).type().equals(typeName)) {
                    //Everything needs to be forced to have full package.
                    forcedFullNames.add(typeName);
                }
            } else if (exceptionImports.containsKey(typeSimpleName)) {
                //There is already specialized handling of a class with this name
                if (!exceptionImports.get(typeSimpleName).type().equals(typeName)) {
                    forcedFullNames.add(exceptionImports.remove(typeSimpleName).type());
                    exceptionImports.put(typeSimpleName, type);
                }
            } else {
                exceptionImports.put(typeSimpleName, type);
                if (type.isInnerType() && type.typeName().startsWith(fullName + ".")) {
                    //This added class is inner class of our currently processed type.
                    innerClasses.add(typeSimpleName);
                }
            }
        }

        public Builder addStaticImport(String staticImport) {
            staticImports.add(staticImport);
            return this;
        }

    }

}
