package io.helidon.builder.model;

import java.io.IOException;
import java.io.Writer;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import io.helidon.common.types.TypeName;
import io.helidon.common.types.TypeNameDefault;

class ImportOrganizer {

    private final List<String> imports;
    private final List<String> staticImports;
    private final Set<String> noImport;
    private final Set<String> forcedFullImports;

    private ImportOrganizer(Builder builder) {
        this.imports = builder.finalImports.values()
                .stream()
                .sorted()
                .toList();
        this.staticImports = builder.staticImports.stream()
                .map(Type::typeName)
                .sorted()
                .toList();
        this.noImport = builder.noImports.values()
                .stream()
                .map(Type::typeName)
                .collect(Collectors.toSet());
        this.forcedFullImports = Set.copyOf(builder.forcedFullImports);
    }

    static Builder builder() {
        return new Builder();
    }

    String typeName(Type type) {
        if (type instanceof Token) {
            return type.typeName();
        }
        String fullTypeName = type.typeName();
        String simpleTypeName = type.simpleTypeName();
        if (forcedFullImports.contains(fullTypeName)) {
            return fullTypeName;
        } else if (noImport.contains(fullTypeName)) {
            return simpleTypeName;
        }
        return imports.contains(fullTypeName) ? simpleTypeName : fullTypeName;
    }

    void writeImports(Writer writer) throws IOException {
        if (!imports.isEmpty()) {
            for (String importName : imports.stream().sorted().toList()) {
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

    List<String> imports() {
        return imports;
    }

    Set<String> noImport() {
        return noImport;
    }

    Set<String> forcedFullImports() {
        return forcedFullImports;
    }

    static final class Builder implements io.helidon.common.Builder<Builder, ImportOrganizer> {

        private final Set<Type> imports = new HashSet<>();
        private final Set<Type> staticImports = new HashSet<>();

        /**
         * Class imports.
         */
        private final Map<String, String> finalImports = new HashMap<>();

        /**
         * Imports from "java.lang" package or classes within the same package.
         * They should be monitored for name collisions, but not included in class imports.
         */
        private final Map<String, Type> noImports = new HashMap<>();

        /**
         * Collection for class names with colliding simple names.
         * The first registered will be used as import. The later ones have to be used as full names.
         */
        private final Set<String> forcedFullImports = new HashSet<>();

        private String packageName = "";
        private String typeName;

        private Builder() {
        }

        Builder packageName(String packageName) {
            this.packageName = packageName;
            return this;
        }

        Builder typeName(String typeName) {
            this.typeName = typeName;
            return this;
        }

        Builder addImport(String type) {
            return addImport(TypeNameDefault.createFromTypeName(type));
        }

        Builder addImport(Class<?> type) {
            return addImport(TypeNameDefault.create(type));
        }

        Builder addImport(TypeName type) {
            return addImport(Type.fromTypeName(type));
        }

        Builder addImport(Type type) {
            imports.add(type);
            return this;
        }

        Builder addStaticImport(String type) {
            return addStaticImport(TypeNameDefault.createFromTypeName(type));
        }

        Builder addStaticImport(Class<?> type) {
            return addStaticImport(TypeNameDefault.create(type));
        }

        Builder addStaticImport(TypeName type) {
            return addStaticImport(Type.fromTypeName(type));
        }

        Builder addStaticImport(Type type) {
            staticImports.add(type);
            return this;
        }

        @Override
        public ImportOrganizer build() {
            if (typeName == null) {
                throw new ClassModelException("Import organizer requires to have built type name specified.");
            }
            finalImports.clear();
            forcedFullImports.clear();
            noImports.clear();
            resolveFinalImports();
            return new ImportOrganizer(this);
        }

        private void resolveFinalImports() {
            for (Type type : imports){
                String typeName = type.typeName();
                String typePackage = type.packageName();
                String typeSimpleName = type.simpleTypeName();

                if (typePackage.equals("java.lang")) {
                    //imported class is from java.lang package -> automatically imported
                    processImportJavaLang(type, typeName, typeSimpleName);
                } else if (this.packageName.equals(typePackage)) {
                    processImportSamePackage(type, typeName, typeSimpleName);
                } else if (finalImports.containsKey(typeSimpleName) &&
                        !finalImports.get(typeSimpleName).equals(typeName)) {
                    //If there is imported class with this simple name already, but it is not in the same package as this one
                    //add this newly added among the forced full names
                    forcedFullImports.add(typeName);
                }  else if (noImports.containsKey(typeSimpleName)) {
                    //There is already class with the same name present in the package we are generating to
                    //or imported from java.lang
                    forcedFullImports.add(typeName);
                } else if (!typePackage.isEmpty()) {
                    finalImports.put(typeSimpleName, typeName);
                }
            }
        }

        private void processImportJavaLang(Type type, String typeName, String typeSimpleName) {
            //new class is from java.lang package
            if (finalImports.containsKey(typeSimpleName)) {
                //some other class with the same name is already being imported (but with the different package)
                //remove that previously added class from imports and place it to the list of forced full class names
                forcedFullImports.add(finalImports.remove(typeSimpleName));
            } else if (noImports.containsKey(typeSimpleName)
                    && !noImports.get(typeSimpleName).typeName().equals(typeName)) {
                //if there is already class with the same name, but different package, added among the imports,
                // and it does not need import specified (java.lang and the same package), remove it from the exception
                // list and add it among forced imports.
                forcedFullImports.add(typeName);
                return;
            }
            noImports.put(typeSimpleName, type);
        }

        private void processImportSamePackage(Type type, String typeName, String typeSimpleName) {
            //            String toCheck = type.outerClass() == null ? typeSimpleName : type.outerClass();
            if (finalImports.containsKey(typeSimpleName)) {
                //There is a class among general imports which match the currently added class name.
                forcedFullImports.add(finalImports.remove(typeSimpleName));
                noImports.put(typeSimpleName, type);
            } else if (noImports.containsKey(typeSimpleName)) {
                //There is already specialized handling of a class with this name
                if (!noImports.get(typeSimpleName).typeName().equals(typeName)) {
                    forcedFullImports.add(noImports.remove(typeSimpleName).typeName());
                    noImports.put(typeSimpleName, type);
                }
            } else {
                noImports.put(typeSimpleName, type);
            }
        }
    }

}
