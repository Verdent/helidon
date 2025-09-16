/*
 * Copyright (c) 2025 Oracle and/or its affiliates.
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

package io.helidon.json.schema;

import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

public final class JsonSchema {

    @Target(ElementType.TYPE)
    @Inherited
    @Retention(RetentionPolicy.CLASS)
    public @interface Schema {
    }

    @Target(ElementType.TYPE)
    @Inherited
    @Retention(RetentionPolicy.CLASS)
    public @interface Id {
        java.lang.String value() default "@default";
    }

    @Target({ElementType.TYPE, ElementType.METHOD, ElementType.FIELD})
    @Inherited
    @Retention(RetentionPolicy.CLASS)
    public @interface Title {
        java.lang.String value();
    }

    @Target({ElementType.TYPE, ElementType.METHOD, ElementType.FIELD})
    @Inherited
    @Retention(RetentionPolicy.CLASS)
    public @interface Description {
        java.lang.String value();
    }

    @Target({ElementType.METHOD, ElementType.FIELD})
    @Inherited
    @Retention(RetentionPolicy.CLASS)
    public @interface Required {
    }

    @Target({ElementType.METHOD, ElementType.FIELD})
    @Inherited
    @Retention(RetentionPolicy.CLASS)
    public @interface DoNotInspect {
    }

    @Target({ElementType.METHOD, ElementType.FIELD})
    @Inherited
    @Retention(RetentionPolicy.CLASS)
    public @interface Ignore {
    }

    public static final class Integer {

        @Target({ElementType.METHOD, ElementType.FIELD})
        @Inherited
        @Retention(RetentionPolicy.CLASS)
        public @interface MultipleOf {
            long value();
        }

        @Target({ElementType.METHOD, ElementType.FIELD})
        @Inherited
        @Retention(RetentionPolicy.CLASS)
        public @interface Minimum {
            long value();
        }

        @Target({ElementType.METHOD, ElementType.FIELD})
        @Inherited
        @Retention(RetentionPolicy.CLASS)
        public @interface Maximum {
            long value();
        }

        @Target({ElementType.METHOD, ElementType.FIELD})
        @Inherited
        @Retention(RetentionPolicy.CLASS)
        public @interface ExclusiveMaximum {
            long value();
        }

        @Target({ElementType.METHOD, ElementType.FIELD})
        @Inherited
        @Retention(RetentionPolicy.CLASS)
        public @interface ExclusiveMinimum {
            long value();
        }
    }

    public static final class String {

        @Target({ElementType.METHOD, ElementType.FIELD})
        @Inherited
        @Retention(RetentionPolicy.CLASS)
        public @interface MinLength {
            long value();
        }

        @Target({ElementType.METHOD, ElementType.FIELD})
        @Inherited
        @Retention(RetentionPolicy.CLASS)
        public @interface MaxLength {
            long value();
        }

        @Target({ElementType.METHOD, ElementType.FIELD})
        @Inherited
        @Retention(RetentionPolicy.CLASS)
        public @interface Pattern {
            java.lang.String value();
        }

    }

    public static final class Object {

        @Target({ElementType.METHOD, ElementType.TYPE, ElementType.FIELD})
        @Inherited
        @Retention(RetentionPolicy.CLASS)
        public @interface MinProperties {
            int value();
        }

        @Target({ElementType.METHOD, ElementType.TYPE, ElementType.FIELD})
        @Inherited
        @Retention(RetentionPolicy.CLASS)
        public @interface MaxProperties {
            int value();
        }

        @Target({ElementType.METHOD, ElementType.TYPE, ElementType.FIELD})
        @Inherited
        @Retention(RetentionPolicy.CLASS)
        public @interface AdditionalProperties {
            boolean value();
        }

    }

    public static final class Number {

        @Target({ElementType.METHOD, ElementType.FIELD})
        @Inherited
        @Retention(RetentionPolicy.CLASS)
        public @interface MultipleOf {
            double value();
        }

        @Target({ElementType.METHOD, ElementType.FIELD})
        @Inherited
        @Retention(RetentionPolicy.CLASS)
        public @interface Minimum {
            double value();
        }

        @Target({ElementType.METHOD, ElementType.FIELD})
        @Inherited
        @Retention(RetentionPolicy.CLASS)
        public @interface Maximum {
            double value();
        }

        @Target({ElementType.METHOD, ElementType.FIELD})
        @Inherited
        @Retention(RetentionPolicy.CLASS)
        public @interface ExclusiveMaximum {
            double value();
        }

        @Target({ElementType.METHOD, ElementType.FIELD})
        @Inherited
        @Retention(RetentionPolicy.CLASS)
        public @interface ExclusiveMinimum {
            double value();
        }
    }

    public static final class Array {

        @Target({ElementType.METHOD, ElementType.FIELD})
        @Inherited
        @Retention(RetentionPolicy.CLASS)
        public @interface MaxItems {
            int value();
        }

        @Target({ElementType.METHOD, ElementType.FIELD})
        @Inherited
        @Retention(RetentionPolicy.CLASS)
        public @interface MinItems {
            int value();
        }

        @Target({ElementType.METHOD, ElementType.FIELD})
        @Inherited
        @Retention(RetentionPolicy.CLASS)
        public @interface UniqueItems {
            boolean value();
        }
    }

}
