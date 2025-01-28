/*
 * Copyright (c) 2016, 2022 Oracle and/or its affiliates. All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0,
 * or the Eclipse Distribution License v. 1.0 which is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 */

package io.helidon.json.tests;

import io.helidon.json.binding.Json;
import io.helidon.json.binding.JsonBinding;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;

/**
 * Tests serialization and deserialization of boolean values.
 *
 * @author Ehsan Zaery Moghaddam (zaerymoghaddam@gmail.com)
 */
public class BooleanTest {

    @Test
    public void testBooleanSerialization() throws Exception {
        BooleanModel booleanModel = new BooleanModel(true, false);

        String expected = "{\"field1\":true,\"field2\":false}";
        assertThat(JsonBinding.serialize(booleanModel), is(expected));
    }

    @Test
    public void testBooleanDeserializationFromBooleanAsStringValue() throws Exception {
        BooleanModel booleanModel = JsonBinding.deserialize("{\"field1\":\"true\",\"field2\":\"true\"}", BooleanModel.class);
        assertThat(booleanModel.field1, is(true));
        assertThat(booleanModel.field2, is(true));
    }

    @Test
    public void testBooleanDeserializationFromBooleanRawValue() throws Exception {
        BooleanModel booleanModel = JsonBinding.deserialize("{\"field1\":false,\"field2\":false}", BooleanModel.class);
        assertThat(booleanModel.field1, is(false));
        assertThat(booleanModel.field2, is(false));
    }

    @Test
    public void testRawBooleans() {
        Boolean bool = JsonBinding.deserialize("true", Boolean.class);
        assertThat(bool, is(true));
        bool = JsonBinding.deserialize("true", boolean.class);
        assertThat(bool, is(true));
        bool = JsonBinding.deserialize("false", Boolean.class);
        assertThat(bool, is(false));
        bool = JsonBinding.deserialize("false", boolean.class);
        assertThat(bool, is(false));
        bool = JsonBinding.deserialize("null", Boolean.class);
        assertThat(bool, nullValue());
        bool = JsonBinding.deserialize("null", boolean.class);
        assertThat(bool, is(false));

        String result = JsonBinding.serialize(true);
        assertThat(result, is("true"));
        result = JsonBinding.serialize(false);
        assertThat(result, is("false"));
    }

//    @Test
//    public void testBooleanArrays() {
//        assertArrayEquals(new boolean[] {true, false}, defaultJsonb.fromJson("[true, false]", boolean[].class));
//        assertArrayEquals(new Boolean[] {true, false}, defaultJsonb.fromJson("[true, false]", Boolean[].class));
//
//        assertEquals("[true,false]", defaultJsonb.toJson(new boolean[] {true, false}));
//        assertEquals("[true,false]", defaultJsonb.toJson(new Boolean[] {true, false}));
//    }

    @Json.Entity
    public static class BooleanModel {
        public Boolean field1;
        public boolean field2;

        public BooleanModel() {
        }

        public BooleanModel(boolean field1, Boolean field2) {
            this.field2 = field2;
            this.field1 = field1;
        }
    }
}
