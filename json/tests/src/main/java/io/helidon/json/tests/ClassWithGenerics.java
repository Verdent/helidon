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

package io.helidon.json.tests;

import java.util.ArrayList;
import java.util.List;

import io.helidon.json.binding.Json;

@Json.Entity
public class ClassWithGenerics<T> {

    private T field;
    private List<T> collection = new ArrayList<>();
    private List<List<T>> collection2 = new ArrayList<>();
    public ClassWithGenerics<T> test;
    private List<? extends SimpleClass> collection23 = new ArrayList<>();
    //widlcard
    //upper/lower bounds
    private int myInt;

    public T getField() {
        return field;
    }

    public void setField(T field) {
        this.field = field;
    }

    public List<T> getCollection() {
        return collection;
    }

    public void setCollection(List<T> collection) {
        this.collection = collection;
    }

    public List<List<T>> getCollection2() {
        return collection2;
    }

    public void setCollection2(List<List<T>> collection2) {
        this.collection2 = collection2;
    }

    public int getMyInt() {
        return myInt;
    }

    public void setMyInt(int myInt) {
        this.myInt = myInt;
    }

    @Override
    public String toString() {
        return "ClassWithGenerics{" +
                "field=" + field +
                ", collection=" + collection +
                ", myInt=" + myInt +
                '}';
    }
}
