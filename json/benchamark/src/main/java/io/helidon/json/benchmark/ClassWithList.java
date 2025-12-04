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

package io.helidon.json.benchmark;

import java.util.ArrayList;
import java.util.List;

import io.helidon.json.binding.Json;

@Json.Entity
public class ClassWithList {

    private List<Integer> list = new ArrayList<>();
    private List<List<Integer>> list2 = new ArrayList<>();

    public List<Integer> getList() {
        return list;
    }

    public void setList(List<Integer> list) {
        this.list = list;
    }

    public List<List<Integer>> getList2() {
        return list2;
    }

    public void setList2(List<List<Integer>> list2) {
        this.list2 = list2;
    }

    @Override
    public String toString() {
        return "ClassWithList{" +
                "list=" + list +
                ", list2=" + list2 +
                '}';
    }
}
