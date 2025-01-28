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
