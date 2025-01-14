package io.helidon.json.tests;

import java.util.ArrayList;
import java.util.List;

import io.helidon.json.binding.Json;

@Json.AsJson
public class ClassWithGenerics<T> {

    private T field;
    private List<T> collection = new ArrayList<>();
    private List<List<T>> collection2 = new ArrayList<>();
//    public ClassWithGenerics<T> test;
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
