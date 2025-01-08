package io.helidon.json.tests;

import java.util.ArrayList;
import java.util.List;

import io.helidon.json.binding.Json;

@Json.AsJson
public class ClassWithGenerics<T> {

    private T field;
    private List<T> collection = new ArrayList<>();
    private List<? extends SimpleClass> collection2 = new ArrayList<>();
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
