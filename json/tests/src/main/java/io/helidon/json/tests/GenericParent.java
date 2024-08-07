package io.helidon.json.tests;

import java.util.List;

public class GenericParent<T> {

    public T myTestField;
    public List<T> myTestFieldList;

    public T getMyTestField() {
        return myTestField;
    }

    public void setMyTestField(T myTestField) {
        this.myTestField = myTestField;
    }

}
