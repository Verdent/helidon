package io.helidon.json.benchmark;

import io.helidon.json.binding.Json;

import com.fasterxml.jackson.annotation.JsonClassDescription;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * TODO javadoc
 */
@Json.Entity
@JsonClassDescription
public class MyJavaBean {

    private String fieldOne;
    private int fieldTwo;
    private String fieldThree;
    private String fieldFour;
    private String fieldFive;
    private long fieldSix;
    private OtherBean otherBean;

    public MyJavaBean() {
    }

    public String getFieldOne() {
        return fieldOne;
    }

    public void setFieldOne(String fieldOne) {
        this.fieldOne = fieldOne;
    }

    public int getFieldTwo() {
        return fieldTwo;
    }

    public void setFieldTwo(int fieldTwo) {
        this.fieldTwo = fieldTwo;
    }

    public String getFieldThree() {
        return fieldThree;
    }

    public void setFieldThree(String fieldThree) {
        this.fieldThree = fieldThree;
    }

    public String getFieldFour() {
        return fieldFour;
    }

    public void setFieldFour(String fieldFour) {
        this.fieldFour = fieldFour;
    }

    public String getFieldFive() {
        return fieldFive;
    }

    public void setFieldFive(String fieldFive) {
        this.fieldFive = fieldFive;
    }

    public long getFieldSix() {
        return fieldSix;
    }

    public void setFieldSix(long fieldSix) {
        this.fieldSix = fieldSix;
    }

    public OtherBean getOtherBean() {
        return otherBean;
    }

    public void setOtherBean(OtherBean otherBean) {
        this.otherBean = otherBean;
    }

    @Override
    public String toString() {
        return "MyJavaBean{" +
                "fieldOne='" + fieldOne + '\'' +
                ", fieldTwo=" + fieldTwo +
                ", fieldThree='" + fieldThree + '\'' +
                ", fieldFour='" + fieldFour + '\'' +
                ", fieldFive='" + fieldFive + '\'' +
                ", otherBean=" + otherBean +
                '}';
    }
}
