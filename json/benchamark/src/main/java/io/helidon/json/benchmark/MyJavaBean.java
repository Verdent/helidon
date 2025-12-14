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

import io.helidon.json.binding.Json;

import com.fasterxml.jackson.annotation.JsonClassDescription;
import com.dslplatform.json.CompiledJson;

/**
 * TODO javadoc
 */
@Json.Entity
@JsonClassDescription
@CompiledJson
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
