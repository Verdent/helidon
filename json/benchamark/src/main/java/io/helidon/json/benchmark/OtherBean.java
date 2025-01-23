package io.helidon.json.benchmark;

import io.helidon.json.binding.Json;

@Json.Entity
public class OtherBean {

    private String otherString;

    public OtherBean() {
    }

    public OtherBean(String otherString) {
        this.otherString = otherString;
    }

    public String getOtherString() {
        return otherString;
    }

    public void setOtherString(String otherString) {
        this.otherString = otherString;
    }

    @Override
    public String toString() {
        return "OtherBean{" +
                "otherString='" + otherString + '\'' +
                '}';
    }
}
