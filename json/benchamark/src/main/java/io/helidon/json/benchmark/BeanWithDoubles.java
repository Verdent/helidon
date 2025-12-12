package io.helidon.json.benchmark;

import io.helidon.json.binding.Json;

@Json.Entity
public final class BeanWithDoubles {
    private double one;
    private double two;
    private double three;

    public double getOne() {
        return one;
    }

    public void setOne(double one) {
        this.one = one;
    }

    public double getTwo() {
        return two;
    }

    public void setTwo(double two) {
        this.two = two;
    }

    public double getThree() {
        return three;
    }

    public void setThree(double three) {
        this.three = three;
    }

    @Override
    public String toString() {
        return "RecordWithDoubles[" +
                "one=" + one + ", " +
                "two=" + two + ", " +
                "three=" + three + ']';
    }

}
