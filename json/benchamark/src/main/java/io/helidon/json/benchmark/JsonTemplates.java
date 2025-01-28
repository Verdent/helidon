package io.helidon.json.benchmark;

class JsonTemplates {

    static final String MY_JAVA_BEAN_WITH_OTHER_BEAN = "{\"fieldTwo\":2147,"
            + "\"fieldOne\":\"Hello\","
            + "\"fieldThree\":\"World\","
            + "\"fieldFour\":   null ,"
            + "\"fieldFive\":\"1234\", "
            + "\"otherBean\":{"
            + "\"otherString\":\"Hello there!\""
            + "}}";

    static final String CLASS_WITH_LIST = "{\"list\":[123, 321],"
            + "\"list2\":[[123456, 654321], [987456321, 123456789,123456789]]}";


}
