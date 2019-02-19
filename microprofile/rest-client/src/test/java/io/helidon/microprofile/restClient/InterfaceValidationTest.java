package io.helidon.microprofile.restClient;

import org.junit.jupiter.api.Test;

/**
 * @author David Kral
 */
public class InterfaceValidationTest {

    @Test
    public void testValidInterface() {
        InterfaceUtil.validateInterface(CorrectInterface.class);
    }

}
