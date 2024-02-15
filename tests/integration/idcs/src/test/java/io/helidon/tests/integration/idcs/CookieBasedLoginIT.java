/*
 * Copyright (c) 2024 Oracle and/or its affiliates.
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

package io.helidon.tests.integration.idcs;

import jakarta.ws.rs.client.WebTarget;
import org.junit.jupiter.api.Test;
import org.openqa.selenium.By;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.ExpectedConditions;

import static io.helidon.tests.integration.idcs.TestResource.EXPECTED_POST_LOGOUT_TEST_MESSAGE;
import static io.helidon.tests.integration.idcs.TestResource.EXPECTED_TEST_MESSAGE;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

class CookieBasedLoginIT extends CommonLoginBase {

    @Test
    public void testSuccessfulLogin() {
        WebElement body = browser.findElement(By.tagName("body"));
        assertThat(body.getText(), is(EXPECTED_TEST_MESSAGE));
    }

    @Test
    public void testLoginWithValidRole(WebTarget webTarget) {
        browser.get(webTarget.getUri().toString() + "/test/secret-endpoint");
        WebElement body = wait.until(ExpectedConditions.visibilityOfElementLocated(By.tagName("body")));
        assertThat(body.getText(), is("secret endpoint hit"));
    }

    @Test
    public void testLoginWithInvalidRole(WebTarget webTarget) {
        browser.get(webTarget.getUri().toString() + "/test/invalid-role-endpoint");
        WebElement body = wait.until(ExpectedConditions.visibilityOfElementLocated(By.tagName("body")));
        assertThat(body.getText(), is(""));
    }

    @Test
    public void testLogoutFunctionality(WebTarget webTarget) {
        browser.get(webTarget.getUri().toString() + "/oidc/logout");
        wait.until(driver -> driver.getTitle().contains("Cloud")); //IDCS logout endpoint reached
        wait.until(driver -> driver.getTitle().isEmpty()); //Redirected back to our test application
        WebElement body = browser.findElement(By.tagName("body"));
        assertThat(body.getText(), is(EXPECTED_POST_LOGOUT_TEST_MESSAGE));
    }
}
