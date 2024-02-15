/*
 * Copyright (c) 2023, 2024 Oracle and/or its affiliates.
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

import java.time.Duration;
import java.util.Map;

import io.helidon.config.Config;
import io.helidon.jersey.connector.HelidonConnectorProvider;
import io.helidon.jersey.connector.HelidonProperties;
import io.helidon.microprofile.testing.junit5.AddBean;
import io.helidon.microprofile.testing.junit5.AddConfig;
import io.helidon.microprofile.testing.junit5.HelidonTest;

import io.github.bonigarcia.wdm.WebDriverManager;
import jakarta.json.Json;
import jakarta.json.JsonBuilderFactory;
import jakarta.json.JsonReaderFactory;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.WebTarget;
import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.client.ClientProperties;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.openqa.selenium.firefox.FirefoxOptions;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;

@HelidonTest(resetPerTest = true)
@AddBean(TestResource.class)
@AddConfig(key = "server.port", value = "6789")
class CommonLoginBase {

    static final JsonBuilderFactory JSON_OBJECT_BUILDER_FACTORY = Json.createBuilderFactory(Map.of());
    static final JsonReaderFactory JSON_READER_FACTORY = Json.createReaderFactory(Map.of());

    private static final Config HELIDON_CONFIG = Config.create();
    private static final Config SELENIUM_CONFIG = HELIDON_CONFIG.get("selenium");

    private static final ClientConfig CONFIG = new ClientConfig()
            .connectorProvider(new HelidonConnectorProvider())
            .property(ClientProperties.CONNECT_TIMEOUT, 10000000)
            .property(ClientProperties.READ_TIMEOUT, 10000000)
            .property(ClientProperties.FOLLOW_REDIRECTS, true)
            .property(HelidonProperties.CONFIG, HELIDON_CONFIG.get("client"));

    Client client;

    WebDriver browser;
    WebDriverWait wait;

    @BeforeAll
    public static void beforeAll() {
        WebDriverManager.chromedriver().setup();
    }

    @BeforeEach
    public void beforeEach(WebTarget webTarget) {
        client = ClientBuilder.newClient(CONFIG);
        ChromeOptions chromeOptions = new ChromeOptions();
        chromeOptions.addArguments("--no-sandbox");
        chromeOptions.addArguments("--disable-dev-shm-usage");
        if (SELENIUM_CONFIG.get("headless").asBoolean().orElse(false)) {
            chromeOptions.addArguments("--headless");
        }
        browser = new ChromeDriver(chromeOptions);
        Long timeout = SELENIUM_CONFIG.get("timeout").asLong().orElse(20L);
        wait = new WebDriverWait(browser, Duration.ofSeconds(timeout));

        performLogin(webTarget);
    }

    @AfterEach
    public void afterEach() {
        browser.quit();
        client.close();
    }

    void performLogin(WebTarget target) {
        browser.get(target.getUri().toString() + "/test");
        //Wait for iframe with cookies to load
        wait.until(ExpectedConditions.frameToBeAvailableAndSwitchToIt(By.className("truste_popframe")));

        //"Agree" to the cookies first
        WebElement acceptCookies = wait.until(ExpectedConditions.visibilityOfElementLocated(By.className("call")));
        acceptCookies.click();
        browser.switchTo().parentFrame(); //Return to the original page
        //Wait for iframe with cookies to hide
        wait.until(webDriver -> webDriver.findElements(By.tagName("iframe")).size() == 1);

        //Fill in login
        WebElement login = browser.findElement(By.id("idcs-signin-basic-signin-form-username"));
        String loginName = SELENIUM_CONFIG.get("oci-login").asString()
                .orElseThrow(() -> new IllegalStateException("OCI login needs to be set under the \"selenium.oci-login\""));
        login.sendKeys(loginName);

        //Fill in password
        WebElement password = browser.findElement(By.id("idcs-signin-basic-signin-form-password|input"));
        String passwordValue = SELENIUM_CONFIG.get("oci-password").asString()
                .orElseThrow(() -> new IllegalStateException("OCI password needs to be set under the \"selenium.oci-password\""));
        password.sendKeys(passwordValue);

        //Click on "Sign in" button
        WebElement submit = browser.findElement(By.id("ui-id-4")); //This targets "Sign in" label
        submit.click();

        //Wait for all redirects to finish. Our test page does have empty title.
        wait.until(webDriver -> webDriver.getTitle().isEmpty());
    }

    String getRequestUri(String html) {
        Document document = Jsoup.parse(html);
        return document.getElementById("kc-form-login").attr("action");
    }

}
