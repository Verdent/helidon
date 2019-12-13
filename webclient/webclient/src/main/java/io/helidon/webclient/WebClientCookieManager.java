package io.helidon.webclient;

import java.io.IOException;
import java.net.CookieManager;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import io.helidon.common.http.Http;

/**
 * TODO Javadoc
 */
public class WebClientCookieManager extends CookieManager {

    private final boolean acceptCookies;
    private final Map<String, String> defaultCookies;

    private WebClientCookieManager(Map<String, String> defaultCookies, boolean acceptCookies) {
        this.defaultCookies = Collections.unmodifiableMap(defaultCookies);
        this.acceptCookies = acceptCookies;
    }

    static WebClientCookieManager create(Map<String, String> defaultCookies, boolean acceptCookies) {
        return new WebClientCookieManager(defaultCookies, acceptCookies);
    }

    @Override
    public Map<String, List<String>> get(URI uri, Map<String, List<String>> requestHeaders) throws IOException {
        Map<String, List<String>> toReturn = new HashMap<>();
        addAllDefaultHeaders(toReturn);
        if (acceptCookies) {
            super.get(uri, requestHeaders).get(Http.Header.COOKIE).forEach(s -> toReturn.get(Http.Header.COOKIE).add(s));
            //TODO Co kdyz tam budou 2 stringy cookie se stejným ID? nahrazovat ci nechat na serveru, který si vybere?
        }
        return Collections.unmodifiableMap(toReturn);
    }

    private void addAllDefaultHeaders(Map<String, List<String>> toReturn) {
        List<String> defaultCookieList = new ArrayList<>();
        defaultCookies.forEach((key, value) -> defaultCookieList.add(key + "=" + value));
        toReturn.put(Http.Header.COOKIE, defaultCookieList);
    }

    @Override
    public void put(URI uri, Map<String, List<String>> responseHeaders) throws IOException {
        if (acceptCookies) {
            super.put(uri, responseHeaders);
        }
    }

    Map<String, String> defaultCookies() {
        return defaultCookies;
    }
}
