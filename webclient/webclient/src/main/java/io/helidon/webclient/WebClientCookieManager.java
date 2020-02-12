package io.helidon.webclient;

import java.io.IOException;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.CookieStore;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import io.helidon.common.http.Http;

/**
 * Helidon web client cookie manager.
 */
class WebClientCookieManager extends CookieManager {

    private final boolean acceptCookies;
    private final Map<String, String> defaultCookies;

    private WebClientCookieManager(CookiePolicy cookiePolicy,
                                   CookieStore cookieStore,
                                   Map<String, String> defaultCookies,
                                   boolean acceptCookies) {
        super(cookieStore, cookiePolicy);
        this.defaultCookies = Collections.unmodifiableMap(defaultCookies);
        this.acceptCookies = acceptCookies;
    }

    static WebClientCookieManager create(CookiePolicy cookiePolicy,
                                         CookieStore cookieStore,
                                         Map<String, String> defaultCookies,
                                         boolean acceptCookies) {
        return new WebClientCookieManager(cookiePolicy, cookieStore, defaultCookies, acceptCookies);
    }

    @Override
    public Map<String, List<String>> get(URI uri, Map<String, List<String>> requestHeaders) throws IOException {
        Map<String, List<String>> toReturn = new HashMap<>();
        addAllDefaultHeaders(toReturn);
        if (acceptCookies) {
            Map<String, List<String>> cookies = super.get(uri, requestHeaders);
            cookies.get(Http.Header.COOKIE).forEach(s -> toReturn.get(Http.Header.COOKIE).add(s));
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
