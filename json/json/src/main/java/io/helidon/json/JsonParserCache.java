package io.helidon.json;

public final class JsonParserCache {

    private static final ThreadLocal<CachedParser> parserCache = ThreadLocal.withInitial(CachedParser::new);

    public static CachedParser getCachedParser() {
        return parserCache.get();
    }

}
