package io.helidon.microprofile.restClient;

/**
 * Created by David Kral.
 */
public class ReflectionUtil {

    public static <T> T createInstance(Class<T> tClass) {
        try {
            return tClass.newInstance();
        } catch (Throwable t) {
            throw new RuntimeException("No default constructor in class " + tClass + " present. Class cannot be created!", t);
        }
    }

}
