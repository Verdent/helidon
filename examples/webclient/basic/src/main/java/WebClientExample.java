import java.util.Collections;
import java.util.concurrent.ExecutionException;

import javax.json.Json;
import javax.json.JsonBuilderFactory;
import javax.json.JsonObject;

import io.helidon.config.Config;
import io.helidon.webclient.WebClient;

/**
 * TODO Javadoc
 */
public class WebClientExample {

    private static final JsonBuilderFactory JSON_BUILDER = Json.createBuilderFactory(Collections.emptyMap());
    private static final JsonObject JSON_NEW_GREETING;

    static {
        JSON_NEW_GREETING = JSON_BUILDER.createObjectBuilder()
                .add("greeting", "Hola")
                .build();
    }

    private static String url;

    public static void main(String[] args) throws ExecutionException, InterruptedException {
        if (args.length == 0) {
            url = "http://localhost:" + Main.DEFAULT_PORT + "/greet";
        } else {
            url = "http://localhost:" + Integer.parseInt(args[0]) + "/greet";
        }

        Config config = Config.create();
        WebClient webClient = WebClient.builder()
                .baseUri(url)
                .config(config)
                .build();

        performPutMethod(webClient);
        performGetMethod(webClient);
        followRedirects(webClient);
        getResponseAsAnJsonObject(webClient);
        saveResponseToFile(webClient);
        registerClientMetric(webClient);
    }

    static void performPutMethod(WebClient webClient) throws ExecutionException, InterruptedException {
        System.out.println("Put request execution.");
        webClient.put()
                .path("/greeting")
                .submit(JSON_NEW_GREETING)
                .whenComplete((aVoid, throwable) -> {
                    if (throwable == null) {
                        System.out.println("Greeting update request successfully executed.");
                    }
                })
                .toCompletableFuture()
                .get();
    }

    static void performGetMethod(WebClient webClient) throws ExecutionException, InterruptedException {
        webClient.get()
                .request(String.class)
                .thenAccept(System.out::println)
                .toCompletableFuture()
                .get();
    }

    static void followRedirects(WebClient webClient) throws ExecutionException, InterruptedException {
        System.out.println("Following request redirection.");
        webClient.get()
                .path("/redirect")
                .request(String.class)
                .whenComplete((aVoid, throwable) -> {
                    if (throwable == null) {
                        System.out.println("Greeting update request successfully executed.");
                    }
                })
                .toCompletableFuture()
                .get();
    }

    static void getResponseAsAnJsonObject(WebClient webClient) throws ExecutionException, InterruptedException {
        webClient.get()
                .request(JsonObject.class)
                .thenAccept(System.out::println)
                .toCompletableFuture()
                .get();
    }

    static void saveResponseToFile(WebClient webClient) throws ExecutionException, InterruptedException {

    }

    static void registerClientMetric(WebClient webClient) throws ExecutionException, InterruptedException {

    }
}
