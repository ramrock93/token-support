package no.nav.security.token.support.demo.spring.mockwebserver;

import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

import javax.annotation.PreDestroy;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static org.springframework.http.HttpHeaders.CONTENT_TYPE;
import static org.springframework.http.MediaType.APPLICATION_JSON_UTF8_VALUE;

@Configuration
public class MockWebServerConfiguration {

    private static final String TOKEN_RESPONSE_TEMPLATE = "{\n" +
        "    \"token_type\": \"Bearer\",\n" +
        "    \"scope\": \"$scope\",\n" +
        "    \"expires_at\": $expires_at,\n" +
        "    \"ext_expires_in\": $ext_expires_in,\n" +
        "    \"expires_in\": $expires_in,\n" +
        "    \"access_token\": \"$access_token\"\n" +
        "}\n";

    private static final String DEFAULT_JSON_RESPONSE = "{\n" +
        "    \"ping\": \"pong\"\n" +
        "}\n";

    private static final String TOKEN_ENDPOINT_URI = "/oauth2/v2.0/token";
    private static final Logger log = LoggerFactory.getLogger(MockWebServerConfiguration.class);
    private final int port;
    private final MockWebServer server;

    public MockWebServerConfiguration(@Value("${mockwebserver.port}") int port) throws IOException {
        this.port = port;
        this.server = new MockWebServer();
        setup();
    }

    private void setup() throws IOException {
        this.server.start(port);
        this.server.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                log.info("received request on url={} with headers={}", request.getRequestUrl(), request.getHeaders());
                return mockResponse(request);
            }
        });
    }

    private MockResponse mockResponse(RecordedRequest request) {
        String body = request.getBody().readUtf8();
        if (isTokenRequest(request)) {
            Map<String, String> formParams = formParameters(body);
            log.info("form parameters decoded:" + formParams);
            return tokenResponse(formParams);
        } else {
            return new MockResponse()
                .setResponseCode(200)
                .setHeader(CONTENT_TYPE, APPLICATION_JSON_UTF8_VALUE)
                .setBody(DEFAULT_JSON_RESPONSE);
        }

    }

    private MockResponse tokenResponse(Map<String, String> formParams) {
        String response = TOKEN_RESPONSE_TEMPLATE
            .replace("$scope", formParams.get("scope"))
            .replace("$expires_at", "" + Instant.now().plusSeconds(3600).getEpochSecond())
            .replace("$ext_expires_in", "30")
            .replace("$expires_in", "30")
            .replace("$access_token", "somerandomaccesstoken");

        log.info("returning tokenResponse={}", response);
        return new MockResponse()
            .setResponseCode(200)
            .setHeader(CONTENT_TYPE, APPLICATION_JSON_UTF8_VALUE)
            .setBody(response);
    }

    @PreDestroy
    void shutdown() throws Exception {
        this.server.shutdown();
    }

    private boolean isTokenRequest(RecordedRequest request) {
        return request.getRequestUrl().toString().endsWith(TOKEN_ENDPOINT_URI) &&
            Optional.ofNullable(request.getHeader("Content-Type"))
                .filter(h -> h.contains("application/x-www-form-urlencoded"))
                .isPresent();
    }

    private Map<String, String> formParameters(String formUrlEncodedString) {
        return Arrays.stream(formUrlEncodedString.split("&"))
            .map(this::decode)
            .map(s -> s.split("="))
            .collect(Collectors.toMap(array -> array[0], array -> array[1]));
    }

    private String decode(String value) {
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8.toString());
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }
}
