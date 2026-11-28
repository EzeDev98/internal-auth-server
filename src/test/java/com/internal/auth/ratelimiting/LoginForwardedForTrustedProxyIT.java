package com.internal.auth.ratelimiting;

import com.internal.auth.testsupport.IntegrationTestBase;
import org.junit.jupiter.api.Test;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/** Verifies login rate limiting uses X-Forwarded-For behind a trusted proxy. */
class LoginForwardedForTrustedProxyIT extends IntegrationTestBase {

    private static final int PORT = 8082;
    private static final HttpClient HTTP_CLIENT = HttpClient.newHttpClient();

    @DynamicPropertySource
    static void forwardedHeadersProperties(DynamicPropertyRegistry registry) {
        registry.add("server.port", () -> PORT);
        registry.add("server.forward-headers-strategy", () -> "native");
    }

    private int attemptLogin(String forwardedFor) throws Exception {
        String body = "{\"username\":\"placeholder\",\"password\":\"placeholder\"}";
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + PORT + "/api/v1/auth/login"))
                .header("Content-Type", "application/json")
                .header("X-Forwarded-For", forwardedFor)
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        return HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofString()).statusCode();
    }

    @Test
    void forwardedForHeader_fromTheTrustedLoopbackPeer_scopesTheIpRateLimitPerForwardedAddress() throws Exception {
        String forwardedA = "203.0.113." + (1 + (Math.abs(UUID.randomUUID().hashCode()) % 250));
        String forwardedB = "203.0.113." + (1 + (Math.abs(UUID.randomUUID().hashCode()) % 250));

        for (int i = 0; i < 10; i++) {
            assertThat(attemptLogin(forwardedA)).isEqualTo(401);
        }
        assertThat(attemptLogin(forwardedA)).isEqualTo(429);

        assertThat(attemptLogin(forwardedB)).isEqualTo(401);
    }
}
