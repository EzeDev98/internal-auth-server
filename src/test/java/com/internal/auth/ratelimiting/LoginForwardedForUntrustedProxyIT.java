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

/** Verifies login rate limiting ignores X-Forwarded-For from an untrusted proxy. */
class LoginForwardedForUntrustedProxyIT extends IntegrationTestBase {

    private static final int PORT = 8083;
    private static final HttpClient HTTP_CLIENT = HttpClient.newHttpClient();

    @DynamicPropertySource
    static void forwardedHeadersProperties(DynamicPropertyRegistry registry) {
        registry.add("server.port", () -> PORT);
        registry.add("server.forward-headers-strategy", () -> "native");
        registry.add("server.tomcat.remoteip.internal-proxies", () -> "10\\.99\\.99\\.99");
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
    void forwardedForHeader_fromAnUntrustedPeer_isIgnored_soASpoofedAddressNeverEvadesTheRealBucket() throws Exception {
        int statusCode = -1;
        int attempts = 0;
        while (statusCode != 429 && attempts < 20) {
            statusCode = attemptLogin("198.51.100." + (1 + attempts));
            attempts++;
        }
        assertThat(statusCode)
                .as("the real (loopback) IP bucket must trip within a bounded number of attempts, "
                        + "regardless of how many prior tests already touched it this run")
                .isEqualTo(429);

        String neverBeforeUsedForwardedAddress = "198.51.100." + (200 + (Math.abs(UUID.randomUUID().hashCode()) % 50));
        assertThat(attemptLogin(neverBeforeUsedForwardedAddress)).isEqualTo(429);
    }
}
