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

/**
 * Step 15B (untrusted-proxy half): the contrasting case to
 * LoginForwardedForTrustedProxyIT. Here
 * server.tomcat.remoteip.internal-proxies is overridden to a regex that
 * never matches loopback, so from RemoteIpValve's perspective this test's
 * real peer (java.net.http.HttpClient connecting to localhost, same as
 * every other IT in this suite) is NOT a trusted proxy - X-Forwarded-For
 * must be ignored entirely, and getRemoteAddr() stays the real peer
 * address no matter what the header claims.
 *
 * <p>Own dedicated port (8083) for the same context-caching /
 * fixed-port-conflict reason as LoginForwardedForTrustedProxyIT - see its
 * class Javadoc.
 *
 * <p>Unlike that class (which fakes a fresh, randomized forwarded address
 * per test run, never touched by anything else), this class's real
 * rate-limit bucket key is the literal loopback peer address - the same
 * one MockMvc's default remote address happens to resemble, which every
 * other MockMvc-driven login test in this suite has already been hitting
 * all session. So this test does not assume a clean slate: it drives the
 * bucket to a tripped state first, however many calls that actually
 * takes, rather than asserting an exact count.
 */
class LoginForwardedForUntrustedProxyIT extends IntegrationTestBase {

    private static final int PORT = 8083;
    private static final HttpClient HTTP_CLIENT = HttpClient.newHttpClient();

    @DynamicPropertySource
    static void forwardedHeadersProperties(DynamicPropertyRegistry registry) {
        registry.add("server.port", () -> PORT);
        registry.add("server.forward-headers-strategy", () -> "native");
        // Deliberately excludes loopback - a regex that matches no real
        // peer address this test will ever actually connect from.
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
        // Drive the real (loopback) bucket into a tripped state, using a
        // different X-Forwarded-For value on every attempt throughout -
        // if the header were honored even once, none of these would ever
        // trip anything, since each looks like a fresh address.
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

        // The core assertion: a brand-new, never-before-used forwarded
        // address, still from the same untrusted real peer, does NOT get
        // a fresh bucket. If the header were honored, this would look
        // like a never-seen address and get 401; since it's ignored, this
        // is really just one more request against the same
        // already-tripped real bucket.
        String neverBeforeUsedForwardedAddress = "198.51.100." + (200 + (Math.abs(UUID.randomUUID().hashCode()) % 50));
        assertThat(attemptLogin(neverBeforeUsedForwardedAddress)).isEqualTo(429);
    }
}
