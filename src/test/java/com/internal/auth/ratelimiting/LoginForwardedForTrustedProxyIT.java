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
 * Step 15B (trusted-proxy half): server.forward-headers-strategy=native
 * activates Tomcat's RemoteIpValve, which rewrites getRemoteAddr() from
 * X-Forwarded-For - but only for a request whose immediate TCP peer
 * matches server.tomcat.remoteip.internal-proxies. This class leaves that
 * property unset, so Tomcat's own built-in default regex applies (covers
 * loopback among other RFC1918 ranges - see application.properties' own
 * comment on this), and every request here genuinely does arrive from
 * loopback (java.net.http.HttpClient connecting to localhost), so this is
 * a real trusted-proxy scenario, not a simulated one.
 *
 * <p>Needs a real running embedded server, not MockMvc - Step 15A
 * confirmed MockMvc dispatches directly against the DispatcherServlet and
 * never actually passes through Tomcat's connector/valve pipeline, so
 * RemoteIpValve simply never runs for a MockMvc-driven request regardless
 * of this property.
 *
 * <p>Runs on its own dedicated port (8082, distinct from the shared
 * default context's 8080 and from LoginForwardedForUntrustedProxyIT's
 * 8083): IntegrationTestBase uses webEnvironment=DEFINED_PORT, and adding
 * a class-level @DynamicPropertySource here (needed for
 * forward-headers-strategy) makes Spring Test cache a separate
 * ApplicationContext for this class rather than reusing the shared
 * default one - Spring's context cache can keep multiple contexts alive
 * at once, and two contexts both trying to bind the embedded server to
 * the same fixed port would conflict at test-run time. This class never
 * mints or validates a JWT, so - unlike the shared default context - it
 * doesn't need app.self-issuer-uri/app.token-issuer-uri to match this
 * port.
 */
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

        // AppConstant.MAX_LOGIN_REQUEST is 10. No real client credentials
        // are sent, so each request gets 401 until the IP bucket for
        // forwardedA trips - proving RemoteIpValve is genuinely rewriting
        // getRemoteAddr() from the header (a fresh, randomized address
        // never used by any other test), not just passing every request
        // through as the one real loopback peer they all share.
        for (int i = 0; i < 10; i++) {
            assertThat(attemptLogin(forwardedA)).isEqualTo(401);
        }
        assertThat(attemptLogin(forwardedA)).isEqualTo(429);

        // A completely different forwarded address is unaffected -
        // confirms the bucket is keyed per forwarded address, not shared
        // across every request from this trusted peer.
        assertThat(attemptLogin(forwardedB)).isEqualTo(401);
    }
}
