package com.internal.auth.feature.session.client;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.Map;

/**
 * Pushes an admin's "Logout all sessions" action straight to Ahorra the
 * moment it happens, instead of leaving Ahorra to find out only on its
 * next hasActiveSession pull. A dedicated secret header, fail-closed
 * when the secret is unset, generous read timeout for Render's
 * free-tier cold starts, and deliberately best-effort: every failure
 * is caught and logged here, never rethrown, since the admin's own
 * console action must complete regardless of whether Ahorra is
 * reachable.
 */
@Slf4j
@Component
public class AhorraSessionClient {

    private final RestClient restClient;
    private final String secret;

    public AhorraSessionClient(
            @Value("${ahorra.session-invalidate.base-url}") String baseUrl,
            @Value("${ahorra.session-invalidate.secret:}") String secret) {
        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setConnectTimeout(10_000);
        requestFactory.setReadTimeout(60_000);

        this.restClient = RestClient.builder().baseUrl(baseUrl).requestFactory(requestFactory).build();
        this.secret = secret;
    }

    /**
     * Fire-and-forget: never throws. Logs and returns if the secret isn't
     * configured (feature stays off until ahorra.session-invalidate.secret
     * is set on both sides) or if the call itself fails for any reason.
     */
    public void notifySessionInvalidated(String username) {
        if (secret == null || secret.isBlank()) {
            log.warn("[SessionPush] ahorra.session-invalidate.secret not configured - skipping push to Ahorra for {}", username);
            return;
        }
        try {
            restClient.post()
                    .uri("/admin/sessions/invalidate-by-username")
                    .header("X-Admin-Secret", secret)
                    .body(Map.of("username", username))
                    .retrieve()
                    .onStatus(HttpStatusCode::isError, (req, res) -> {
                        throw new IllegalStateException("HTTP " + res.getStatusCode().value());
                    })
                    .toBodilessEntity();
            log.info("[SessionPush] Pushed session invalidation to Ahorra for {}", username);
        } catch (Exception e) {
            log.warn("[SessionPush] Could not push session invalidation to Ahorra for {}: {}", username, e.getMessage());
        }
    }
}
