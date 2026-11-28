package com.internal.auth.feature.session.client;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.Map;

/** Notifies Ahorra when an admin logs out all of a user's sessions. */
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
