package com.internal.auth.feature.identity.client;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.Map;

/**
 * Pushes user lifecycle changes made in the IAM admin console (deleted,
 * disabled, re-enabled) to notare, so notare's local user row never
 * drifts from IAM (the source of truth).
 * <p>
 * Same shape as SyncPointSessionClient: secret header, skipped when the
 * secret is blank, best-effort - never throws, because the admin's own
 * action has already been committed in IAM by the time this runs.
 * Login-time sync in notare is the fallback if a push is missed.
 */
@Slf4j
@Component
public class NotareUserEventClient {

    public enum Event { DELETED, DISABLED, ENABLED }

    private final RestClient restClient;
    private final String secret;
    private final String notareClientId;

    public NotareUserEventClient(
            @Value("${notare.user-events.base-url}") String baseUrl,
            @Value("${notare.user-events.secret:}") String secret,
            @Value("${notare.internal-auth-client-id:notare}") String notareClientId) {
        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setConnectTimeout(10_000);
        requestFactory.setReadTimeout(60_000);
        this.restClient = RestClient.builder().baseUrl(baseUrl).requestFactory(requestFactory).build();
        this.secret = secret;
        this.notareClientId = notareClientId;
    }

    /** True only for users that belong to the notare tenant. */
    public boolean isNotareTenant(String clientId) {
        return notareClientId.equals(clientId);
    }

    public void notifyUserEvent(String internalAuthUserId, Event event) {
        if (secret == null || secret.isBlank()) {
            log.warn("[NotareUserEvent] notare.user-events.secret not configured - skipping {} push for {}", event, internalAuthUserId);
            return;
        }
        try {
            restClient.post()
                    .uri("/internal/user-events")
                    .header("X-Internal-Secret", secret)
                    .body(Map.of("internalAuthUserId", internalAuthUserId, "event", event.name()))
                    .retrieve()
                    .onStatus(HttpStatusCode::isError, (req, res) -> {
                        throw new IllegalStateException("HTTP " + res.getStatusCode().value());
                    })
                    .toBodilessEntity();
            log.info("[NotareUserEvent] Pushed {} to notare for {}", event, internalAuthUserId);
        } catch (Exception e) {
            log.warn("[NotareUserEvent] Could not push {} to notare for {}: {}", event, internalAuthUserId, e.getMessage());
        }
    }
}
