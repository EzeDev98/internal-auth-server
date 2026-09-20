package com.internal.auth.feature.session.client;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.Map;

/**
 * Pushes an admin's "Logout all sessions" action straight to SyncPoint the
 * moment it happens, instead of leaving SyncPoint to find out only when it
 * next pulls POST /auth/session-status on the user's next login attempt
 * (WalletAuthServiceImpl#walletLogin -> SyncPoint's SessionManagementServiceImpl
 * #hasActiveSession). That pull check stays in place as-is - it is the
 * fallback for exactly the case this push fails to reach SyncPoint (down,
 * unreachable, misconfigured secret).
 * <p>
 * Same outbound-call shape as DownstreamAppWipeClient (admin/client
 * package): a dedicated secret header, fail-closed when the secret is
 * unset, generous read timeout for Render's free-tier cold starts. Unlike
 * the wipe client this is deliberately best-effort - by the time this is
 * called, invalidateUserSessionByAdmin has already deleted this user's
 * oauth2_authorization rows in THIS app, so a stuck or unreachable
 * SyncPoint must never stop the admin's own console action from
 * completing. Every failure is caught and logged here, never rethrown.
 */
@Slf4j
@Component
public class SyncPointSessionClient {

    private final RestClient restClient;
    private final String secret;

    public SyncPointSessionClient(
            @Value("${sync-point.session-invalidate.base-url}") String baseUrl,
            @Value("${sync-point.session-invalidate.secret:}") String secret) {
        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setConnectTimeout(10_000);
        requestFactory.setReadTimeout(60_000);

        this.restClient = RestClient.builder().baseUrl(baseUrl).requestFactory(requestFactory).build();
        this.secret = secret;
    }

    /**
     * Fire-and-forget: never throws. Logs and returns if the secret isn't
     * configured (feature stays off until sync-point.session-invalidate.secret
     * is set on both sides) or if the call itself fails for any reason.
     */
    public void notifySessionInvalidated(String username) {
        if (secret == null || secret.isBlank()) {
            log.warn("[SessionPush] sync-point.session-invalidate.secret not configured - skipping push to SyncPoint for {}", username);
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
            log.info("[SessionPush] Pushed session invalidation to SyncPoint for {}", username);
        } catch (Exception e) {
            log.warn("[SessionPush] Could not push session invalidation to SyncPoint for {}: {}", username, e.getMessage());
        }
    }
}
