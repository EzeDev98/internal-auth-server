package com.internal.auth.feature.admin.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.util.StreamUtils;
import org.springframework.web.client.RestClient;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/** Calls the downstream apps' admin wipe endpoints during a full wipe. */
@Slf4j
@Component
public class DownstreamAppWipeClient {

    private static final String SYNC_POINT_CONFIRMATION = "WIPE-EVERYTHING";
    private static final String AHORRA_CONFIRMATION = "WIPE-EVERYTHING";

    private final RestClient syncPointClient;
    private final RestClient notareClient;
    private final RestClient ahorraClient;
    private final String syncPointSecret;
    private final String notareSecret;
    private final String ahorraSecret;
    private final ObjectMapper objectMapper;

    public DownstreamAppWipeClient(
            @Value("${sync-point.wipe.base-url}") String syncPointBaseUrl,
            @Value("${sync-point.wipe.secret:}") String syncPointSecret,
            @Value("${notare.wipe.base-url}") String notareBaseUrl,
            @Value("${notare.wipe.secret:}") String notareSecret,
            @Value("${ahorra.wipe.base-url}") String ahorraBaseUrl,
            @Value("${ahorra.wipe.secret:}") String ahorraSecret) {
        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setConnectTimeout(10_000);
        requestFactory.setReadTimeout(60_000);

        this.syncPointClient = RestClient.builder().baseUrl(syncPointBaseUrl).requestFactory(requestFactory).build();
        this.notareClient = RestClient.builder().baseUrl(notareBaseUrl).requestFactory(requestFactory).build();
        this.ahorraClient = RestClient.builder().baseUrl(ahorraBaseUrl).requestFactory(requestFactory).build();
        this.syncPointSecret = syncPointSecret;
        this.notareSecret = notareSecret;
        this.ahorraSecret = ahorraSecret;
        this.objectMapper = new ObjectMapper();
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> wipeSyncPoint(boolean includeSystemWallet) {
        if (syncPointSecret == null || syncPointSecret.isBlank()) {
            throw new DownstreamWipeException("sync-point.wipe.secret is not configured - refusing to call SyncPoint's wipe endpoint.");
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("confirmation", SYNC_POINT_CONFIRMATION);
        body.put("includeSystemWallet", includeSystemWallet);

        try {
            JsonNode response = syncPointClient.post()
                    .uri("/admin/reset/wipe")
                    .header("X-Reset-Secret", syncPointSecret)
                    .body(body)
                    .retrieve()
                    .onStatus(HttpStatusCode::isError, (req, res) -> {
                        throw new DownstreamWipeException("SyncPoint wipe failed: " + extractMessage(res));
                    })
                    .body(JsonNode.class);
            JsonNode data = response != null ? response.get("data") : null;
            return data != null ? objectMapper.convertValue(data, Map.class) : Map.of();
        } catch (DownstreamWipeException e) {
            throw e;
        } catch (Exception e) {
            log.error("[WipeAll] SyncPoint wipe call failed", e);
            throw new DownstreamWipeException("Could not reach SyncPoint: " + e.getMessage());
        }
    }

    public void wipeNotare() {
        if (notareSecret == null || notareSecret.isBlank()) {
            throw new DownstreamWipeException("notare.wipe.secret is not configured - refusing to call Notare's wipe endpoint.");
        }
        try {
            notareClient.post()
                    .uri("/admin/database/wipe")
                    .header("X-Admin-Secret", notareSecret)
                    .retrieve()
                    .onStatus(HttpStatusCode::isError, (req, res) -> {
                        throw new DownstreamWipeException("Notare wipe failed: " + extractMessage(res));
                    })
                    .toBodilessEntity();
        } catch (DownstreamWipeException e) {
            throw e;
        } catch (Exception e) {
            log.error("[WipeAll] Notare wipe call failed", e);
            throw new DownstreamWipeException("Could not reach Notare: " + e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> wipeAhorra() {
        if (ahorraSecret == null || ahorraSecret.isBlank()) {
            throw new DownstreamWipeException("ahorra.wipe.secret is not configured - refusing to call Ahorra's wipe endpoint.");
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("confirmation", AHORRA_CONFIRMATION);

        try {
            JsonNode response = ahorraClient.post()
                    .uri("/admin/reset/wipe")
                    .header("X-Reset-Secret", ahorraSecret)
                    .body(body)
                    .retrieve()
                    .onStatus(HttpStatusCode::isError, (req, res) -> {
                        throw new DownstreamWipeException("Ahorra wipe failed: " + extractMessage(res));
                    })
                    .body(JsonNode.class);
            JsonNode data = response != null ? response.get("data") : null;
            return data != null ? objectMapper.convertValue(data, Map.class) : Map.of();
        } catch (DownstreamWipeException e) {
            throw e;
        } catch (Exception e) {
            log.error("[WipeAll] Ahorra wipe call failed", e);
            throw new DownstreamWipeException("Could not reach Ahorra: " + e.getMessage());
        }
    }

    private String extractMessage(ClientHttpResponse response) {
        try {
            String raw = StreamUtils.copyToString(response.getBody(), StandardCharsets.UTF_8);
            if (raw.isBlank()) {
                return "HTTP " + response.getStatusCode().value();
            }
            try {
                JsonNode parsed = objectMapper.readTree(raw);
                if (parsed.has("message") && !parsed.get("message").isNull()) {
                    return parsed.get("message").asText();
                }
            } catch (Exception ignored) {
            }
            return raw;
        } catch (Exception e) {
            return "HTTP " + safeStatus(response) + " (could not read response body)";
        }
    }

    private int safeStatus(ClientHttpResponse response) {
        try {
            return response.getStatusCode().value();
        } catch (Exception e) {
            return -1;
        }
    }
}
