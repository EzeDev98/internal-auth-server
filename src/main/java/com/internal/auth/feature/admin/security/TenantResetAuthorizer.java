package com.internal.auth.feature.admin.security;

import com.internal.auth.common.exception.BadRequestException;
import com.internal.auth.common.exception.InvalidResetSecretException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Guards the per-tenant destructive data wipe, mirroring SyncPoint's own
 * ResetAuthorizer pattern (secret + confirmation phrase, both required),
 * plus the one field that pattern didn't need: which tenant to wipe.
 * <ul>
 *   <li><b>Secret.</b> The caller must present {@code X-Reset-Secret}
 *       matching {@code admin.reset.secret}. A blank/unset property disables
 *       the endpoint entirely. Constant-time comparison.</li>
 *   <li><b>appId.</b> Required - identifies which ClientApplication's data
 *       to wipe. Never defaulted or inferred.</li>
 *   <li><b>Confirmation phrase.</b> The body must carry the exact phrase, so
 *       a call holding only the secret cannot fire by accident or replay.</li>
 * </ul>
 */
@Slf4j
@Component
public class TenantResetAuthorizer {

    private static final String REQUIRED_CONFIRMATION = "WIPE-EVERYTHING";

    private final String configuredSecret;

    public TenantResetAuthorizer(@Value("${admin.reset.secret:}") String configuredSecret) {
        this.configuredSecret = configuredSecret;
    }

    /**
     * @param providedSecret value of the {@code X-Reset-Secret} header
     * @param appId          the clientId to wipe, from the request body
     * @param confirmation   confirmation phrase from the request body
     * @throws InvalidResetSecretException if the endpoint is disabled or the secret is missing/invalid
     * @throws BadRequestException         if appId or the confirmation phrase is missing/incorrect
     */
    public void authorize(String providedSecret, String appId, String confirmation) {
        if (configuredSecret == null || configuredSecret.isBlank()) {
            log.warn("[TenantReset] Rejected — endpoint disabled (no admin.reset.secret configured)");
            throw new InvalidResetSecretException("Tenant reset endpoint is disabled. Set admin.reset.secret to enable it.");
        }

        if (!secretMatches(providedSecret)) {
            log.warn("[TenantReset] Rejected — missing or invalid X-Reset-Secret");
            throw new InvalidResetSecretException("Invalid or missing reset secret.");
        }

        if (appId == null || appId.isBlank()) {
            log.warn("[TenantReset] Rejected — missing appId");
            throw new BadRequestException("appId is required.");
        }

        if (!REQUIRED_CONFIRMATION.equals(confirmation)) {
            log.warn("[TenantReset] Rejected — confirmation phrase missing or incorrect for appId={}", appId);
            throw new BadRequestException("Confirmation required: send {\"confirmation\": \"" + REQUIRED_CONFIRMATION + "\"} in the body.");
        }
    }

    private boolean secretMatches(String providedSecret) {
        if (providedSecret == null) {
            return false;
        }
        byte[] expected = configuredSecret.getBytes(StandardCharsets.UTF_8);
        byte[] actual = providedSecret.getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(expected, actual);
    }
}
