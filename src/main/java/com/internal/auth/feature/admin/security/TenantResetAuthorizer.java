package com.internal.auth.feature.admin.security;

import com.internal.auth.common.exception.BadRequestException;
import com.internal.auth.common.exception.InvalidResetSecretException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/** Validates the secret and confirmation required for a tenant wipe. */
@Slf4j
@Component
public class TenantResetAuthorizer {

    private static final String REQUIRED_CONFIRMATION = "WIPE-EVERYTHING";

    private final String configuredSecret;

    public TenantResetAuthorizer(@Value("${admin.reset.secret:}") String configuredSecret) {
        this.configuredSecret = configuredSecret;
    }

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

    public void authorizeWipeAll(String providedSecret, String confirmation) {
        if (configuredSecret == null || configuredSecret.isBlank()) {
            log.warn("[WipeAll] Rejected — endpoint disabled (no admin.reset.secret configured)");
            throw new InvalidResetSecretException("Wipe-all endpoint is disabled. Set admin.reset.secret to enable it.");
        }

        if (!secretMatches(providedSecret)) {
            log.warn("[WipeAll] Rejected — missing or invalid X-Reset-Secret");
            throw new InvalidResetSecretException("Invalid or missing reset secret.");
        }

        if (!REQUIRED_CONFIRMATION.equals(confirmation)) {
            log.warn("[WipeAll] Rejected — confirmation phrase missing or incorrect");
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
