package com.internal.auth.feature.signingkey.controller;

import com.internal.auth.common.response.InternalAuthApiResponse;

import com.internal.auth.common.constant.AppConstant;
import com.internal.auth.common.util.RateLimiterService;
import com.internal.auth.config.auth.Roles;
import com.internal.auth.feature.signingkey.dto.SigningKeyResponse;
import com.internal.auth.feature.signingkey.model.SigningKey;
import com.internal.auth.feature.signingkey.service.SigningKeyService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.util.List;

/**
 * Step 14D: admin-only JWT signing-key rotation.
 */
@RequiredArgsConstructor
@RestController
@RequestMapping("${app.title}")
@Tag(name = "Signing Key Admin API", description = "Step 14D: admin-only JWT signing-key rotation")
public class SigningKeyController {

    private final SigningKeyService signingKeyService;
    private final RateLimiterService rateLimiterService;

    /**
     * Generates a new RSA signing key, makes it the one new tokens are
     * signed with, and keeps the previous key valid for verification for
     * AppConstant.SIGNING_KEY_GRACE_PERIOD_DAYS before it's retired - so
     * tokens already handed out don't immediately break the moment this
     * runs. Admin-only and rate-limited the same way session-invalidate is
     * (Step 14C): already access-controlled, this is abuse-prevention
     * against repeatedly triggering a rotation, not brute-force defense.
     */
    @Operation(method = "POST", summary = "Rotate signing key", description = "Generates a new JWT signing key and makes it current. The previous key stays valid for verification during the grace period.")
    @PreAuthorize(Roles.HAS_ADMIN)
    @PostMapping("/admin/signing-keys/rotate")
    public ResponseEntity<InternalAuthApiResponse<SigningKeyResponse>> rotate(HttpServletRequest httpRequest) {
        rateLimiterService.checkRateLimit(AppConstant.SIGNING_KEY_ROTATE_RATE_LIMIT_KEY_PREFIX + httpRequest.getRemoteAddr(), AppConstant.MAX_SIGNING_KEY_ROTATE_REQUEST, Duration.ofDays(AppConstant.SIGNING_KEY_ROTATE_RATE_LIMIT_DURATION_DAYS));
        SigningKey newKey = signingKeyService.rotate();
        SigningKeyResponse response = new SigningKeyResponse(newKey.getKid(), newKey.getStatus().name(), newKey.isCurrent(), newKey.getCreatedAt(), newKey.getRetiredAt());
        return ResponseEntity.ok(InternalAuthApiResponse.success("Signing key rotated successfully.", response));
    }

    /**
     * Step 11A (React Admin Client plan v4): the plan's own Step 2's
     * "Already built, no work needed" list only names the rotate endpoint
     * above - nothing upstream exposed the current key (or its history) a
     * real Settings panel needs to show before a rotate. Purely additive,
     * same reasoning as Step 2H's password-reset endpoints: reuses
     * SigningKeyResponse as-is, no existing endpoint or DTO touched.
     */
    @Operation(method = "GET", summary = "List signing keys", description = "Admin-only audit list of every signing key this server has ever minted, newest first.")
    @PreAuthorize(Roles.HAS_ADMIN)
    @GetMapping("/admin/signing-keys")
    public ResponseEntity<InternalAuthApiResponse<List<SigningKeyResponse>>> list() {
        List<SigningKeyResponse> response = signingKeyService.listKeys().stream()
                .map(key -> new SigningKeyResponse(key.getKid(), key.getStatus().name(), key.isCurrent(), key.getCreatedAt(), key.getRetiredAt()))
                .toList();
        return ResponseEntity.ok(InternalAuthApiResponse.success(response));
    }
}
