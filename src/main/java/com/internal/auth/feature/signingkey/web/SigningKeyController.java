package com.internal.auth.feature.signingkey.web;

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
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;

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
    public ResponseEntity<SigningKeyResponse> rotate(HttpServletRequest httpRequest) {
        rateLimiterService.checkRateLimit(AppConstant.SIGNING_KEY_ROTATE_RATE_LIMIT_KEY_PREFIX + httpRequest.getRemoteAddr(), AppConstant.MAX_SIGNING_KEY_ROTATE_REQUEST, Duration.ofDays(AppConstant.SIGNING_KEY_ROTATE_RATE_LIMIT_DURATION_DAYS));
        SigningKey newKey = signingKeyService.rotate();
        return ResponseEntity.ok(new SigningKeyResponse(newKey.getKid(), newKey.getStatus().name(), newKey.isCurrent(), newKey.getCreatedAt()));
    }
}
