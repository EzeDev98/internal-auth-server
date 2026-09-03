package com.internal.auth.feature.passwordreset.web;

import com.internal.auth.common.reset.dto.VerifyOtpRequest;
import com.internal.auth.common.reset.dto.VerifyOtpResponse;
import com.internal.auth.common.util.RateLimiterService;
import com.internal.auth.feature.passwordreset.dto.CompletePasswordResetRequest;
import com.internal.auth.feature.passwordreset.dto.PasswordResetRequestDto;
import com.internal.auth.feature.passwordreset.dto.PasswordResetResponse;
import com.internal.auth.feature.passwordreset.service.PasswordResetService;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;

import static com.internal.auth.common.constant.AppConstant.COMPLETE_RESET_RATE_LIMIT_DURATION_HOURS;
import static com.internal.auth.common.constant.AppConstant.COMPLETE_RESET_RATE_LIMIT_KEY_PREFIX;
import static com.internal.auth.common.constant.AppConstant.MAX_COMPLETE_RESET_REQUEST;
import static com.internal.auth.common.constant.AppConstant.MAX_RESET_PASSWORD_REQUEST;
import static com.internal.auth.common.constant.AppConstant.MAX_VERIFY_OTP_REQUEST;
import static com.internal.auth.common.constant.AppConstant.RESET_PASSWORD_RATE_LIMIT_DURATION;
import static com.internal.auth.common.constant.AppConstant.VERIFY_OTP_RATE_LIMIT_DURATION_HOURS;
import static com.internal.auth.common.constant.AppConstant.VERIFY_OTP_RATE_LIMIT_KEY_PREFIX;


@RestController
@RequestMapping("${app.title}/password-reset")
@Tag(name = "Password Reset API", description = "Phone-number OTP based password reset flow")
public class PasswordResetController {

    private final PasswordResetService passwordResetService;
    private final RateLimiterService rateLimiterService;

    public PasswordResetController(PasswordResetService passwordResetService, RateLimiterService rateLimiterService) {
        this.passwordResetService = passwordResetService;
        this.rateLimiterService = rateLimiterService;
    }

    @PostMapping("/request")
    public ResponseEntity<PasswordResetResponse> requestOtp(@RequestBody PasswordResetRequestDto request) {
        rateLimiterService.checkRateLimit("ratelimit:password-reset-otp:phone:" + request.getPhoneNumber(), MAX_RESET_PASSWORD_REQUEST, Duration.ofHours(RESET_PASSWORD_RATE_LIMIT_DURATION));
        return ResponseEntity.ok(passwordResetService.requestOtp(request));
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<VerifyOtpResponse> verifyOtp(@RequestBody VerifyOtpRequest request) {
        // Step 11F: guards against the per-OTP attemptCount getting reset by
        // simply requesting a fresh OTP every cooldown window — this caps
        // total guess attempts per phone number independently of how many
        // OTPs were issued.
        rateLimiterService.checkRateLimit(VERIFY_OTP_RATE_LIMIT_KEY_PREFIX + request.getPhoneNumber(), MAX_VERIFY_OTP_REQUEST, Duration.ofHours(VERIFY_OTP_RATE_LIMIT_DURATION_HOURS));
        return ResponseEntity.ok(passwordResetService.verifyOtp(request));
    }

    @PostMapping("/complete")
    public ResponseEntity<PasswordResetResponse> completeReset(@RequestBody CompletePasswordResetRequest request, HttpServletRequest httpRequest) {
        // Step 11F: CompletePasswordResetRequest carries no phone number, and
        // the reset token itself is a 256-bit random value that can't
        // realistically be brute-forced, so this is generic abuse/DoS
        // protection keyed by client IP rather than a guessing defense.
        rateLimiterService.checkRateLimit(COMPLETE_RESET_RATE_LIMIT_KEY_PREFIX + httpRequest.getRemoteAddr(), MAX_COMPLETE_RESET_REQUEST, Duration.ofHours(COMPLETE_RESET_RATE_LIMIT_DURATION_HOURS));
        return ResponseEntity.ok(passwordResetService.completeReset(request));
    }
}
