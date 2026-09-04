package com.internal.auth.feature.passwordreset.controller;

import com.internal.auth.common.response.InternalAuthApiResponse;

import com.internal.auth.common.reset.dto.VerifyOtpRequest;
import com.internal.auth.common.reset.dto.VerifyOtpResponse;
import com.internal.auth.common.util.RateLimiterService;
import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.service.ClientApplicationService;
import com.internal.auth.feature.passwordreset.dto.CompletePasswordResetRequest;
import com.internal.auth.feature.passwordreset.dto.PasswordResetRequestDto;
import com.internal.auth.feature.passwordreset.dto.PasswordResetResponse;
import com.internal.auth.feature.passwordreset.service.PasswordResetService;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
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


/**
 * Mapped under the "${app.title}" property, same as every other controller
 * in the app. API-contract review (step 1): this was briefly pinned to the
 * literal "/api/v1/password-reset" because WebSecurityConfig's permitAll()
 * matchers didn't yet cover the "${app.title}" form for these paths - that
 * was the wrong fix for the underlying problem. WebSecurityConfig now reads
 * the same "app.title" property to build its own matcher paths, so this
 * controller and its security rule move together no matter which
 * representation either side uses.
 *
 * Multi-tenant redesign, OTP/token flows step: "/request" and
 * "/verify-otp" now require the same HTTP Basic client-credential header
 * RegistrationController/LoginController resolve (see
 * RegistrationController's Javadoc for the full rationale). Rate-limiter
 * keys are namespaced by the resolved client_application_id too - a bare
 * phone-number key would let one app's caller exhaust the rate limit for a
 * different app's user who happens to share that phone number.
 * "/complete" is untouched - it resolves everything from the reset
 * token's own hash, which was never ambiguous, so there's no caller
 * identity to resolve there.
 */
@RestController
@RequestMapping("${app.title}/password-reset")
@Tag(name = "Password Reset API", description = "Phone-number OTP based password reset flow")
public class PasswordResetController {

    private final PasswordResetService passwordResetService;
    private final RateLimiterService rateLimiterService;
    private final ClientApplicationService clientApplicationService;

    public PasswordResetController(PasswordResetService passwordResetService, RateLimiterService rateLimiterService, ClientApplicationService clientApplicationService) {
        this.passwordResetService = passwordResetService;
        this.rateLimiterService = rateLimiterService;
        this.clientApplicationService = clientApplicationService;
    }

    @PostMapping("/request")
    public ResponseEntity<InternalAuthApiResponse<PasswordResetResponse>> requestOtp(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorizationHeader,
            @RequestBody PasswordResetRequestDto request) {
        ClientApplication client = clientApplicationService.authenticateClientFromBasicAuthHeader(authorizationHeader);
        rateLimiterService.checkRateLimit("ratelimit:password-reset-otp:phone:" + client.getId() + ":" + request.getPhoneNumber(), MAX_RESET_PASSWORD_REQUEST, Duration.ofHours(RESET_PASSWORD_RATE_LIMIT_DURATION));
        PasswordResetResponse response = passwordResetService.requestOtp(request, client.getId());
        return ResponseEntity.ok(InternalAuthApiResponse.success(response.getMessage(), response));
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<InternalAuthApiResponse<VerifyOtpResponse>> verifyOtp(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorizationHeader,
            @RequestBody VerifyOtpRequest request) {
        ClientApplication client = clientApplicationService.authenticateClientFromBasicAuthHeader(authorizationHeader);
        // Step 11F: guards against the per-OTP attemptCount getting reset by
        // simply requesting a fresh OTP every cooldown window — this caps
        // total guess attempts per phone number independently of how many
        // OTPs were issued.
        rateLimiterService.checkRateLimit(VERIFY_OTP_RATE_LIMIT_KEY_PREFIX + client.getId() + ":" + request.getPhoneNumber(), MAX_VERIFY_OTP_REQUEST, Duration.ofHours(VERIFY_OTP_RATE_LIMIT_DURATION_HOURS));
        VerifyOtpResponse response = passwordResetService.verifyOtp(request, client.getId());
        return ResponseEntity.ok(InternalAuthApiResponse.success("OTP verified successfully.", response));
    }

    @PostMapping("/complete")
    public ResponseEntity<InternalAuthApiResponse<PasswordResetResponse>> completeReset(@RequestBody CompletePasswordResetRequest request, HttpServletRequest httpRequest) {
        // Step 11F: CompletePasswordResetRequest carries no phone number, and
        // the reset token itself is a 256-bit random value that can't
        // realistically be brute-forced, so this is generic abuse/DoS
        // protection keyed by client IP rather than a guessing defense.
        rateLimiterService.checkRateLimit(COMPLETE_RESET_RATE_LIMIT_KEY_PREFIX + httpRequest.getRemoteAddr(), MAX_COMPLETE_RESET_REQUEST, Duration.ofHours(COMPLETE_RESET_RATE_LIMIT_DURATION_HOURS));
        PasswordResetResponse response = passwordResetService.completeReset(request);
        return ResponseEntity.ok(InternalAuthApiResponse.success(response.getMessage(), response));
    }
}
