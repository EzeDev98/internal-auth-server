package com.internal.auth.feature.passwordreset.controller;

import com.internal.auth.common.response.InternalAuthApiResponse;

import com.internal.auth.common.reset.dto.VerifyOtpRequest;
import com.internal.auth.common.reset.dto.VerifyOtpResponse;
import com.internal.auth.common.util.RateLimiterService;
import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.service.ClientApplicationService;
import com.internal.auth.feature.passwordreset.dto.request.CompletePasswordResetRequest;
import com.internal.auth.feature.passwordreset.dto.request.PasswordResetRequest;
import com.internal.auth.feature.passwordreset.dto.request.EmailPasswordResetRequest;
import com.internal.auth.feature.passwordreset.dto.request.EmailVerifyOtpRequest;
import com.internal.auth.feature.passwordreset.dto.response.PasswordResetResponse;
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

/** Endpoints for resetting and changing passwords. */
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
            @RequestBody PasswordResetRequest request) {
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
        rateLimiterService.checkRateLimit(VERIFY_OTP_RATE_LIMIT_KEY_PREFIX + client.getId() + ":" + request.getPhoneNumber(), MAX_VERIFY_OTP_REQUEST, Duration.ofHours(VERIFY_OTP_RATE_LIMIT_DURATION_HOURS));
        VerifyOtpResponse response = passwordResetService.verifyOtp(request, client.getId());
        return ResponseEntity.ok(InternalAuthApiResponse.success("OTP verified successfully.", response));
    }

    @PostMapping("/complete")
    public ResponseEntity<InternalAuthApiResponse<PasswordResetResponse>> completeReset(@RequestBody CompletePasswordResetRequest request, HttpServletRequest httpRequest) {
        rateLimiterService.checkRateLimit(COMPLETE_RESET_RATE_LIMIT_KEY_PREFIX + httpRequest.getRemoteAddr(), MAX_COMPLETE_RESET_REQUEST, Duration.ofHours(COMPLETE_RESET_RATE_LIMIT_DURATION_HOURS));
        PasswordResetResponse response = passwordResetService.completeReset(request);
        return ResponseEntity.ok(InternalAuthApiResponse.success(response.getMessage(), response));
    }

    @PostMapping("/email/request")
    public ResponseEntity<InternalAuthApiResponse<PasswordResetResponse>> requestEmailOtp(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorizationHeader,
            @RequestBody EmailPasswordResetRequest request) {
        ClientApplication client = clientApplicationService.authenticateClientFromBasicAuthHeader(authorizationHeader);
        rateLimiterService.checkRateLimit("ratelimit:password-reset-otp:email:" + client.getId() + ":" + request.getEmail(), MAX_RESET_PASSWORD_REQUEST, Duration.ofHours(RESET_PASSWORD_RATE_LIMIT_DURATION));
        PasswordResetResponse response = passwordResetService.requestEmailOtp(request, client.getId());
        return ResponseEntity.ok(InternalAuthApiResponse.success(response.getMessage(), response));
    }

    @PostMapping("/email/verify-otp")
    public ResponseEntity<InternalAuthApiResponse<VerifyOtpResponse>> verifyEmailOtp(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorizationHeader,
            @RequestBody EmailVerifyOtpRequest request) {
        ClientApplication client = clientApplicationService.authenticateClientFromBasicAuthHeader(authorizationHeader);
        rateLimiterService.checkRateLimit(VERIFY_OTP_RATE_LIMIT_KEY_PREFIX + client.getId() + ":" + request.getEmail(), MAX_VERIFY_OTP_REQUEST, Duration.ofHours(VERIFY_OTP_RATE_LIMIT_DURATION_HOURS));
        VerifyOtpResponse response = passwordResetService.verifyEmailOtp(request, client.getId());
        return ResponseEntity.ok(InternalAuthApiResponse.success("OTP verified successfully.", response));
    }
}
