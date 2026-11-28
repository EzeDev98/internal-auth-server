package com.internal.auth.feature.identity.controller;

import com.internal.auth.common.response.InternalAuthApiResponse;

import com.internal.auth.common.constant.AppConstant;
import com.internal.auth.common.reset.dto.VerifyOtpRequest;
import com.internal.auth.common.reset.dto.VerifyOtpResponse;
import com.internal.auth.common.util.RateLimiterService;
import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.service.ClientApplicationService;
import com.internal.auth.feature.identity.dto.request.AdminRegisterRequest;
import com.internal.auth.feature.identity.dto.response.AdminRegisterResponse;
import com.internal.auth.feature.identity.dto.request.LoginRequest;
import com.internal.auth.feature.identity.dto.response.LoginResponse;
import com.internal.auth.feature.identity.dto.request.RefreshTokenRequest;
import com.internal.auth.feature.identity.service.AdminRegistrationService;
import com.internal.auth.feature.identity.service.UserLoginService;
import com.internal.auth.feature.passwordreset.dto.request.PasswordResetRequest;
import com.internal.auth.feature.passwordreset.dto.response.PasswordResetResponse;
import com.internal.auth.feature.passwordreset.service.PasswordResetService;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;

import static com.internal.auth.common.constant.AppConstant.MAX_RESET_PASSWORD_REQUEST;
import static com.internal.auth.common.constant.AppConstant.MAX_VERIFY_OTP_REQUEST;
import static com.internal.auth.common.constant.AppConstant.RESET_PASSWORD_RATE_LIMIT_DURATION;
import static com.internal.auth.common.constant.AppConstant.VERIFY_OTP_RATE_LIMIT_DURATION_HOURS;
import static com.internal.auth.common.constant.AppConstant.VERIFY_OTP_RATE_LIMIT_KEY_PREFIX;

/** Endpoints for bootstrapping the first admin and admin sign-in. */
@RestController
@RequestMapping("${app.title}/admin")
@Tag(name = "Admin API", description = "Admin bootstrap registration and admin sign-in")
@RequiredArgsConstructor
public class AdminController {

    private final AdminRegistrationService adminRegistrationService;
    private final UserLoginService loginService;
    private final ClientApplicationService clientApplicationService;
    private final RateLimiterService rateLimiterService;
    private final PasswordResetService passwordResetService;

    @PostMapping("/register")
    public ResponseEntity<InternalAuthApiResponse<AdminRegisterResponse>> register(@RequestBody AdminRegisterRequest request) {
        ClientApplication adminClient = clientApplicationService.getOrCreateInternalAdminClient();
        AdminRegisterResponse response = adminRegistrationService.register(request, adminClient.getId());
        return ResponseEntity.status(HttpStatus.CREATED).body(InternalAuthApiResponse.success(response.getMessage(), response));
    }

    @PostMapping("/login")
    public ResponseEntity<InternalAuthApiResponse<LoginResponse>> login(@RequestBody LoginRequest request, HttpServletRequest httpRequest) {
        rateLimiterService.checkRateLimit(AppConstant.LOGIN_RATE_LIMIT_KEY_PREFIX + "admin:" + httpRequest.getRemoteAddr(),
                AppConstant.MAX_LOGIN_REQUEST, Duration.ofMinutes(AppConstant.LOGIN_RATE_LIMIT_DURATION_MINUTES));
        ClientApplication adminClient = clientApplicationService.getOrCreateInternalAdminClient();
        LoginResponse response = loginService.login(request, adminClient.getId(), httpRequest.getRemoteAddr(), httpRequest.getHeader("User-Agent"));
        return ResponseEntity.ok(InternalAuthApiResponse.success(response.getMessage(), response));
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<InternalAuthApiResponse<LoginResponse>> refreshToken(@RequestBody RefreshTokenRequest request, HttpServletRequest httpRequest) {
        rateLimiterService.checkRateLimit(AppConstant.REFRESH_TOKEN_RATE_LIMIT_KEY_PREFIX + "admin:" + httpRequest.getRemoteAddr(),
                AppConstant.MAX_REFRESH_TOKEN_REQUEST, Duration.ofMinutes(AppConstant.REFRESH_TOKEN_RATE_LIMIT_DURATION_MINUTES));
        ClientApplication adminClient = clientApplicationService.getOrCreateInternalAdminClient();
        LoginResponse response = loginService.refreshToken(request, adminClient.getId());
        return ResponseEntity.ok(InternalAuthApiResponse.success(response.getMessage(), response));
    }

    @PostMapping("/password-reset/request")
    public ResponseEntity<InternalAuthApiResponse<PasswordResetResponse>> requestPasswordResetOtp(@RequestBody PasswordResetRequest request) {
        rateLimiterService.checkRateLimit("ratelimit:password-reset-otp:phone:admin:" + request.getPhoneNumber(),
                MAX_RESET_PASSWORD_REQUEST, Duration.ofHours(RESET_PASSWORD_RATE_LIMIT_DURATION));
        ClientApplication adminClient = clientApplicationService.getOrCreateInternalAdminClient();
        PasswordResetResponse response = passwordResetService.requestOtp(request, adminClient.getId());
        return ResponseEntity.ok(InternalAuthApiResponse.success(response.getMessage(), response));
    }

    @PostMapping("/password-reset/verify-otp")
    public ResponseEntity<InternalAuthApiResponse<VerifyOtpResponse>> verifyPasswordResetOtp(@RequestBody VerifyOtpRequest request) {
        rateLimiterService.checkRateLimit(VERIFY_OTP_RATE_LIMIT_KEY_PREFIX + "admin:" + request.getPhoneNumber(),
                MAX_VERIFY_OTP_REQUEST, Duration.ofHours(VERIFY_OTP_RATE_LIMIT_DURATION_HOURS));
        ClientApplication adminClient = clientApplicationService.getOrCreateInternalAdminClient();
        VerifyOtpResponse response = passwordResetService.verifyOtp(request, adminClient.getId());
        return ResponseEntity.ok(InternalAuthApiResponse.success("OTP verified successfully.", response));
    }
}
