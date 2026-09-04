package com.internal.auth.feature.identity.controller;

import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.service.ClientApplicationService;
import com.internal.auth.feature.identity.dto.LoginRequest;
import com.internal.auth.feature.identity.dto.LoginResponse;
import com.internal.auth.feature.identity.dto.VerifyLoginOtpRequest;
import com.internal.auth.feature.identity.service.LoginService;
import com.internal.auth.common.constant.AppConstant;
import com.internal.auth.common.util.RateLimiterService;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.internal.auth.common.response.InternalAuthApiResponse;
import jakarta.servlet.http.HttpServletRequest;

import java.time.Duration;

/**
 * Step 11A/11E. Mapped under the "${app.title}" property, same base as
 * RegistrationController - see that class's javadoc for why this reverted
 * from a hardcoded "/api/v1/auth" literal back to the property (API-contract
 * review, step 1): WebSecurityConfig now builds its own permitAll() matcher
 * paths from the same "app.title" property, so the two can't drift apart
 * regardless of representation.
 *
 * Multi-tenant redesign: both "/login" and "/login/verify-otp" now
 * require the same HTTP Basic client-credential header
 * RegistrationController resolves (see its Javadoc for the full
 * rationale) - "/login/verify-otp"'s login-MFA OTP lookup is scoped by
 * client_application_id now too (see LoginServiceImpl's class Javadoc).
 */
@RestController
@RequestMapping("${app.title}/auth")
@Tag(name = "Login API", description = "Local credential authentication with optional MFA step-up (Stage 3/4 Steps 11A/11E)")
@RequiredArgsConstructor
public class LoginController {

    private final LoginService loginService;
    private final ClientApplicationService clientApplicationService;
    private final RateLimiterService rateLimiterService;

    @PostMapping("/login")
    public ResponseEntity<InternalAuthApiResponse<LoginResponse>> login(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorizationHeader,
            @RequestBody LoginRequest request,
            HttpServletRequest httpRequest) {
        rateLimiterService.checkRateLimit(AppConstant.LOGIN_RATE_LIMIT_KEY_PREFIX + httpRequest.getRemoteAddr(), AppConstant.MAX_LOGIN_REQUEST, Duration.ofMinutes(AppConstant.LOGIN_RATE_LIMIT_DURATION_MINUTES));
        ClientApplication client = clientApplicationService.authenticateClientFromBasicAuthHeader(authorizationHeader);
        LoginResponse response = loginService.login(request, client.getId());
        return ResponseEntity.ok(InternalAuthApiResponse.success(response.getMessage(), response));
    }

    @PostMapping("/login/verify-otp")
    public ResponseEntity<InternalAuthApiResponse<LoginResponse>> verifyLoginOtp(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorizationHeader,
            @RequestBody VerifyLoginOtpRequest request,
            HttpServletRequest httpRequest) {
        rateLimiterService.checkRateLimit(AppConstant.LOGIN_OTP_VERIFY_RATE_LIMIT_KEY_PREFIX + httpRequest.getRemoteAddr(), AppConstant.MAX_LOGIN_OTP_VERIFY_REQUEST, Duration.ofMinutes(AppConstant.LOGIN_OTP_VERIFY_RATE_LIMIT_DURATION_MINUTES));
        ClientApplication client = clientApplicationService.authenticateClientFromBasicAuthHeader(authorizationHeader);
        LoginResponse response = loginService.verifyLoginOtp(request, client.getId());
        return ResponseEntity.ok(InternalAuthApiResponse.success(response.getMessage(), response));
    }
}
