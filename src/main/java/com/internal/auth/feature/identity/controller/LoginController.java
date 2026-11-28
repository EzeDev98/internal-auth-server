package com.internal.auth.feature.identity.controller;

import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.service.ClientApplicationService;
import com.internal.auth.common.constant.AppConstant;
import com.internal.auth.common.util.RateLimiterService;
import com.internal.auth.feature.identity.dto.request.ChangePasswordRequest;
import com.internal.auth.feature.identity.dto.request.LoginRequest;
import com.internal.auth.feature.passwordreset.service.PasswordChangeService;
import com.internal.auth.common.exception.BadRequestException;
import com.internal.auth.feature.identity.dto.request.RefreshTokenRequest;
import com.internal.auth.feature.identity.dto.request.SessionStatusRequest;
import com.internal.auth.feature.session.dto.SessionStatusResponse;
import com.internal.auth.feature.session.service.SessionManagementService;
import com.internal.auth.feature.identity.dto.response.LoginResponse;
import com.internal.auth.feature.identity.service.UserLoginService;
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

/** Endpoints for login, token refresh, session status and password change. */
@RestController
@RequestMapping("${app.title}/auth")
@Tag(name = "Login API", description = "Local credential authentication")
@RequiredArgsConstructor
public class LoginController {

    private final UserLoginService loginService;
    private final ClientApplicationService clientApplicationService;
    private final RateLimiterService rateLimiterService;
    private final SessionManagementService sessionManagementService;
    private final PasswordChangeService passwordChangeService;

    @PostMapping("/change-password")
    public ResponseEntity<InternalAuthApiResponse<Void>> changePassword(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorizationHeader,
            @RequestBody ChangePasswordRequest request,
            HttpServletRequest httpRequest) {
        rateLimiterService.checkRateLimit(AppConstant.LOGIN_RATE_LIMIT_KEY_PREFIX + httpRequest.getRemoteAddr(), AppConstant.MAX_LOGIN_REQUEST, Duration.ofMinutes(AppConstant.LOGIN_RATE_LIMIT_DURATION_MINUTES));
        ClientApplication client = clientApplicationService.authenticateClientFromBasicAuthHeader(authorizationHeader);
        if (isBlank(request.getUsername()) || isBlank(request.getCurrentPassword()) || isBlank(request.getNewPassword())) {
            throw new BadRequestException("username, currentPassword and newPassword are required");
        }
        checkAccountRateLimit(client.getId(), request.getUsername());
        passwordChangeService.changePassword(client.getId(), request);
        return ResponseEntity.ok(InternalAuthApiResponse.<Void>success("Password changed", null));
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    @PostMapping("/login")
    public ResponseEntity<InternalAuthApiResponse<LoginResponse>> login(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorizationHeader,
            @RequestBody LoginRequest request,
            HttpServletRequest httpRequest) {
        rateLimiterService.checkRateLimit(AppConstant.LOGIN_RATE_LIMIT_KEY_PREFIX + httpRequest.getRemoteAddr(), AppConstant.MAX_LOGIN_REQUEST, Duration.ofMinutes(AppConstant.LOGIN_RATE_LIMIT_DURATION_MINUTES));
        ClientApplication client = clientApplicationService.authenticateClientFromBasicAuthHeader(authorizationHeader);
        checkAccountRateLimit(client.getId(), request.getUsername());
        LoginResponse response = loginService.login(request, client.getId(), httpRequest.getRemoteAddr(), deviceUserAgent(request, httpRequest));
        return ResponseEntity.ok(InternalAuthApiResponse.success(response.getMessage(), response));
    }

    private void checkAccountRateLimit(Long clientApplicationId, String username) {
        if (username == null || username.isBlank()) {
            return;
        }
        String key = AppConstant.LOGIN_ACCOUNT_RATE_LIMIT_KEY_PREFIX + clientApplicationId + ":" + username.trim();
        rateLimiterService.checkRateLimit(key, AppConstant.MAX_LOGIN_ACCOUNT_REQUEST,
                Duration.ofMinutes(AppConstant.LOGIN_ACCOUNT_RATE_LIMIT_DURATION_MINUTES));
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<InternalAuthApiResponse<LoginResponse>> refreshToken(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorizationHeader,
            @RequestBody RefreshTokenRequest request,
            HttpServletRequest httpRequest) {
        rateLimiterService.checkRateLimit(AppConstant.REFRESH_TOKEN_RATE_LIMIT_KEY_PREFIX + httpRequest.getRemoteAddr(), AppConstant.MAX_REFRESH_TOKEN_REQUEST, Duration.ofMinutes(AppConstant.REFRESH_TOKEN_RATE_LIMIT_DURATION_MINUTES));
        ClientApplication client = clientApplicationService.authenticateClientFromBasicAuthHeader(authorizationHeader);
        LoginResponse response = loginService.refreshToken(request, client.getId());
        return ResponseEntity.ok(InternalAuthApiResponse.success(response.getMessage(), response));
    }

    @PostMapping("/session-status")
    public ResponseEntity<InternalAuthApiResponse<SessionStatusResponse>> sessionStatus(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorizationHeader,
            @RequestBody SessionStatusRequest request,
            HttpServletRequest httpRequest) {
        rateLimiterService.checkRateLimit(AppConstant.SESSION_STATUS_RATE_LIMIT_KEY_PREFIX + httpRequest.getRemoteAddr(), AppConstant.MAX_SESSION_STATUS_REQUEST, Duration.ofHours(AppConstant.SESSION_STATUS_RATE_LIMIT_DURATION_HOURS));
        ClientApplication client = clientApplicationService.authenticateClientFromBasicAuthHeader(authorizationHeader);
        if (request.getUsername() == null || request.getUsername().isBlank()) {
            throw new BadRequestException("username is required");
        }
        boolean active = sessionManagementService.hasLiveRefreshToken(request.getUsername().trim(), client.getId());
        return ResponseEntity.ok(InternalAuthApiResponse.success("Session status", new SessionStatusResponse(active)));
    }

    private static String deviceUserAgent(LoginRequest request, HttpServletRequest httpRequest) {
        String forwarded = request.getUserAgent();
        return forwarded != null && !forwarded.isBlank() ? forwarded : httpRequest.getHeader(HttpHeaders.USER_AGENT);
    }
}
