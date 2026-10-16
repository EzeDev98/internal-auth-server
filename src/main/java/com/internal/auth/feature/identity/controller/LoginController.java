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
import com.internal.auth.feature.identity.dto.request.VerifyLoginOtpRequest;
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

    private final UserLoginService loginService;
    private final ClientApplicationService clientApplicationService;
    private final RateLimiterService rateLimiterService;
    private final SessionManagementService sessionManagementService;
    private final PasswordChangeService passwordChangeService;

    /**
     * Step 17g (B-02): a signed-in user changes their own password. The calling app proves who it is
     * with its Basic client credentials and names the user, as /session-status does. A wrong current
     * password is a 400 "Incorrect password.", never a 401 (callers read 401 as "session over"). The
     * user's session is not ended; see PasswordChangeService. The login's per-account rate limit
     * applies, so the current password cannot be guessed through this door either.
     */
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
        LoginResponse response = loginService.login(request, client.getId(), httpRequest.getRemoteAddr(), httpRequest.getHeader("User-Agent"));
        return ResponseEntity.ok(InternalAuthApiResponse.success(response.getMessage(), response));
    }

    /**
     * Step 4 (account-aware rate limiting): the IP-keyed check above stops a
     * single attacker hammering the endpoint from one address, but does
     * nothing against a distributed credential-stuffing attack that spreads
     * the same username's password guesses across many IPs - each IP stays
     * under its own limit while the account itself gets hit continuously.
     * Keyed by (client_application_id, username) rather than username
     * alone, matching the multi-tenant redesign - usernames are only
     * unique per-tenant, so two different tenants' accounts must not share
     * a lockout bucket. A blank/missing username is left to loginService's
     * own validation - nothing meaningful to key a per-account limit on yet.
     */
    private void checkAccountRateLimit(Long clientApplicationId, String username) {
        if (username == null || username.isBlank()) {
            return;
        }
        String key = AppConstant.LOGIN_ACCOUNT_RATE_LIMIT_KEY_PREFIX + clientApplicationId + ":" + username.trim();
        rateLimiterService.checkRateLimit(key, AppConstant.MAX_LOGIN_ACCOUNT_REQUEST,
                Duration.ofMinutes(AppConstant.LOGIN_ACCOUNT_RATE_LIMIT_DURATION_MINUTES));
    }

    @PostMapping("/login/verify-otp")
    public ResponseEntity<InternalAuthApiResponse<LoginResponse>> verifyLoginOtp(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorizationHeader,
            @RequestBody VerifyLoginOtpRequest request,
            HttpServletRequest httpRequest) {
        rateLimiterService.checkRateLimit(AppConstant.LOGIN_OTP_VERIFY_RATE_LIMIT_KEY_PREFIX + httpRequest.getRemoteAddr(), AppConstant.MAX_LOGIN_OTP_VERIFY_REQUEST, Duration.ofMinutes(AppConstant.LOGIN_OTP_VERIFY_RATE_LIMIT_DURATION_MINUTES));
        ClientApplication client = clientApplicationService.authenticateClientFromBasicAuthHeader(authorizationHeader);
        LoginResponse response = loginService.verifyLoginOtp(request, client.getId(), httpRequest.getRemoteAddr(), httpRequest.getHeader("User-Agent"));
        return ResponseEntity.ok(InternalAuthApiResponse.success(response.getMessage(), response));
    }

    /**
     * Step 15C - redeems a refresh token minted by a previous successful
     * login for a new access token (and a new refresh token - rotation,
     * see ClientApplicationRegisteredClientRepository's TokenSettings
     * javadoc). Same HTTP Basic client-credential requirement as
     * login()/verifyLoginOtp() above - the resolved client_application_id
     * is what LoginServiceImpl#refreshToken checks the redeemed token
     * actually belongs to, not just any authenticated client.
     */
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

    /**
     * Server-to-server: tells an integrating app whether one of its own users still holds a live
     * refresh token here. The app uses it to notice that an admin signed the user out in this
     * console (which deletes those tokens), so its own "already signed in" record can be released.
     * Same HTTP Basic client-credential requirement as login(); the user is looked up within the
     * calling client only.
     */
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
}
