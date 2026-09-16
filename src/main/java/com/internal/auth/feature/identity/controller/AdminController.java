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
import com.internal.auth.feature.identity.dto.request.VerifyLoginOtpRequest;
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

/**
 * Admin bootstrap + admin sign-in - the equivalent of Keycloak's master-
 * realm admin console for this app's own platform operators.
 *
 * Mapped under the "${app.title}" property, same as every other controller
 * in the app - see RegistrationController's javadoc for why a hardcoded
 * "/api/v1/admin" literal isn't needed here either (API-contract review,
 * step 1): WebSecurityConfig builds its own permitAll() matcher paths from
 * the same "app.title" property now, so this controller and its security
 * rule move together regardless of representation.
 *
 * All three endpoints resolve a reserved, internal ClientApplication
 * ("internal-auth-admin-console" - AppConstant#INTERNAL_ADMIN_CLIENT_ID) via
 * ClientApplicationService#getOrCreateInternalAdminClient, which creates
 * that row on first use if it doesn't exist yet - no seed migration, no
 * manual SQL, nothing to run beforehand. That row has no secret
 * (client_secret_hash stays null) and is never authenticated against - it
 * exists purely so admin User rows have a client_application_id to satisfy
 * the NOT NULL FK the multi-tenant redesign (V8) added. Callers never see
 * or supply it, unlike the HTTP Basic client credentials
 * RegistrationController/LoginController require for real integrating apps
 * (SyncPoint, Notare, ...) - an admin isn't a tenant end user, and the whole
 * point of this controller is that the very first admin has no credentials
 * of any kind yet to present.
 *
 * "/register" is a self-limiting bootstrap - see
 * AdminRegistrationServiceImpl for why the gate is enforced in code rather
 * than @PreAuthorize. "/login" and "/login/verify-otp" are unrestricted -
 * any admin can always sign in - and simply delegate to the same
 * LoginService every regular user login uses; the returned token's "roles"
 * claim naturally includes create-admin because that's what
 * LoginServiceImpl#mintAccessToken actually reads off the user's assigned
 * UserRole rows, same as for anyone else. Rate-limit buckets are kept
 * separate from regular user login ("admin:" prefix) so the two pools can't
 * exhaust each other.
 */
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

    @PostMapping("/login/verify-otp")
    public ResponseEntity<InternalAuthApiResponse<LoginResponse>> verifyLoginOtp(@RequestBody VerifyLoginOtpRequest request, HttpServletRequest httpRequest) {
        rateLimiterService.checkRateLimit(AppConstant.LOGIN_OTP_VERIFY_RATE_LIMIT_KEY_PREFIX + "admin:" + httpRequest.getRemoteAddr(),
                AppConstant.MAX_LOGIN_OTP_VERIFY_REQUEST, Duration.ofMinutes(AppConstant.LOGIN_OTP_VERIFY_RATE_LIMIT_DURATION_MINUTES));
        ClientApplication adminClient = clientApplicationService.getOrCreateInternalAdminClient();
        LoginResponse response = loginService.verifyLoginOtp(request, adminClient.getId(), httpRequest.getRemoteAddr(), httpRequest.getHeader("User-Agent"));
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

    /**
     * React Admin Client plan v4, Step 5C/5D backend gap. PasswordResetController's
     * "/request" and "/verify-otp" resolve the calling ClientApplication via
     * authenticateClientFromBasicAuthHeader - the same HTTP Basic client-credential
     * header RegistrationController/LoginController require - which can never
     * succeed for the internal-auth-admin-console client for the exact reason
     * documented on refreshToken() above: it has no secret (clientSecretHash is
     * null) and authenticateClient() unconditionally rejects a null-hash client.
     * These two endpoints mirror /login and /refresh-token above instead: no
     * Basic Auth, resolve the reserved admin client directly, same
     * PasswordResetService the real-client-app flow uses underneath. "/complete"
     * needs no equivalent - it resolves everything from the reset token's own
     * hash and takes no client-identifying header at all, so the admin console
     * calls PasswordResetController's existing "/complete" directly. Rate-limit
     * keys use their own "admin:" segment so this pool can't exhaust, or be
     * exhausted by, the real-client-app pool on the same phone number.
     */
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
