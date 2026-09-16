package com.internal.auth.feature.identity.service;

import com.internal.auth.feature.identity.dto.request.LoginRequest;
import com.internal.auth.feature.identity.dto.request.RefreshTokenRequest;
import com.internal.auth.feature.identity.dto.request.VerifyLoginOtpRequest;
import com.internal.auth.feature.identity.dto.response.LoginResponse;

public interface UserLoginService {
    /**
     * @param clientApplicationId the calling app's resolved
     *   client_application_id (see LoginController - resolved from the
     *   request's Authorization: Basic clientId:clientSecret header,
     *   multi-tenant redesign). The username lookup is scoped to this
     *   value, same as RegistrationServiceImpl.
     */
    LoginResponse login(LoginRequest request, Long clientApplicationId);

    /**
     * Same as {@link #login(LoginRequest, Long)}, but also forwards the
     * caller's IP/User-Agent into {@code SessionManagementService.createSession}
     * so the resulting {@code UserSession} row isn't born with a null
     * ipAddress/device - the gap that left every locally-authenticated
     * session's IP/device blank on the admin Sessions screens, unlike
     * sessions backfilled by JwtSessionTrackingFilter (which already
     * passes both). Both params are nullable/best-effort, same status as
     * ipAddress/userAgent on UserSession itself.
     *
     * @param clientApplicationId the calling app's resolved
     *   client_application_id (see LoginController - resolved from the
     *   request's Authorization: Basic clientId:clientSecret header,
     *   multi-tenant redesign). The username lookup is scoped to this
     *   value, same as RegistrationServiceImpl.
     * @param ipAddress the caller's remote address (e.g. HttpServletRequest#getRemoteAddr())
     * @param userAgent the caller's User-Agent request header
     */
    LoginResponse login(LoginRequest request, Long clientApplicationId, String ipAddress, String userAgent);

    /**
     * @param clientApplicationId the calling app's resolved
     *   client_application_id (see LoginController - resolved from the
     *   request's Authorization: Basic clientId:clientSecret header,
     *   multi-tenant redesign). Scopes the login-MFA OTP lookup, since
     *   phoneNumber alone can now belong to accounts in different apps
     *   (see LoginMfaOtp's class Javadoc and the V9 migration).
     */
    LoginResponse verifyLoginOtp(VerifyLoginOtpRequest request, Long clientApplicationId);

    /**
     * Same as {@link #verifyLoginOtp(VerifyLoginOtpRequest, Long)}, but also
     * creates the {@code UserSession} row for the completed login - unlike
     * {@link #login}, the no-MFA path, verifyLoginOtp() never called
     * {@code SessionManagementService.createSession} at all, so an
     * MFA-enabled account's login never got a session row (with or
     * without IP/device) from this flow; it only existed if
     * JwtSessionTrackingFilter happened to backfill one later. See
     * {@link #login(LoginRequest, Long, String, String)} for why
     * ipAddress/userAgent are both nullable/best-effort here too.
     */
    LoginResponse verifyLoginOtp(VerifyLoginOtpRequest request, Long clientApplicationId, String ipAddress, String userAgent);

    /**
     * Step 15C - redeems a refresh token minted by mintTokens() (Step 15B)
     * for a new access token (and, per TokenSettings.reuseRefreshTokens
     * (false), a new refresh token - the old one stops working the moment
     * this succeeds). See LoginServiceImpl#refreshToken javadoc for the
     * full validation this performs.
     *
     * @param clientApplicationId the calling app's resolved
     *   client_application_id (see LoginController). The redeemed refresh
     *   token must belong to this exact client application, not just any
     *   client - a token minted for one integrating app must never be
     *   redeemable by another.
     */
    LoginResponse refreshToken(RefreshTokenRequest request, Long clientApplicationId);
}