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
     * @param clientApplicationId the calling app's resolved
     *   client_application_id (see LoginController - resolved from the
     *   request's Authorization: Basic clientId:clientSecret header,
     *   multi-tenant redesign). Scopes the login-MFA OTP lookup, since
     *   phoneNumber alone can now belong to accounts in different apps
     *   (see LoginMfaOtp's class Javadoc and the V9 migration).
     */
    LoginResponse verifyLoginOtp(VerifyLoginOtpRequest request, Long clientApplicationId);

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