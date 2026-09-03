package com.internal.auth.feature.identity.service;

import com.internal.auth.feature.identity.dto.LoginRequest;
import com.internal.auth.feature.identity.dto.LoginResponse;
import com.internal.auth.feature.identity.dto.VerifyLoginOtpRequest;

public interface LoginService {
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
}
