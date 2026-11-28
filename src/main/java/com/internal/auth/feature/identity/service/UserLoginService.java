package com.internal.auth.feature.identity.service;

import com.internal.auth.feature.identity.dto.request.LoginRequest;
import com.internal.auth.feature.identity.dto.request.RefreshTokenRequest;
import com.internal.auth.feature.identity.dto.response.LoginResponse;

/** Operations for login and token refresh. */
public interface UserLoginService {
    LoginResponse login(LoginRequest request, Long clientApplicationId);

    LoginResponse login(LoginRequest request, Long clientApplicationId, String ipAddress, String userAgent);

    LoginResponse refreshToken(RefreshTokenRequest request, Long clientApplicationId);
}
