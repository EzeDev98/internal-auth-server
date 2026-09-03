package com.internal.auth.feature.identity.service;

import com.internal.auth.feature.identity.dto.LoginRequest;
import com.internal.auth.feature.identity.dto.LoginResponse;
import com.internal.auth.feature.identity.dto.VerifyLoginOtpRequest;

public interface LoginService {
    LoginResponse login(LoginRequest request);
    LoginResponse verifyLoginOtp(VerifyLoginOtpRequest request);
}
