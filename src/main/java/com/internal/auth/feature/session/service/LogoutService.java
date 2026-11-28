package com.internal.auth.feature.session.service;

import com.internal.auth.feature.session.dto.LogoutResponse;

/** Operations for logging out. */
public interface LogoutService {
    LogoutResponse logout(String sessionId);

    LogoutResponse logoutAll(String token);
}
