package com.internal.auth.feature.session.service;

import com.internal.auth.feature.session.dto.LogoutResponse;

public interface LogoutService {
    LogoutResponse logout(String sessionId);

    /** Ends every session and revokes every refresh token of the token's owner. */
    LogoutResponse logoutAll(String token);
}
