package com.internal.auth.feature.session.service;

import com.internal.auth.feature.session.dto.LogoutResponse;

public interface LogoutService {
    LogoutResponse logout(String sessionId);
}
