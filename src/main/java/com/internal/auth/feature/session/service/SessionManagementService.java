package com.internal.auth.feature.session.service;

import com.internal.auth.feature.session.dto.InvalidatedSessionResponse;

/**
 * Step 11B: invalidateUserSessionByAdmin takes username (resolved to
 * userId internally), not phoneNumber - an admin can now invalidate any
 * user's session regardless of whether they have a phone number on file.
 * updateSessionOnRefresh/hasActiveSession take userId directly.
 */
public interface SessionManagementService {
    void createSession(Long userId, String phoneNumber, String token);
    void invalidateSession(String token);
    InvalidatedSessionResponse invalidateUserSessionByAdmin(String username);
    void updateSessionOnRefresh(Long userId, String newToken);
    boolean hasActiveSession(Long userId);
}
