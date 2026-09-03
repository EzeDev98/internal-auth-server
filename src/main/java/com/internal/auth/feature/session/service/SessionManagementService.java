package com.internal.auth.feature.session.service;

import com.internal.auth.feature.session.dto.InvalidatedSessionResponse;

/**
 * Step 11B: invalidateUserSessionByAdmin takes username (resolved to
 * userId internally), not phoneNumber - an admin can now invalidate any
 * user's session regardless of whether they have a phone number on file.
 * updateSessionOnRefresh/hasActiveSession take userId directly.
 *
 * Multi-tenant redesign, sessions step: session lookups themselves
 * (findByUserIdAndIsActiveTrue, findByTokenHash) were already safe - a
 * userId is a specific User row's own primary key, already anchored to
 * one client_application_id, and tokenHash is a random unique value.
 * invalidateUserSessionByAdmin was the one real gap: it resolved a userId
 * from a bare username, which is ambiguous now that usernames are only
 * unique per app - it now takes clientApplicationId too (resolved by
 * UserSessionController from an admin-supplied clientId). Callers that
 * already hold a resolved User (PasswordResetServiceImpl) should use
 * invalidateActiveSessionForUser(userId) instead of round-tripping
 * through an ambiguous username lookup they don't need.
 */
public interface SessionManagementService {
    void createSession(Long userId, String phoneNumber, String token);
    void invalidateSession(String token);

    /**
     * Invalidates the caller's own already-known active session by userId
     * directly - no username lookup, so no client-application ambiguity
     * to resolve. For internal callers (e.g. PasswordResetServiceImpl)
     * that already hold a resolved User.
     */
    void invalidateActiveSessionForUser(Long userId);

    InvalidatedSessionResponse invalidateUserSessionByAdmin(String username, Long clientApplicationId);
    void updateSessionOnRefresh(Long userId, String newToken);
    boolean hasActiveSession(Long userId);
}
