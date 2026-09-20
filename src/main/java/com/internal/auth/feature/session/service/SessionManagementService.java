package com.internal.auth.feature.session.service;

import com.internal.auth.feature.session.dto.InvalidatedSessionResponse;
import com.internal.auth.feature.session.dto.PagedAdminSessionsResponse;
import org.springframework.data.domain.Pageable;

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
@org.springframework.modulith.NamedInterface
public interface SessionManagementService {
    void createSession(Long userId, String phoneNumber, String token);

    /**
     * Step 2E (React Admin Client plan v4): same as the three-arg overload
     * above, plus the caller's IP/User-Agent, captured for the admin
     * Sessions - List screen this backs (see UserSession's class Javadoc
     * on ipAddress/userAgent). The three-arg overload delegates here with
     * both null.
     */
    void createSession(Long userId, String phoneNumber, String token, String ipAddress, String userAgent);
    void invalidateSession(String token);

    /**
     * Invalidates the caller's own already-known active session by userId
     * directly - no username lookup, so no client-application ambiguity
     * to resolve. For internal callers (e.g. PasswordResetServiceImpl)
     * that already hold a resolved User. Also deletes the user's stored refresh-token
     * authorizations for their client, so a password reset or admin action really ends
     * the login instead of only closing the tracking row.
     */
    void invalidateActiveSessionForUser(Long userId);

    InvalidatedSessionResponse invalidateUserSessionByAdmin(String username, Long clientApplicationId);

    /**
     * True while the user still holds an unexpired refresh token for the given client. Admin
     * sign-out and password reset delete those tokens, so this turns false after either.
     */
    boolean hasLiveRefreshToken(String username, Long clientApplicationId);

    /**
     * Step 2E (React Admin Client plan v4): backs GET
     * ${app.title}/admin/sessions. username is resolved against
     * clientApplicationId the same way invalidateUserSessionByAdmin above
     * does - pass both null to list across every user. ipAddress/device
     * match as a case-insensitive substring; active filters on session
     * status. A username that doesn't resolve to any user yields an empty
     * page rather than an error.
     */
    PagedAdminSessionsResponse listSessions(String username, Long clientApplicationId, String ipAddress, String device, Boolean active, Pageable pageable);
    void updateSessionOnRefresh(Long userId, String newToken);
    boolean hasActiveSession(Long userId);
}
