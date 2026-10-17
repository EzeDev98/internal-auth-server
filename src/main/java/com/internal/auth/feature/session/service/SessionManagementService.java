package com.internal.auth.feature.session.service;

import com.internal.auth.feature.session.dto.InvalidatedSessionResponse;
import com.internal.auth.feature.session.dto.OwnSessionResponse;
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

    /**
     * Step 17h (B-14): a sign-in. authorizationId is the oauth2_authorization row (refresh token) minted
     * with this token, so this one device can later be signed out on its own. When the client allows
     * several devices and this sign-in goes past the limit, the device used least recently is signed out.
     * The overloads above pass null: a client limited to several devices records sessions only here.
     */
    void createSession(Long userId, String phoneNumber, String token, String ipAddress, String userAgent, String authorizationId);
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
    /**
     * Step 17h: moves the session that was using previousAccessToken onto newToken and its (possibly new)
     * authorization, and records the refresh as activity. Falls back to the user's only active session
     * when previousAccessToken is unknown.
     */
    void updateSessionOnRefresh(Long userId, String previousAccessToken, String newToken, String authorizationId);

    /**
     * Step 17h (B-14): every device the caller's account is signed in on, one per session, with
     * current = true for the session whose token made the request. Sessions whose refresh token has
     * ended are closed on the way and left out.
     */
    java.util.List<OwnSessionResponse> listOwnSessions(String token);

    /** Step 17h: signs one of the caller's own sessions out, revoking its refresh token. 404 if it is not theirs. */
    void revokeOwnSession(String token, Long sessionId);

    /** Step 17h: signs out every session of the caller's account except the one making the request. Returns how many. */
    int revokeOtherSessions(String token);
    boolean hasActiveSession(Long userId);
}
