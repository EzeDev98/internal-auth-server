package com.internal.auth.feature.session.service;

import com.internal.auth.feature.session.dto.InvalidatedSessionResponse;
import com.internal.auth.feature.session.dto.OwnSessionResponse;
import com.internal.auth.feature.session.dto.PagedAdminSessionsResponse;
import org.springframework.data.domain.Pageable;

/** Operations for creating, checking and invalidating sessions. */
@org.springframework.modulith.NamedInterface
public interface SessionManagementService {
    void createSession(Long userId, String phoneNumber, String token);

    void createSession(Long userId, String phoneNumber, String token, String ipAddress, String userAgent);

    void createSession(Long userId, String phoneNumber, String token, String ipAddress, String userAgent, String authorizationId);
    void invalidateSession(String token);

    void invalidateActiveSessionForUser(Long userId);

    InvalidatedSessionResponse invalidateUserSessionByAdmin(String username, Long clientApplicationId);

    boolean hasLiveRefreshToken(String username, Long clientApplicationId);

    PagedAdminSessionsResponse listSessions(String username, Long clientApplicationId, String ipAddress, String device, Boolean active, Pageable pageable);
    void updateSessionOnRefresh(Long userId, String previousAccessToken, String newToken, String authorizationId);

    java.util.List<OwnSessionResponse> listOwnSessions(String token);

    void revokeOwnSession(String token, Long sessionId);

    int revokeOtherSessions(String token);
    boolean hasActiveSession(Long userId);
}
