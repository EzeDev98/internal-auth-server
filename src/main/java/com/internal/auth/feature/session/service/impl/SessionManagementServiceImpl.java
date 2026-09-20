package com.internal.auth.feature.session.service.impl;

import com.internal.auth.common.crypto.TokenHasher;
import com.internal.auth.feature.client.service.ClientApplicationService;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.identity.repository.UserRepository;
import com.internal.auth.feature.session.dto.InvalidatedSessionResponse;
import com.internal.auth.feature.session.dto.AdminSessionSummaryResponse;
import com.internal.auth.feature.session.dto.PagedAdminSessionsResponse;
import com.internal.auth.feature.session.model.UserSession;
import com.internal.auth.feature.session.repository.UserSessionRepository;
import com.internal.auth.feature.session.service.SessionManagementService;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static com.internal.auth.common.constant.AppConstant.*;

/**
 * Step 11B: session lookups are keyed on userId, not phoneNumber. Was
 * originally phoneNumber-keyed throughout (findByPhoneNumberAndIsActiveTrue)
 * - broke silently for any email-only user (phoneNumber optional since
 * Stage 2) once JwtSessionTrackingFilter started passing a null
 * phoneNumber into createSession, since user_sessions.phone_number was NOT
 * NULL: every authenticated request for such a user hit a swallowed
 * DataIntegrityViolationException inside the filter, so session tracking
 * silently never worked for that user - and separately,
 * PasswordResetServiceImpl's post-reset session invalidation silently
 * no-opped for them too (a real security gap - a password reset should
 * always force logout of the old session). userId is always present (NOT
 * NULL), so it's the correct key regardless of which contact methods a
 * user has. phoneNumber is retained on UserSession as optional,
 * informational-only data, no longer used for lookups.
 *
 * invalidateUserSessionByAdmin takes username (mandatory on every account)
 * rather than phoneNumber, resolving it to a userId via UserRepository -
 * the same reasoning UserSessionController's endpoint follows.
 *
 * This is also the prerequisite for Step 11B's other decision - scoping
 * sessions per (user, application) once Step 12 exists: userId is the
 * anchor a future clientApplicationId column pairs with, not phoneNumber.
 *
 * Multi-tenant redesign, sessions step: findByUserIdAndIsActiveTrue and
 * findByTokenHash were already unambiguous (see SessionManagementService's
 * class Javadoc) - no schema change needed here. The one real fix is
 * invalidateUserSessionByAdmin, which now takes clientApplicationId to
 * scope its username lookup, plus the new invalidateActiveSessionForUser
 * for callers that already have a userId and shouldn't go through an
 * ambiguous username lookup at all.
 */
@Service
public class SessionManagementServiceImpl implements SessionManagementService {

    private static final Logger log = LoggerFactory.getLogger(SessionManagementServiceImpl.class);
    private final UserSessionRepository userSessionRepository;
    private final UserRepository userRepository;
    private final TokenHasher tokenHasher;
    private final ClientApplicationService clientApplicationService;
    private final org.springframework.jdbc.core.JdbcTemplate jdbcTemplate;

    @Value("${app.authorization-server.refresh-token-ttl-days}")
    private long globalRefreshTokenTtlDays;

    public SessionManagementServiceImpl(UserSessionRepository userSessionRepository, UserRepository userRepository, TokenHasher tokenHasher, ClientApplicationService clientApplicationService, org.springframework.jdbc.core.JdbcTemplate jdbcTemplate) {
        this.userSessionRepository = userSessionRepository;
        this.userRepository = userRepository;
        this.tokenHasher = tokenHasher;
        this.clientApplicationService = clientApplicationService;
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    @Transactional
    public void createSession(Long userId, String phoneNumber, String token) {
        createSession(userId, phoneNumber, token, null, null);
    }

    /**
     * Step 2E (React Admin Client plan v4): same as the three-arg overload
     * above, plus the caller's IP/User-Agent, captured for the admin
     * Sessions - List screen this backs. The three-arg overload delegates
     * here with both null, so JwtSessionTrackingFilter is the only caller
     * that needs to change - every other existing caller/test is
     * unaffected.
     */
    @Override
    @Transactional
    public void createSession(Long userId, String phoneNumber, String token, String ipAddress, String userAgent) {
        String tokenHash = tokenHasher.sha256Hex(token);
        UserSession existing = userSessionRepository.findByUserIdAndIsActiveTrue(userId).orElse(null);
        if (existing != null && tokenHash.equals(existing.getTokenHash())) {
            // Same token already tracked (login, or updateSessionOnRefresh, got there first):
            // keep the row instead of closing it and opening an identical one.
            return;
        }
        if (existing != null) {
            closeSession(existing, REPLACED_BY_NEW_LOGIN);
        }

        UserSession session = new UserSession();
        session.setUserId(userId);
        session.setPhoneNumber(phoneNumber);
        session.setTokenHash(tokenHash);
        session.setIpAddress(ipAddress);
        session.setUserAgent(userAgent);
        session.setActive(true);
        session.setCreatedAt(LocalDateTime.now());

        userSessionRepository.save(session);
        log.info("New session created for user id: {}", userId);
    }

    @Override
    @Transactional
    public void invalidateSession(String token) {
        userSessionRepository.findByTokenHash(tokenHasher.sha256Hex(token))
                .ifPresentOrElse(
                        session -> {
                            closeSession(session, LOGOUT);
                            log.info("Session invalidated for user id: {}", session.getUserId());
                        },
                        () -> log.warn("No session found for token during logout")
                );
    }

    @Override
    @Transactional
    public void invalidateActiveSessionForUser(Long userId) {
        userSessionRepository.findByUserIdAndIsActiveTrue(userId)
                .ifPresent(session -> {
                    closeSession(session, ADMIN_ACTION);
                    log.info("Session invalidated for user id: {}", userId);
                });
        revokeAuthorizations(userRepository.findById(userId).orElse(null));
    }

    @Override
    @Transactional
    public InvalidatedSessionResponse invalidateUserSessionByAdmin(String username, Long clientApplicationId) {
        User user = userRepository.findByUsernameAndClientApplicationId(username, clientApplicationId).orElse(null);
        if (user == null) {
            log.warn("No user found for username {} in client application {} during admin session invalidation", username, clientApplicationId);
            return new InvalidatedSessionResponse(HttpServletResponse.SC_NOT_FOUND, "No user found with username " + username);
        }

        revokeAuthorizations(user);

        return userSessionRepository.findByUserIdAndIsActiveTrue(user.getId())
                .map(session -> {
                    closeSession(session, ADMIN_ACTION);
                    log.info("Session invalidated by admin for user: {}", username);
                    return new InvalidatedSessionResponse(HttpServletResponse.SC_OK, "Session successfully invalidated for user " + username);
                })
                .orElseGet(() -> {
                    log.warn("No active session found for {} during admin invalidation - nothing to update", username);
                    return new InvalidatedSessionResponse(HttpServletResponse.SC_NOT_FOUND, "No active session found for user " + username);
                });
    }

    @Override
    @Transactional
    public void updateSessionOnRefresh(Long userId, String newToken) {
        userSessionRepository.findByUserIdAndIsActiveTrue(userId)
                .ifPresentOrElse(
                        session -> {
                            session.setTokenHash(tokenHasher.sha256Hex(newToken));
                            session.setCreatedAt(LocalDateTime.now());
                            userSessionRepository.save(session);
                            log.info("Session refreshed and TTL reset for user id: {}", userId);
                        },
                        () -> log.warn("No active session found for user id {} during refresh - nothing to update", userId)
                );
    }

    @Override
    @Transactional
    public boolean hasActiveSession(Long userId) {
        return userSessionRepository.findByUserIdAndIsActiveTrue(userId)
                .map(session -> {
                    long ttlDays = resolveSessionTtlDays(userId);
                    LocalDateTime expiryThreshold = session.getCreatedAt().plusDays(ttlDays);
                    if (LocalDateTime.now().isAfter(expiryThreshold)) {
                        log.info("Session for user id {} exceeded {}-day TTL - expiring", userId, ttlDays);
                        closeSession(session, TTL_EXPIRED);
                        return false;
                    }
                    return true;
                }).orElse(false);
    }

    /**
     * The session row must never expire before the refresh token it tracks,
     * otherwise a client with a long-lived (persistent) refresh token would
     * be cut off while its refresh token is still valid. Uses the larger of
     * the fixed SESSION_TTL_DAYS floor and the client's effective refresh
     * token TTL (per-client override, else the global default).
     */
    private long resolveSessionTtlDays(Long userId) {
        long refreshTtlDays = userRepository.findById(userId)
                .map(user -> {
                    Integer perClientDays = clientApplicationService.getById(user.getClientApplicationId()).getRefreshTokenTtlDays();
                    return perClientDays != null ? perClientDays.longValue() : globalRefreshTokenTtlDays;
                })
                .orElse(globalRefreshTokenTtlDays);
        return Math.max(SESSION_TTL_DAYS, refreshTtlDays);
    }

    /**
     * Deletes the user's refresh-token authorizations for their own client. Without this, closing the
     * tracking row does not stop a stored refresh token from minting new access tokens. Access tokens
     * already issued stay valid until their own short expiry.
     */
    private void revokeAuthorizations(User user) {
        if (user == null || user.getInternalAuthUserId() == null || user.getClientApplicationId() == null) {
            return;
        }
        int removed = jdbcTemplate.update(
                "DELETE FROM oauth2_authorization WHERE principal_name = ? AND registered_client_id = ?",
                user.getInternalAuthUserId(), String.valueOf(user.getClientApplicationId()));
        if (removed > 0) {
            log.info("Revoked {} refresh-token authorization(s) for user id {}", removed, user.getId());
        }
    }

    private static final Long NO_MATCHING_USER_ID = -1L;

    @Override
    @Transactional
    public PagedAdminSessionsResponse listSessions(String username, Long clientApplicationId, String ipAddress, String device, Boolean active, Pageable pageable) {
        Long userId = null;
        if (username != null) {
            userId = userRepository.findByUsernameAndClientApplicationId(username, clientApplicationId)
                    .map(User::getId)
                    .orElse(NO_MATCHING_USER_ID);
        }

        String normalizedIp = (ipAddress == null || ipAddress.isBlank()) ? null : ipAddress.trim();
        String normalizedDevice = (device == null || device.isBlank()) ? null : device.trim();

        Page<UserSession> page = userSessionRepository.searchForAdmin(userId, active, normalizedIp, normalizedDevice, pageable);

        List<Long> userIds = page.getContent().stream().map(UserSession::getUserId).distinct().toList();
        List<User> users = userRepository.findAllById(userIds);
        Map<Long, String> usernamesById = users.stream()
                .collect(Collectors.toMap(User::getId, User::getUsername));
        Map<Long, String> clientIdsById = users.stream()
                .collect(Collectors.toMap(User::getId, this::resolveClientId));

        List<AdminSessionSummaryResponse> content = page.getContent().stream()
                .map(session -> new AdminSessionSummaryResponse(
                        session.getId(),
                        session.getUserId(),
                        usernamesById.get(session.getUserId()),
                        session.getIpAddress(),
                        session.getUserAgent(),
                        session.isActive(),
                        session.getCreatedAt(),
                        session.getEndedAt(),
                        session.getEndReason(),
                        clientIdsById.get(session.getUserId())))
                .toList();

        return new PagedAdminSessionsResponse(content, page.getNumber(), page.getSize(), page.getTotalElements(), page.getTotalPages());
    }

    // Step 10B: best-effort resolution of the owning client's clientId
    // string, same pattern and same caveats as AdminUserServiceImpl's own
    // resolveClientId (Step 7A) - the standalone Sessions - List screen's
    // Revoke action needs clientId on each row to call DELETE
    // ${app.title}/users/{username}/sessions, since username alone is
    // ambiguous across client applications (see User's class Javadoc, V8).
    private String resolveClientId(User user) {
        try {
            return clientApplicationService.getById(user.getClientApplicationId()).getClientId();
        } catch (RuntimeException e) {
            log.warn("Could not resolve clientId for user id={}, clientApplicationId={}", user.getId(), user.getClientApplicationId());
            return null;
        }
    }

    private void closeSession(UserSession session, String reason) {
        session.setActive(false);
        session.setEndedAt(LocalDateTime.now());
        session.setEndReason(reason);
        userSessionRepository.save(session);
    }
}
