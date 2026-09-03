package com.internal.auth.feature.session.service.impl;

import com.internal.auth.common.crypto.TokenHasher;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.identity.repository.UserRepository;
import com.internal.auth.feature.session.dto.InvalidatedSessionResponse;
import com.internal.auth.feature.session.model.UserSession;
import com.internal.auth.feature.session.repository.UserSessionRepository;
import com.internal.auth.feature.session.service.SessionManagementService;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

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
 */
@Service
public class SessionManagementServiceImpl implements SessionManagementService {

    private static final Logger log = LoggerFactory.getLogger(SessionManagementServiceImpl.class);
    private final UserSessionRepository userSessionRepository;
    private final UserRepository userRepository;
    private final TokenHasher tokenHasher;

    public SessionManagementServiceImpl(UserSessionRepository userSessionRepository, UserRepository userRepository, TokenHasher tokenHasher) {
        this.userSessionRepository = userSessionRepository;
        this.userRepository = userRepository;
        this.tokenHasher = tokenHasher;
    }

    @Override
    @Transactional
    public void createSession(Long userId, String phoneNumber, String token) {
        userSessionRepository.findByUserIdAndIsActiveTrue(userId)
                .ifPresent(existing -> closeSession(existing, REPLACED_BY_NEW_LOGIN));

        UserSession session = new UserSession();
        session.setUserId(userId);
        session.setPhoneNumber(phoneNumber);
        session.setTokenHash(tokenHasher.sha256Hex(token));
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
    public InvalidatedSessionResponse invalidateUserSessionByAdmin(String username) {
        User user = userRepository.findByUsername(username).orElse(null);
        if (user == null) {
            log.warn("No user found for username {} during admin session invalidation", username);
            return new InvalidatedSessionResponse(HttpServletResponse.SC_NOT_FOUND, "No user found with username " + username);
        }

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
                    LocalDateTime expiryThreshold = session.getCreatedAt().plusDays(SESSION_TTL_DAYS);
                    if (LocalDateTime.now().isAfter(expiryThreshold)) {
                        log.info("Session for user id {} exceeded {}-day TTL - expiring", userId, SESSION_TTL_DAYS);
                        closeSession(session, TTL_EXPIRED);
                        return false;
                    }
                    return true;
                }).orElse(false);
    }

    private void closeSession(UserSession session, String reason) {
        session.setActive(false);
        session.setEndedAt(LocalDateTime.now());
        session.setEndReason(reason);
        userSessionRepository.save(session);
    }
}
