package com.internal.auth.feature.session.service.impl;

import com.internal.auth.common.crypto.TokenHasher;
import com.internal.auth.common.exception.BadRequestException;
import com.internal.auth.common.exception.SessionNotFoundException;
import com.internal.auth.feature.client.service.ClientApplicationService;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.identity.repository.UserRepository;
import com.internal.auth.feature.session.dto.InvalidatedSessionResponse;
import com.internal.auth.feature.session.dto.OwnSessionResponse;
import com.internal.auth.feature.session.dto.AdminSessionSummaryResponse;
import com.internal.auth.feature.session.dto.PagedAdminSessionsResponse;
import com.internal.auth.feature.session.model.UserSession;
import com.internal.auth.feature.session.repository.UserSessionRepository;
import com.internal.auth.feature.session.service.SessionManagementService;
import com.internal.auth.feature.session.util.DeviceLabelParser;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static com.internal.auth.common.constant.AppConstant.*;

/** Creates, checks and invalidates user sessions. */
@Service
public class SessionManagementServiceImpl implements SessionManagementService {

    private static final Logger log = LoggerFactory.getLogger(SessionManagementServiceImpl.class);
    private static final int SINGLE_SESSION = 1;

    private static final String LIVE_AUTHORIZATION_IDS_SQL =
            "SELECT id FROM oauth2_authorization WHERE principal_name = ? AND registered_client_id = ? AND ("
                    + "(refresh_token_value IS NOT NULL AND (refresh_token_expires_at IS NULL OR refresh_token_expires_at > ?)) "
                    + "OR (refresh_token_value IS NULL AND (access_token_expires_at IS NULL OR access_token_expires_at > ?)))";

    private static final String DELETE_UNCLAIMED_AUTHORIZATIONS_SQL =
            "DELETE FROM oauth2_authorization WHERE principal_name = ? AND registered_client_id = ? AND id NOT IN "
                    + "(SELECT authorization_id FROM user_sessions WHERE user_id = ? AND is_active = TRUE AND authorization_id IS NOT NULL)";

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
        createSession(userId, phoneNumber, token, null, null, null);
    }

    @Override
    @Transactional
    public void createSession(Long userId, String phoneNumber, String token, String ipAddress, String userAgent) {
        createSession(userId, phoneNumber, token, ipAddress, userAgent, null);
    }

    @Override
    @Transactional
    public void createSession(Long userId, String phoneNumber, String token, String ipAddress, String userAgent, String authorizationId) {
        String tokenHash = tokenHasher.sha256Hex(token);
        if (userSessionRepository.findByTokenHash(tokenHash).isPresent()) {
            return;
        }

        User user = userRepository.findById(userId).orElse(null);
        int limit = maxActiveSessions(user);
        if (limit > SINGLE_SESSION && authorizationId == null) {
            log.debug("Not backfilling a session for user id {}: client allows {} devices and records them at sign-in", userId, limit);
            return;
        }
        if (limit == SINGLE_SESSION) {
            userSessionRepository.findAllByUserIdAndIsActiveTrue(userId)
                    .forEach(existing -> closeSession(existing, REPLACED_BY_NEW_LOGIN));
        }

        LocalDateTime now = LocalDateTime.now();
        UserSession session = new UserSession();
        session.setUserId(userId);
        session.setPhoneNumber(phoneNumber);
        session.setTokenHash(tokenHash);
        session.setIpAddress(ipAddress);
        session.setUserAgent(userAgent);
        session.setDeviceLabel(DeviceLabelParser.label(userAgent));
        session.setAuthorizationId(authorizationId);
        session.setActive(true);
        session.setCreatedAt(now);
        session.setLastActiveAt(now);
        userSessionRepository.save(session);
        log.info("New session created for user id: {}", userId);

        if (limit > SINGLE_SESSION) {
            signOutBeyondLimit(user, limit, session);
        }
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
        List<UserSession> active = userSessionRepository.findAllByUserIdAndIsActiveTrue(userId);
        active.forEach(session -> closeSession(session, ADMIN_ACTION));
        if (!active.isEmpty()) {
            log.info("{} session(s) invalidated for user id: {}", active.size(), userId);
        }
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

        List<UserSession> active = userSessionRepository.findAllByUserIdAndIsActiveTrue(user.getId());
        if (active.isEmpty()) {
            log.warn("No active session found for {} during admin invalidation - nothing to update", username);
            return new InvalidatedSessionResponse(HttpServletResponse.SC_NOT_FOUND, "No active session found for user " + username);
        }
        active.forEach(session -> closeSession(session, ADMIN_ACTION));
        log.info("{} session(s) invalidated by admin for user: {}", active.size(), username);
        return new InvalidatedSessionResponse(HttpServletResponse.SC_OK, "Session successfully invalidated for user " + username);
    }

    @Override
    @Transactional
    public boolean hasLiveRefreshToken(String username, Long clientApplicationId) {
        User user = userRepository.findByUsernameAndClientApplicationId(username, clientApplicationId).orElse(null);
        if (user == null || user.getInternalAuthUserId() == null) {
            return false;
        }
        Integer live = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM oauth2_authorization WHERE principal_name = ? AND registered_client_id = ? "
                        + "AND refresh_token_value IS NOT NULL "
                        + "AND (refresh_token_expires_at IS NULL OR refresh_token_expires_at > ?)",
                Integer.class,
                user.getInternalAuthUserId(), String.valueOf(user.getClientApplicationId()),
                java.sql.Timestamp.from(java.time.Instant.now()));
        return live != null && live > 0;
    }

    @Override
    @Transactional
    public List<OwnSessionResponse> listOwnSessions(String token) {
        UserSession caller = userSessionRepository.findByTokenHash(tokenHasher.sha256Hex(token))
                .filter(UserSession::isActive)
                .orElse(null);
        if (caller == null) {
            return List.of();
        }
        User user = userRepository.findById(caller.getUserId()).orElse(null);
        long ttlDays = resolveSessionTtlDays(user);
        return liveSessions(caller.getUserId(), user).stream()
                .map(session -> toOwnSession(session, session.getId().equals(caller.getId()), ttlDays))
                .toList();
    }

    @Override
    @Transactional
    public void revokeOwnSession(String token, Long sessionId) {
        UserSession caller = activeSessionFor(token);
        UserSession target = userSessionRepository.findById(sessionId)
                .filter(UserSession::isActive)
                .filter(session -> session.getUserId().equals(caller.getUserId()))
                .orElseThrow(() -> new SessionNotFoundException("Session not found"));

        revokeAuthorization(userRepository.findById(caller.getUserId()).orElse(null), target);
        closeSession(target, target.getId().equals(caller.getId()) ? LOGOUT : SIGNED_OUT_FROM_ANOTHER_DEVICE);
        log.info("Session {} signed out by user id {}", target.getId(), caller.getUserId());
    }

    @Override
    @Transactional
    public int revokeOtherSessions(String token) {
        UserSession caller = activeSessionFor(token);
        User user = userRepository.findById(caller.getUserId()).orElse(null);
        List<UserSession> others = liveSessions(caller.getUserId(), user).stream()
                .filter(session -> !session.getId().equals(caller.getId()))
                .toList();
        others.forEach(session -> {
            revokeAuthorization(user, session);
            closeSession(session, SIGNED_OUT_FROM_ANOTHER_DEVICE);
        });
        log.info("{} other session(s) signed out by user id {}", others.size(), caller.getUserId());
        return others.size();
    }

    @Override
    @Transactional
    public void updateSessionOnRefresh(Long userId, String previousAccessToken, String newToken, String authorizationId) {
        Optional<UserSession> byPreviousToken = previousAccessToken == null
                ? Optional.empty()
                : userSessionRepository.findByTokenHash(tokenHasher.sha256Hex(previousAccessToken)).filter(UserSession::isActive);
        byPreviousToken.or(() -> onlyActiveSession(userId))
                .ifPresentOrElse(
                        session -> {
                            LocalDateTime now = LocalDateTime.now();
                            session.setTokenHash(tokenHasher.sha256Hex(newToken));
                            session.setAuthorizationId(authorizationId);
                            session.setCreatedAt(now);
                            session.setLastActiveAt(now);
                            userSessionRepository.save(session);
                            log.info("Session refreshed and TTL reset for user id: {}", userId);
                        },
                        () -> log.warn("No active session found for user id {} during refresh - nothing to update", userId)
                );
    }

    @Override
    @Transactional
    public boolean hasActiveSession(Long userId) {
        return !liveSessions(userId, userRepository.findById(userId).orElse(null)).isEmpty();
    }

    private List<UserSession> liveSessions(Long userId, User user) {
        List<UserSession> active = userSessionRepository.findAllByUserIdAndIsActiveTrue(userId);
        if (active.isEmpty()) {
            return active;
        }
        Set<String> liveAuthorizationIds = liveAuthorizationIds(user);
        long ttlDays = resolveSessionTtlDays(user);
        LocalDateTime now = LocalDateTime.now();

        List<UserSession> live = new ArrayList<>();
        for (UserSession session : active) {
            if (session.getCreatedAt() != null && now.isAfter(session.getCreatedAt().plusDays(ttlDays))) {
                log.info("Session {} for user id {} exceeded {}-day TTL - expiring", session.getId(), userId, ttlDays);
                closeSession(session, TTL_EXPIRED);
            } else if (session.getAuthorizationId() != null && !liveAuthorizationIds.contains(session.getAuthorizationId())) {
                closeSession(session, REFRESH_TOKEN_ENDED);
            } else {
                live.add(session);
            }
        }
        live.sort(Comparator.comparing(SessionManagementServiceImpl::lastActivity).reversed());
        return live;
    }

    private void signOutBeyondLimit(User user, int limit, UserSession justOpened) {
        List<UserSession> live = liveSessions(justOpened.getUserId(), user);
        int excess = live.size() - limit;
        if (excess <= 0) {
            return;
        }
        live.stream()
                .filter(session -> !session.getId().equals(justOpened.getId()))
                .sorted(Comparator.comparing(SessionManagementServiceImpl::lastActivity))
                .limit(excess)
                .forEach(session -> {
                    revokeAuthorization(user, session);
                    closeSession(session, SESSION_LIMIT_REACHED);
                    log.info("Session {} for user id {} signed out: {}-device limit reached", session.getId(), justOpened.getUserId(), limit);
                });
    }

    private Set<String> liveAuthorizationIds(User user) {
        if (user == null || user.getInternalAuthUserId() == null || user.getClientApplicationId() == null) {
            return Set.of();
        }
        Timestamp now = Timestamp.from(Instant.now());
        return new HashSet<>(jdbcTemplate.queryForList(LIVE_AUTHORIZATION_IDS_SQL, String.class,
                user.getInternalAuthUserId(), String.valueOf(user.getClientApplicationId()), now, now));
    }

    private void revokeAuthorization(User user, UserSession session) {
        if (session.getAuthorizationId() != null) {
            jdbcTemplate.update("DELETE FROM oauth2_authorization WHERE id = ?", session.getAuthorizationId());
            return;
        }
        if (user == null || user.getInternalAuthUserId() == null || user.getClientApplicationId() == null) {
            return;
        }
        jdbcTemplate.update(DELETE_UNCLAIMED_AUTHORIZATIONS_SQL,
                user.getInternalAuthUserId(), String.valueOf(user.getClientApplicationId()), user.getId());
    }

    private UserSession activeSessionFor(String token) {
        return userSessionRepository.findByTokenHash(tokenHasher.sha256Hex(token))
                .filter(UserSession::isActive)
                .orElseThrow(() -> new BadRequestException("No active session found"));
    }

    private Optional<UserSession> onlyActiveSession(Long userId) {
        List<UserSession> active = userSessionRepository.findAllByUserIdAndIsActiveTrue(userId);
        return active.size() == 1 ? Optional.of(active.get(0)) : Optional.empty();
    }

    private int maxActiveSessions(User user) {
        if (user == null || user.getClientApplicationId() == null) {
            return SINGLE_SESSION;
        }
        return clientApplicationService.getById(user.getClientApplicationId()).getMaxActiveSessions();
    }

    private OwnSessionResponse toOwnSession(UserSession session, boolean current, long ttlDays) {
        Instant created = session.getCreatedAt() == null ? Instant.now() : toInstant(session.getCreatedAt());
        Instant lastActive = session.getLastActiveAt() == null ? created : toInstant(session.getLastActiveAt());
        String deviceLabel = session.getDeviceLabel() != null ? session.getDeviceLabel() : DeviceLabelParser.label(session.getUserAgent());
        return new OwnSessionResponse(
                String.valueOf(session.getId()),
                deviceLabel,
                session.getUserAgent(),
                session.getIpAddress(),
                created,
                lastActive,
                created.plus(Duration.ofDays(ttlDays)),
                current);
    }

    private static LocalDateTime lastActivity(UserSession session) {
        if (session.getLastActiveAt() != null) {
            return session.getLastActiveAt();
        }
        return session.getCreatedAt() != null ? session.getCreatedAt() : LocalDateTime.MIN;
    }

    private static Instant toInstant(LocalDateTime value) {
        return value.atZone(ZoneId.systemDefault()).toInstant();
    }

    private long resolveSessionTtlDays(User user) {
        long refreshTtlDays = globalRefreshTokenTtlDays;
        if (user != null && user.getClientApplicationId() != null) {
            Integer perClientDays = clientApplicationService.getById(user.getClientApplicationId()).getRefreshTokenTtlDays();
            if (perClientDays != null) {
                refreshTtlDays = perClientDays.longValue();
            }
        }
        return Math.max(SESSION_TTL_DAYS, refreshTtlDays);
    }

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
