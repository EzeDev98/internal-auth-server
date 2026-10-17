package com.internal.auth.feature.session.service.impl;

import com.internal.auth.common.crypto.TokenHasher;
import com.internal.auth.feature.client.service.ClientApplicationService;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.identity.repository.UserRepository;
import com.internal.auth.feature.session.dto.InvalidatedSessionResponse;
import com.internal.auth.feature.session.model.UserSession;
import com.internal.auth.feature.session.repository.UserSessionRepository;
import com.internal.auth.testsupport.builder.UserTestDataBuilder;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import static com.internal.auth.common.constant.AppConstant.ADMIN_ACTION;
import static com.internal.auth.common.constant.AppConstant.LOGOUT;
import static com.internal.auth.common.constant.AppConstant.REPLACED_BY_NEW_LOGIN;
import static com.internal.auth.common.constant.AppConstant.SESSION_TTL_DAYS;
import static com.internal.auth.common.constant.AppConstant.TTL_EXPIRED;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Step 8A (service half). SessionManagementServiceImpl's own class Javadoc
 * documents the userId-keyed redesign (see that class) - these tests lock
 * in every branch of its public contract directly, as plain mock-based unit
 * tests against UserSessionRepository/UserRepository/TokenHasher.
 */
class SessionManagementServiceImplTest {

    private final UserSessionRepository userSessionRepository = mock(UserSessionRepository.class);
    private final UserRepository userRepository = mock(UserRepository.class);
    private final TokenHasher tokenHasher = mock(TokenHasher.class);
    private final ClientApplicationService clientApplicationService = mock(ClientApplicationService.class);
    private final org.springframework.jdbc.core.JdbcTemplate jdbcTemplate = mock(org.springframework.jdbc.core.JdbcTemplate.class);

    private final SessionManagementServiceImpl service =
            new SessionManagementServiceImpl(userSessionRepository, userRepository, tokenHasher, clientApplicationService, jdbcTemplate);

    @Test
    void createSession_noExistingActiveSession_savesANewActiveSession() {
        when(userSessionRepository.findAllByUserIdAndIsActiveTrue(1L)).thenReturn(List.of());
        when(tokenHasher.sha256Hex("raw-token")).thenReturn("hashed-token");

        service.createSession(1L, "08010000000", "raw-token");

        ArgumentCaptor<UserSession> captor = ArgumentCaptor.forClass(UserSession.class);
        verify(userSessionRepository, times(1)).save(captor.capture());
        UserSession saved = captor.getValue();
        assertThat(saved.getUserId()).isEqualTo(1L);
        assertThat(saved.getPhoneNumber()).isEqualTo("08010000000");
        assertThat(saved.getTokenHash()).isEqualTo("hashed-token");
        assertThat(saved.isActive()).isTrue();
        assertThat(saved.getCreatedAt()).isNotNull();
    }

    @Test
    void createSession_existingActiveSession_closesTheOldOneAsReplacedByNewLogin_thenSavesTheNewOne() {
        UserSession existing = new UserSession();
        existing.setUserId(1L);
        existing.setActive(true);
        when(userSessionRepository.findAllByUserIdAndIsActiveTrue(1L)).thenReturn(List.of(existing));
        when(tokenHasher.sha256Hex("raw-token")).thenReturn("hashed-token");

        service.createSession(1L, "08010000000", "raw-token");

        ArgumentCaptor<UserSession> captor = ArgumentCaptor.forClass(UserSession.class);
        verify(userSessionRepository, times(2)).save(captor.capture());
        UserSession closedOld = captor.getAllValues().get(0);
        assertThat(closedOld).isSameAs(existing);
        assertThat(closedOld.isActive()).isFalse();
        assertThat(closedOld.getEndReason()).isEqualTo(REPLACED_BY_NEW_LOGIN);
        assertThat(closedOld.getEndedAt()).isNotNull();
        UserSession newSession = captor.getAllValues().get(1);
        assertThat(newSession).isNotSameAs(existing);
        assertThat(newSession.isActive()).isTrue();
    }

    @Test
    void createSession_sameTokenAlreadyTracked_keepsTheExistingRowAndSavesNothing() {
        UserSession existing = new UserSession();
        existing.setUserId(1L);
        existing.setActive(true);
        existing.setTokenHash("hashed-token");
        when(userSessionRepository.findByTokenHash("hashed-token")).thenReturn(Optional.of(existing));
        when(tokenHasher.sha256Hex("raw-token")).thenReturn("hashed-token");

        service.createSession(1L, "08010000000", "raw-token");

        verify(userSessionRepository, never()).save(org.mockito.ArgumentMatchers.any(UserSession.class));
        assertThat(existing.isActive()).isTrue();
    }

    @Test
    void invalidateSession_matchingToken_closesItWithLogoutReason() {
        UserSession session = new UserSession();
        session.setUserId(2L);
        session.setActive(true);
        when(tokenHasher.sha256Hex("tok")).thenReturn("hash");
        when(userSessionRepository.findByTokenHash("hash")).thenReturn(Optional.of(session));

        service.invalidateSession("tok");

        assertThat(session.isActive()).isFalse();
        assertThat(session.getEndReason()).isEqualTo(LOGOUT);
        verify(userSessionRepository).save(session);
    }

    @Test
    void invalidateSession_noMatchingToken_doesNothing() {
        when(tokenHasher.sha256Hex("tok")).thenReturn("hash");
        when(userSessionRepository.findByTokenHash("hash")).thenReturn(Optional.empty());

        service.invalidateSession("tok");

        verify(userSessionRepository, never()).save(any());
    }

    @Test
    void invalidateActiveSessionForUser_existingActiveSession_closesItWithAdminActionReason() {
        UserSession session = new UserSession();
        session.setUserId(3L);
        session.setActive(true);
        when(userSessionRepository.findAllByUserIdAndIsActiveTrue(3L)).thenReturn(List.of(session));

        service.invalidateActiveSessionForUser(3L);

        assertThat(session.isActive()).isFalse();
        assertThat(session.getEndReason()).isEqualTo(ADMIN_ACTION);
    }

    @Test
    void invalidateActiveSessionForUser_noActiveSession_doesNothing() {
        when(userSessionRepository.findAllByUserIdAndIsActiveTrue(3L)).thenReturn(List.of());

        service.invalidateActiveSessionForUser(3L);

        verify(userSessionRepository, never()).save(any());
    }

    @Test
    void invalidateActiveSessionForUser_alsoDeletesThatUsersRefreshTokensForTheirClient() {
        User user = new User();
        user.setId(3L);
        user.setInternalAuthUserId("alice");
        user.setClientApplicationId(9L);
        when(userRepository.findById(3L)).thenReturn(Optional.of(user));
        when(userSessionRepository.findAllByUserIdAndIsActiveTrue(3L)).thenReturn(List.of());

        service.invalidateActiveSessionForUser(3L);

        verify(jdbcTemplate).update(org.mockito.ArgumentMatchers.eq("DELETE FROM oauth2_authorization WHERE principal_name = ? AND registered_client_id = ?"),
                org.mockito.ArgumentMatchers.eq("alice"), org.mockito.ArgumentMatchers.eq("9"));
    }

    @Test
    void invalidateActiveSessionForUser_unknownUser_deletesNoAuthorizations() {
        when(userRepository.findById(3L)).thenReturn(Optional.empty());
        when(userSessionRepository.findAllByUserIdAndIsActiveTrue(3L)).thenReturn(List.of());

        service.invalidateActiveSessionForUser(3L);

        org.mockito.Mockito.verifyNoInteractions(jdbcTemplate);
    }

    @Test
    void invalidateUserSessionByAdmin_deletesRefreshTokensEvenWhenNoTrackedSessionExists() {
        User user = new User();
        user.setId(4L);
        user.setInternalAuthUserId("bob");
        user.setClientApplicationId(9L);
        when(userRepository.findByUsernameAndClientApplicationId("bob", 9L)).thenReturn(Optional.of(user));
        when(userSessionRepository.findAllByUserIdAndIsActiveTrue(4L)).thenReturn(List.of());

        InvalidatedSessionResponse response = service.invalidateUserSessionByAdmin("bob", 9L);

        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_NOT_FOUND);
        verify(jdbcTemplate).update(org.mockito.ArgumentMatchers.eq("DELETE FROM oauth2_authorization WHERE principal_name = ? AND registered_client_id = ?"),
                org.mockito.ArgumentMatchers.eq("bob"), org.mockito.ArgumentMatchers.eq("9"));
    }

    @Test
    void invalidateUserSessionByAdmin_unknownUsernameInThatClientApplication_returnsNotFoundWithoutTouchingSessions() {
        when(userRepository.findByUsernameAndClientApplicationId("ghost", 9L)).thenReturn(Optional.empty());

        InvalidatedSessionResponse response = service.invalidateUserSessionByAdmin("ghost", 9L);

        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_NOT_FOUND);
        verify(userSessionRepository, never()).findAllByUserIdAndIsActiveTrue(any());
    }

    @Test
    void invalidateUserSessionByAdmin_userExistsButHasNoActiveSession_returnsNotFound() {
        User user = UserTestDataBuilder.aUser().withUsername("bob").build();
        user.setId(99L);
        when(userRepository.findByUsernameAndClientApplicationId("bob", 9L)).thenReturn(Optional.of(user));
        when(userSessionRepository.findAllByUserIdAndIsActiveTrue(99L)).thenReturn(List.of());

        InvalidatedSessionResponse response = service.invalidateUserSessionByAdmin("bob", 9L);

        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_NOT_FOUND);
        assertThat(response.getMessage()).contains("No active session found");
    }

    @Test
    void invalidateUserSessionByAdmin_userWithAnActiveSession_closesItAndReturnsOk() {
        User user = UserTestDataBuilder.aUser().withUsername("bob").build();
        user.setId(99L);
        UserSession session = new UserSession();
        session.setUserId(99L);
        session.setActive(true);
        when(userRepository.findByUsernameAndClientApplicationId("bob", 9L)).thenReturn(Optional.of(user));
        when(userSessionRepository.findAllByUserIdAndIsActiveTrue(99L)).thenReturn(List.of(session));

        InvalidatedSessionResponse response = service.invalidateUserSessionByAdmin("bob", 9L);

        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
        assertThat(session.isActive()).isFalse();
        assertThat(session.getEndReason()).isEqualTo(ADMIN_ACTION);
    }

    @Test
    void updateSessionOnRefresh_activeSession_replacesTokenHashAndResetsTheTtlClock() {
        UserSession session = new UserSession();
        session.setUserId(5L);
        session.setTokenHash("old-hash");
        LocalDateTime originalCreatedAt = LocalDateTime.now().minusDays(1);
        session.setCreatedAt(originalCreatedAt);
        when(userSessionRepository.findAllByUserIdAndIsActiveTrue(5L)).thenReturn(List.of(session));
        when(tokenHasher.sha256Hex("new-token")).thenReturn("new-hash");

        service.updateSessionOnRefresh(5L, null, "new-token", "auth-1");

        assertThat(session.getTokenHash()).isEqualTo("new-hash");
        assertThat(session.getCreatedAt()).isAfter(originalCreatedAt);
        assertThat(session.getAuthorizationId()).isEqualTo("auth-1");
        assertThat(session.getLastActiveAt()).isNotNull();
        verify(userSessionRepository).save(session);
    }

    @Test
    void updateSessionOnRefresh_noActiveSession_doesNothing() {
        when(userSessionRepository.findAllByUserIdAndIsActiveTrue(5L)).thenReturn(List.of());

        service.updateSessionOnRefresh(5L, null, "new-token", null);

        verify(userSessionRepository, never()).save(any());
    }

    @Test
    void hasActiveSession_withinTtl_returnsTrueAndLeavesTheSessionUntouched() {
        UserSession session = new UserSession();
        session.setUserId(6L);
        session.setCreatedAt(LocalDateTime.now().minusDays(1));
        when(userSessionRepository.findAllByUserIdAndIsActiveTrue(6L)).thenReturn(List.of(session));

        boolean result = service.hasActiveSession(6L);

        assertThat(result).isTrue();
        verify(userSessionRepository, never()).save(any());
    }

    @Test
    void hasActiveSession_pastTheTtl_expiresTheSessionAndReturnsFalse() {
        UserSession session = new UserSession();
        session.setUserId(6L);
        session.setCreatedAt(LocalDateTime.now().minusDays(SESSION_TTL_DAYS + 1));
        when(userSessionRepository.findAllByUserIdAndIsActiveTrue(6L)).thenReturn(List.of(session));

        boolean result = service.hasActiveSession(6L);

        assertThat(result).isFalse();
        assertThat(session.isActive()).isFalse();
        assertThat(session.getEndReason()).isEqualTo(TTL_EXPIRED);
    }

    @Test
    void hasActiveSession_noSessionAtAll_returnsFalse() {
        when(userSessionRepository.findAllByUserIdAndIsActiveTrue(6L)).thenReturn(List.of());

        boolean result = service.hasActiveSession(6L);

        assertThat(result).isFalse();
    }
}
