package com.internal.auth.feature.session.service.impl;

import com.internal.auth.common.crypto.TokenHasher;
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

    private final SessionManagementServiceImpl service =
            new SessionManagementServiceImpl(userSessionRepository, userRepository, tokenHasher);

    @Test
    void createSession_noExistingActiveSession_savesANewActiveSession() {
        when(userSessionRepository.findByUserIdAndIsActiveTrue(1L)).thenReturn(Optional.empty());
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
        when(userSessionRepository.findByUserIdAndIsActiveTrue(1L)).thenReturn(Optional.of(existing));
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
        when(userSessionRepository.findByUserIdAndIsActiveTrue(3L)).thenReturn(Optional.of(session));

        service.invalidateActiveSessionForUser(3L);

        assertThat(session.isActive()).isFalse();
        assertThat(session.getEndReason()).isEqualTo(ADMIN_ACTION);
    }

    @Test
    void invalidateActiveSessionForUser_noActiveSession_doesNothing() {
        when(userSessionRepository.findByUserIdAndIsActiveTrue(3L)).thenReturn(Optional.empty());

        service.invalidateActiveSessionForUser(3L);

        verify(userSessionRepository, never()).save(any());
    }

    @Test
    void invalidateUserSessionByAdmin_unknownUsernameInThatClientApplication_returnsNotFoundWithoutTouchingSessions() {
        when(userRepository.findByUsernameAndClientApplicationId("ghost", 9L)).thenReturn(Optional.empty());

        InvalidatedSessionResponse response = service.invalidateUserSessionByAdmin("ghost", 9L);

        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_NOT_FOUND);
        verify(userSessionRepository, never()).findByUserIdAndIsActiveTrue(any());
    }

    @Test
    void invalidateUserSessionByAdmin_userExistsButHasNoActiveSession_returnsNotFound() {
        User user = UserTestDataBuilder.aUser().withUsername("bob").build();
        user.setId(99L);
        when(userRepository.findByUsernameAndClientApplicationId("bob", 9L)).thenReturn(Optional.of(user));
        when(userSessionRepository.findByUserIdAndIsActiveTrue(99L)).thenReturn(Optional.empty());

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
        when(userSessionRepository.findByUserIdAndIsActiveTrue(99L)).thenReturn(Optional.of(session));

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
        when(userSessionRepository.findByUserIdAndIsActiveTrue(5L)).thenReturn(Optional.of(session));
        when(tokenHasher.sha256Hex("new-token")).thenReturn("new-hash");

        service.updateSessionOnRefresh(5L, "new-token");

        assertThat(session.getTokenHash()).isEqualTo("new-hash");
        assertThat(session.getCreatedAt()).isAfter(originalCreatedAt);
        verify(userSessionRepository).save(session);
    }

    @Test
    void updateSessionOnRefresh_noActiveSession_doesNothing() {
        when(userSessionRepository.findByUserIdAndIsActiveTrue(5L)).thenReturn(Optional.empty());

        service.updateSessionOnRefresh(5L, "new-token");

        verify(userSessionRepository, never()).save(any());
    }

    @Test
    void hasActiveSession_withinTtl_returnsTrueAndLeavesTheSessionUntouched() {
        UserSession session = new UserSession();
        session.setUserId(6L);
        session.setCreatedAt(LocalDateTime.now().minusDays(1));
        when(userSessionRepository.findByUserIdAndIsActiveTrue(6L)).thenReturn(Optional.of(session));

        boolean result = service.hasActiveSession(6L);

        assertThat(result).isTrue();
        verify(userSessionRepository, never()).save(any());
    }

    @Test
    void hasActiveSession_pastTheTtl_expiresTheSessionAndReturnsFalse() {
        UserSession session = new UserSession();
        session.setUserId(6L);
        session.setCreatedAt(LocalDateTime.now().minusDays(SESSION_TTL_DAYS + 1));
        when(userSessionRepository.findByUserIdAndIsActiveTrue(6L)).thenReturn(Optional.of(session));

        boolean result = service.hasActiveSession(6L);

        assertThat(result).isFalse();
        assertThat(session.isActive()).isFalse();
        assertThat(session.getEndReason()).isEqualTo(TTL_EXPIRED);
    }

    @Test
    void hasActiveSession_noSessionAtAll_returnsFalse() {
        when(userSessionRepository.findByUserIdAndIsActiveTrue(6L)).thenReturn(Optional.empty());

        boolean result = service.hasActiveSession(6L);

        assertThat(result).isFalse();
    }
}
