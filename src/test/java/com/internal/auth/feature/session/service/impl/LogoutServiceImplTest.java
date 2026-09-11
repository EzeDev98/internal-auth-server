package com.internal.auth.feature.session.service.impl;

import com.internal.auth.common.crypto.TokenHasher;
import com.internal.auth.common.exception.BadRequestException;
import com.internal.auth.feature.session.dto.LogoutResponse;
import com.internal.auth.feature.session.model.UserSession;
import com.internal.auth.feature.session.repository.UserSessionRepository;
import com.internal.auth.feature.session.service.SessionManagementService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class LogoutServiceImplTest {

    private final UserSessionRepository userSessionRepository = mock(UserSessionRepository.class);
    private final SessionManagementService sessionManagementService = mock(SessionManagementService.class);
    private final TokenHasher tokenHasher = mock(TokenHasher.class);
    private final OAuth2AuthorizationService authorizationService = mock(OAuth2AuthorizationService.class);

    private final LogoutServiceImpl service =
            new LogoutServiceImpl(userSessionRepository, sessionManagementService, tokenHasher, authorizationService);

    @Test
    void logout_nullToken_throwsBadRequestBeforeTouchingSessionLookup() {
        // The null/blank guard sits above logout()'s own try/catch, so this
        // propagates as a real exception (for GlobalExceptionHandler to
        // convert at the HTTP layer) rather than coming back as a
        // LogoutResponse - unlike every other failure path in this method.
        assertThatThrownBy(() -> service.logout(null))
                .isInstanceOf(BadRequestException.class)
                .hasMessage("Invalid token");

        verifyNoInteractions(userSessionRepository, sessionManagementService);
    }

    @Test
    void logout_blankToken_throwsBadRequestBeforeTouchingSessionLookup() {
        assertThatThrownBy(() -> service.logout("   "))
                .isInstanceOf(BadRequestException.class)
                .hasMessage("Invalid token");

        verifyNoInteractions(userSessionRepository, sessionManagementService);
    }

    @Test
    void logout_noSessionMatchesTheToken_returnsBadRequest_sessionManagementNeverInvoked() {
        when(tokenHasher.sha256Hex("tok")).thenReturn("hash");
        when(userSessionRepository.findByTokenHash("hash")).thenReturn(Optional.empty());

        LogoutResponse response = service.logout("tok");

        assertThat(response.getStatusCode()).isEqualTo(HttpServletResponse.SC_BAD_REQUEST);
        assertThat(response.getMessage()).contains("No active session found");
        verify(sessionManagementService, never()).invalidateSession(any());
    }

    @Test
    void logout_validTokenWithAMatchingSession_invalidatesItAndReturnsSuccess() {
        UserSession session = new UserSession();
        session.setPhoneNumber("08010000000");
        when(tokenHasher.sha256Hex("tok")).thenReturn("hash");
        when(userSessionRepository.findByTokenHash("hash")).thenReturn(Optional.of(session));

        LogoutResponse response = service.logout("tok");

        assertThat(response.getStatusCode()).isEqualTo(HttpServletResponse.SC_OK);
        assertThat(response.getMessage()).isEqualTo("Logout successful");
        verify(sessionManagementService).invalidateSession("tok");
    }

    @Test
    void logout_sessionManagementThrowsUnexpectedly_returnsAGracefulInternalServerErrorResponse() {
        UserSession session = new UserSession();
        when(tokenHasher.sha256Hex("tok")).thenReturn("hash");
        when(userSessionRepository.findByTokenHash("hash")).thenReturn(Optional.of(session));
        doThrow(new RuntimeException("redis unavailable")).when(sessionManagementService).invalidateSession("tok");

        LogoutResponse response = service.logout("tok");

        assertThat(response.getStatusCode()).isEqualTo(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        assertThat(response.getMessage()).isEqualTo("Logout failed. Please try again.");
    }
}
