package com.internal.auth.config.auth;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.internal.auth.config.redis.SessionStorage;
import com.internal.auth.common.security.AuthenticationHelper;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.identity.repository.UserRepository;
import com.internal.auth.feature.session.service.SessionManagementService;
import com.internal.auth.testsupport.builder.UserTestDataBuilder;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Step 8A. The behavior under test here is the fix described on
 * SessionManagementServiceImpl's class Javadoc and this filter's own
 * resolveUser() Javadoc: once a username can exist in more than one
 * client application (multi-tenant redesign), a token carrying no
 * client_application_id claim (a Keycloak-issued token, which predates the
 * tenant concept) can no longer safely guess which tenant's user a bare
 * username refers to. The filter must skip session tracking entirely in
 * that case - not silently attach the session to an arbitrary match - and
 * log it, so the gap is visible rather than swallowed.
 */
class JwtSessionTrackingFilterTest {

    private final SessionManagementService sessionManagementService = mock(SessionManagementService.class);
    private final SessionStorage sessionStorage = mock(SessionStorage.class);
    private final UserRepository userRepository = mock(UserRepository.class);
    private final AuthenticationHelper authenticationHelper = new AuthenticationHelper();

    private final JwtSessionTrackingFilter filter =
            new JwtSessionTrackingFilter(sessionManagementService, sessionStorage, authenticationHelper, userRepository);

    private final HttpServletRequest request = mock(HttpServletRequest.class);
    private final HttpServletResponse response = mock(HttpServletResponse.class);
    private final FilterChain filterChain = mock(FilterChain.class);

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void skipsTracking_whenUsernameIsAmbiguousAcrossTenants_andLogsAWarning() throws Exception {
        authenticateAs(jwtWithClaims(Map.of("preferred_username", "shared_username")));
        when(sessionStorage.getCache(eq("JWT_SESSION_TRACKED"), any())).thenReturn(null);
        when(request.getHeader("Authorization")).thenReturn("Bearer some.raw.token");
        User tenantOneUser = UserTestDataBuilder.aUser().withUsername("shared_username").withClientApplicationId(1L).build();
        User tenantTwoUser = UserTestDataBuilder.aUser().withUsername("shared_username").withClientApplicationId(2L).build();
        when(userRepository.findAllByUsername("shared_username")).thenReturn(List.of(tenantOneUser, tenantTwoUser));

        Logger filterLogger = (Logger) LoggerFactory.getLogger(JwtSessionTrackingFilter.class);
        ListAppender<ILoggingEvent> logCapture = new ListAppender<>();
        logCapture.start();
        filterLogger.addAppender(logCapture);

        try {
            filter.doFilterInternal(request, response, filterChain);
        } finally {
            filterLogger.detachAppender(logCapture);
        }

        verify(sessionManagementService, never()).createSession(anyLong(), any(), any());
        verify(sessionStorage, never()).putCache(anyString(), any(), any(), anyLong());
        assertThat(logCapture.list)
                .anySatisfy(event -> {
                    assertThat(event.getLevel()).isEqualTo(Level.WARN);
                    assertThat(event.getFormattedMessage()).contains("Skipping session tracking").contains("shared_username");
                });
        // Session bookkeeping is never allowed to block the real request.
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void tracksSession_scopedByClientApplicationId_whenTheTokenCarriesThatClaim() throws Exception {
        authenticateAs(jwtWithClaims(Map.of("preferred_username", "alice", "client_application_id", 5L)));
        when(sessionStorage.getCache(eq("JWT_SESSION_TRACKED"), any())).thenReturn(null);
        when(request.getHeader("Authorization")).thenReturn("Bearer raw-token-value");
        User user = UserTestDataBuilder.aUser().withUsername("alice").withClientApplicationId(5L).withPhoneNumber("08010000001").build();
        user.setId(42L);
        when(userRepository.findByUsernameAndClientApplicationId("alice", 5L)).thenReturn(Optional.of(user));

        filter.doFilterInternal(request, response, filterChain);

        verify(sessionManagementService).createSession(42L, "08010000001", "raw-token-value");
        verify(userRepository, never()).findAllByUsername(any());
        verify(sessionStorage).putCache(eq("JWT_SESSION_TRACKED"), any(), eq(Boolean.TRUE), eq(300L));
    }

    @Test
    void tracksSession_viaUnscopedFallback_whenNoClientApplicationIdClaimAndExactlyOneMatch() throws Exception {
        authenticateAs(jwtWithClaims(Map.of("preferred_username", "bob")));
        when(sessionStorage.getCache(eq("JWT_SESSION_TRACKED"), any())).thenReturn(null);
        when(request.getHeader("Authorization")).thenReturn("Bearer raw-token-value");
        User user = UserTestDataBuilder.aUser().withUsername("bob").build();
        user.setId(7L);
        when(userRepository.findAllByUsername("bob")).thenReturn(List.of(user));

        filter.doFilterInternal(request, response, filterChain);

        verify(sessionManagementService).createSession(eq(7L), any(), eq("raw-token-value"));
    }

    @Test
    void skipsTheDatabaseEntirely_whenThisSessionWasAlreadyTrackedRecently() throws Exception {
        authenticateAs(jwtWithClaims(Map.of("preferred_username", "alice")));
        when(sessionStorage.getCache(eq("JWT_SESSION_TRACKED"), any())).thenReturn(Boolean.TRUE);

        filter.doFilterInternal(request, response, filterChain);

        verifyNoInteractions(userRepository);
        verify(sessionManagementService, never()).createSession(anyLong(), any(), any());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void skipsTracking_whenThereIsNoJwtAuthenticatedPrincipal() throws Exception {
        // SecurityContextHolder left empty - no login-adjacent request at all.

        filter.doFilterInternal(request, response, filterChain);

        verifyNoInteractions(sessionManagementService, sessionStorage, userRepository);
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void swallowsAnyFailure_soTrackingCanNeverBreakTheRealRequest() throws Exception {
        authenticateAs(jwtWithClaims(Map.of("preferred_username", "alice")));
        when(sessionStorage.getCache(eq("JWT_SESSION_TRACKED"), any())).thenReturn(null);
        when(request.getHeader("Authorization")).thenReturn("Bearer raw-token-value");
        User user = UserTestDataBuilder.aUser().withUsername("alice").build();
        user.setId(1L);
        when(userRepository.findAllByUsername("alice")).thenReturn(List.of(user));
        doThrow(new RuntimeException("db unavailable")).when(sessionManagementService).createSession(anyLong(), any(), any());

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }

    @Test
    void extractSessionId_prefersTheSidClaimOverSessionState() {
        Jwt jwt = jwtWithClaims(Map.of("sid", "sid-value", "session_state", "session-state-value"));

        assertThat(JwtSessionTrackingFilter.extractSessionId(jwt)).isEqualTo("sid-value");
    }

    @Test
    void extractSessionId_fallsBackToSessionState_whenSidIsAbsent() {
        Jwt jwt = jwtWithClaims(Map.of("session_state", "session-state-value"));

        assertThat(JwtSessionTrackingFilter.extractSessionId(jwt)).isEqualTo("session-state-value");
    }

    private void authenticateAs(Jwt jwt) {
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken(jwt, null));
    }

    private Jwt jwtWithClaims(Map<String, Object> claims) {
        Jwt.Builder builder = Jwt.withTokenValue("test-token-value")
                .header("alg", "RS256")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(300))
                .claim("sub", "test-subject");
        claims.forEach(builder::claim);
        return builder.build();
    }
}
