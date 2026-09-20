package com.internal.auth.feature.identity.service.impl;

import com.internal.auth.common.exception.AccountDisabledException;
import com.internal.auth.common.exception.InvalidRefreshTokenException;
import com.internal.auth.common.reset.OtpResetEngine;
import com.internal.auth.common.reset.OtpService;
import com.internal.auth.common.reset.delivery.OtpDeliveryService;
import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.service.ClientApplicationService;
import com.internal.auth.feature.identity.config.LoginMfaProperties;
import com.internal.auth.feature.identity.dto.request.LoginRequest;
import com.internal.auth.feature.identity.dto.request.RefreshTokenRequest;
import com.internal.auth.feature.identity.dto.response.LoginResponse;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.identity.repository.LoginMfaOtpRepository;
import com.internal.auth.feature.identity.repository.UserRepository;
import com.internal.auth.feature.rbac.model.Role;
import com.internal.auth.feature.rbac.repository.UserRolesRepository;
import com.internal.auth.feature.session.service.SessionManagementService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.redisson.api.RedissonClient;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Covers the refresh-token paths added for persistent (non-rotating) clients:
 * sliding expiry, the absolute session cap, legacy authorizations without a
 * login stamp, the rotating path staying unchanged, and the per-client
 * revokePriorSessionsOnLogin toggle on login().
 */
class UserLoginServiceRefreshTest {

    private static final Long CLIENT_APP_ID = 7L;
    private static final String SELF_ISSUER_URI = "https://auth.example.com";
    private static final String SESSION_STARTED_AT = "internal_auth.session_started_at";
    private static final AuthorizationGrantType LOCAL_LOGIN = new AuthorizationGrantType("local_login");

    private final ApplicationEventPublisher eventPublisher = mock(ApplicationEventPublisher.class);
    private final UserRepository userRepository = mock(UserRepository.class);
    private final PasswordEncoder passwordEncoder = mock(PasswordEncoder.class);
    private final UserRolesRepository userRolesRepository = mock(UserRolesRepository.class);
    private final RegisteredClientRepository registeredClientRepository = mock(RegisteredClientRepository.class);
    private final OAuth2AuthorizationService authorizationService = mock(OAuth2AuthorizationService.class);
    @SuppressWarnings("unchecked")
    private final OAuth2TokenGenerator<OAuth2Token> tokenGenerator = mock(OAuth2TokenGenerator.class);
    private final ClientApplicationService clientApplicationService = mock(ClientApplicationService.class);
    private final SessionManagementService sessionManagementService = mock(SessionManagementService.class);
    private final JdbcTemplate jdbcTemplate = mock(JdbcTemplate.class);

    private final UserLoginServiceImpl service = new UserLoginServiceImpl(
            eventPublisher, userRepository, passwordEncoder, mock(LoginMfaOtpRepository.class), mock(OtpService.class),
            mock(OtpDeliveryService.class), mock(OtpResetEngine.class), new LoginMfaProperties(), mock(RedissonClient.class),
            userRolesRepository, registeredClientRepository, authorizationService, tokenGenerator,
            AuthorizationServerSettings.builder().issuer(SELF_ISSUER_URI).build(),
            clientApplicationService, sessionManagementService, jdbcTemplate);

    private ClientApplication client;
    private User user;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(service, "selfIssuerUri", SELF_ISSUER_URI);
        ReflectionTestUtils.setField(service, "globalRefreshTokenTtlDays", 30L);

        client = new ClientApplication();
        client.setId(CLIENT_APP_ID);
        client.setRefreshTokenRotationEnabled(false);
        client.setRefreshTokenTtlDays(60);
        when(clientApplicationService.getById(CLIENT_APP_ID)).thenReturn(client);

        user = new User();
        user.setId(1L);
        user.setClientApplicationId(CLIENT_APP_ID);
        user.setInternalAuthUserId("alice");
        user.setUsername("alice");
        user.setPassword("hashed-pw");
        user.setEmail("alice@example.com");
        user.setPhoneNumber("+2348000000001");
        user.setEnabled(true);
        user.setEmailVerified(true);
        user.setPhoneVerified(true);
        user.setMfaEnabled(false);
        when(userRepository.findByInternalAuthUserIdAndClientApplicationId("alice", CLIENT_APP_ID)).thenReturn(Optional.of(user));

        Role role = new Role();
        role.setRoleName("Buyer");
        when(userRolesRepository.findRolesByUserId(1L)).thenReturn(List.of(role));

        when(registeredClientRepository.findById("7")).thenReturn(registeredClient("7"));
        when(tokenGenerator.generate(any(OAuth2TokenContext.class)))
                .thenReturn(new AccessOnly("new-access", Instant.now(), Instant.now().plusSeconds(900)));
    }

    // ===================== persistent (non-rotating) refresh =====================

    @Test
    void nonRotating_refresh_keepsTheSameTokenValueAndSlidesExpiryByTheClientTtl() {
        OAuth2Authorization existing = authorization(registeredClient("7"), Instant.now().plus(Duration.ofDays(5)), Instant.now().minus(Duration.ofDays(10)));
        when(authorizationService.findByToken("refresh-1", OAuth2TokenType.REFRESH_TOKEN)).thenReturn(existing);

        Instant before = Instant.now();
        LoginResponse response = service.refreshToken(new RefreshTokenRequest("refresh-1"), CLIENT_APP_ID);
        Instant after = Instant.now();

        assertThat(response.getRefreshToken()).isEqualTo("refresh-1");
        assertThat(response.getAccessToken()).isEqualTo("new-access");
        verify(authorizationService, never()).remove(any());

        OAuth2RefreshToken saved = savedAuthorization().getRefreshToken().getToken();
        assertThat(saved.getTokenValue()).isEqualTo("refresh-1");
        assertThat(saved.getExpiresAt()).isBetween(before.plus(Duration.ofDays(60)), after.plus(Duration.ofDays(60)));
        verify(sessionManagementService).updateSessionOnRefresh(1L, "new-access");
    }

    @Test
    void nonRotating_refresh_fallsBackToTheGlobalTtlWhenTheClientHasNone() {
        client.setRefreshTokenTtlDays(null);
        OAuth2Authorization existing = authorization(registeredClient("7"), Instant.now().plus(Duration.ofDays(5)), Instant.now().minus(Duration.ofDays(1)));
        when(authorizationService.findByToken("refresh-1", OAuth2TokenType.REFRESH_TOKEN)).thenReturn(existing);

        Instant before = Instant.now();
        service.refreshToken(new RefreshTokenRequest("refresh-1"), CLIENT_APP_ID);
        Instant after = Instant.now();

        assertThat(savedAuthorization().getRefreshToken().getToken().getExpiresAt())
                .isBetween(before.plus(Duration.ofDays(30)), after.plus(Duration.ofDays(30)));
    }

    @Test
    void nonRotating_refresh_withCap_clampsTheSlidingExpiryToLoginTimePlusCap() {
        client.setRefreshTokenMaxLifetimeDays(90);
        Instant startedAt = Instant.now().minus(Duration.ofDays(50));
        OAuth2Authorization existing = authorization(registeredClient("7"), Instant.now().plus(Duration.ofDays(5)), startedAt);
        when(authorizationService.findByToken("refresh-1", OAuth2TokenType.REFRESH_TOKEN)).thenReturn(existing);

        service.refreshToken(new RefreshTokenRequest("refresh-1"), CLIENT_APP_ID);

        // now + 60d would land after the deadline (login + 90d = now + 40d), so it is clamped to it.
        assertThat(savedAuthorization().getRefreshToken().getToken().getExpiresAt())
                .isEqualTo(startedAt.plus(Duration.ofDays(90)));
    }

    @Test
    void nonRotating_refresh_pastTheCap_deletesTheAuthorizationAndReturnsTheGenericInvalidRefreshError() {
        client.setRefreshTokenMaxLifetimeDays(90);
        OAuth2Authorization existing = authorization(registeredClient("7"), Instant.now().plus(Duration.ofDays(5)), Instant.now().minus(Duration.ofDays(91)));
        when(authorizationService.findByToken("refresh-1", OAuth2TokenType.REFRESH_TOKEN)).thenReturn(existing);

        assertThatThrownBy(() -> service.refreshToken(new RefreshTokenRequest("refresh-1"), CLIENT_APP_ID))
                .isInstanceOfSatisfying(InvalidRefreshTokenException.class,
                        ex -> assertThat(ex.getMessage()).isEqualTo("Refresh token is invalid or expired"));

        verify(authorizationService).remove(existing);
        verify(authorizationService, never()).save(any());
        verifyNoInteractions(sessionManagementService);
    }

    @Test
    void nonRotating_refresh_withoutACap_neverExpiresByAge() {
        client.setRefreshTokenMaxLifetimeDays(null);
        OAuth2Authorization existing = authorization(registeredClient("7"), Instant.now().plus(Duration.ofDays(5)), Instant.now().minus(Duration.ofDays(400)));
        when(authorizationService.findByToken("refresh-1", OAuth2TokenType.REFRESH_TOKEN)).thenReturn(existing);

        LoginResponse response = service.refreshToken(new RefreshTokenRequest("refresh-1"), CLIENT_APP_ID);

        assertThat(response.getRefreshToken()).isEqualTo("refresh-1");
        verify(authorizationService, never()).remove(any());
    }

    @Test
    void nonRotating_refresh_legacyAuthorizationWithoutLoginStamp_isNotRejectedAndGetsStampedNow() {
        client.setRefreshTokenMaxLifetimeDays(90);
        OAuth2Authorization existing = authorization(registeredClient("7"), Instant.now().plus(Duration.ofDays(5)), null);
        when(authorizationService.findByToken("refresh-1", OAuth2TokenType.REFRESH_TOKEN)).thenReturn(existing);

        Instant before = Instant.now();
        service.refreshToken(new RefreshTokenRequest("refresh-1"), CLIENT_APP_ID);

        String stamped = savedAuthorization().getAttribute(SESSION_STARTED_AT);
        assertThat(stamped).isNotNull();
        assertThat(Instant.parse(stamped)).isAfterOrEqualTo(before);
    }

    // ===================== guards shared by both modes =====================

    @Test
    void refresh_tokenIssuedToAnotherClient_isRejectedWithoutChangingAnything() {
        OAuth2Authorization existing = authorization(registeredClient("8"), Instant.now().plus(Duration.ofDays(5)), Instant.now());
        when(authorizationService.findByToken("refresh-1", OAuth2TokenType.REFRESH_TOKEN)).thenReturn(existing);

        assertThatThrownBy(() -> service.refreshToken(new RefreshTokenRequest("refresh-1"), CLIENT_APP_ID))
                .isInstanceOf(InvalidRefreshTokenException.class);

        verify(authorizationService, never()).save(any());
        verify(authorizationService, never()).remove(any());
    }

    @Test
    void refresh_expiredRefreshToken_isRejected() {
        OAuth2Authorization existing = authorizationWithRefreshWindow(registeredClient("7"),
                Instant.now().minus(Duration.ofDays(2)), Instant.now().minus(Duration.ofDays(1)), Instant.now().minus(Duration.ofDays(2)));
        when(authorizationService.findByToken("refresh-1", OAuth2TokenType.REFRESH_TOKEN)).thenReturn(existing);

        assertThatThrownBy(() -> service.refreshToken(new RefreshTokenRequest("refresh-1"), CLIENT_APP_ID))
                .isInstanceOf(InvalidRefreshTokenException.class);

        verify(authorizationService, never()).save(any());
    }

    @Test
    void refresh_disabledAccount_isRejectedEvenWithAValidRefreshToken() {
        user.setEnabled(false);
        OAuth2Authorization existing = authorization(registeredClient("7"), Instant.now().plus(Duration.ofDays(5)), Instant.now());
        when(authorizationService.findByToken("refresh-1", OAuth2TokenType.REFRESH_TOKEN)).thenReturn(existing);

        assertThatThrownBy(() -> service.refreshToken(new RefreshTokenRequest("refresh-1"), CLIENT_APP_ID))
                .isInstanceOf(AccountDisabledException.class);

        verify(authorizationService, never()).save(any());
    }

    // ===================== rotating path is unchanged =====================

    @Test
    void rotating_refresh_removesTheSpentAuthorizationAndMintsANewOne() {
        client.setRefreshTokenRotationEnabled(true);
        client.setRefreshTokenTtlDays(null);
        Instant now = Instant.now();
        RegisteredClient withRefreshGrant = registeredClient("7");
        when(registeredClientRepository.findById("7")).thenReturn(withRefreshGrant);
        when(tokenGenerator.generate(any(OAuth2TokenContext.class))).thenAnswer(invocation -> {
            OAuth2TokenContext context = invocation.getArgument(0);
            if (OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())) {
                return new OAuth2RefreshToken("refresh-2", now, now.plus(Duration.ofDays(30)));
            }
            return new AccessOnly("new-access", now, now.plusSeconds(900));
        });
        OAuth2Authorization existing = authorization(withRefreshGrant, now.plus(Duration.ofDays(5)), now.minus(Duration.ofDays(1)));
        when(authorizationService.findByToken("refresh-1", OAuth2TokenType.REFRESH_TOKEN)).thenReturn(existing);

        LoginResponse response = service.refreshToken(new RefreshTokenRequest("refresh-1"), CLIENT_APP_ID);

        verify(authorizationService).remove(existing);
        assertThat(response.getRefreshToken()).isEqualTo("refresh-2");
        assertThat(savedAuthorization().getRefreshToken().getToken().getTokenValue()).isEqualTo("refresh-2");
    }

    // ===================== login(): revokePriorSessionsOnLogin toggle =====================

    @Test
    void login_revokePriorSessionsOn_deletesEarlierAuthorizationsForThatUserAndClient() {
        stubPasswordLogin();
        client.setRevokePriorSessionsOnLogin(true);

        service.login(new LoginRequest("alice", "Passw0rd!"), CLIENT_APP_ID);

        verify(jdbcTemplate).update(eq("DELETE FROM oauth2_authorization WHERE principal_name = ? AND registered_client_id = ?"),
                eq("alice"), eq("7"));
    }

    @Test
    void login_revokePriorSessionsOff_leavesOtherDevicesAuthorizationsAlone() {
        stubPasswordLogin();
        client.setRevokePriorSessionsOnLogin(false);

        LoginResponse response = service.login(new LoginRequest("alice", "Passw0rd!"), CLIENT_APP_ID);

        assertThat(response.getAccessToken()).isEqualTo("new-access");
        verifyNoInteractions(jdbcTemplate);
    }

    @Test
    void login_stampsTheOriginalLoginTimeOnTheNewAuthorization() {
        stubPasswordLogin();

        Instant before = Instant.now();
        service.login(new LoginRequest("alice", "Passw0rd!"), CLIENT_APP_ID);

        String stamped = savedAuthorization().getAttribute(SESSION_STARTED_AT);
        assertThat(stamped).isNotNull();
        assertThat(Instant.parse(stamped)).isAfterOrEqualTo(before);
    }

    // ===================== helpers =====================

    private void stubPasswordLogin() {
        when(userRepository.findByUsernameAndClientApplicationId("alice", CLIENT_APP_ID)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("Passw0rd!", "hashed-pw")).thenReturn(true);
    }

    private OAuth2Authorization savedAuthorization() {
        ArgumentCaptor<OAuth2Authorization> captor = ArgumentCaptor.forClass(OAuth2Authorization.class);
        verify(authorizationService).save(captor.capture());
        return captor.getValue();
    }

    private static RegisteredClient registeredClient(String id) {
        return RegisteredClient.withId(id)
                .clientId(id)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .build();
    }

    private static OAuth2Authorization authorization(RegisteredClient registeredClient, Instant refreshExpiresAt, Instant sessionStartedAt) {
        return authorizationWithRefreshWindow(registeredClient, Instant.now().minus(Duration.ofDays(1)), refreshExpiresAt, sessionStartedAt);
    }

    private static OAuth2Authorization authorizationWithRefreshWindow(RegisteredClient registeredClient, Instant refreshIssuedAt,
                                                                      Instant refreshExpiresAt, Instant sessionStartedAt) {
        OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName("alice")
                .authorizationGrantType(LOCAL_LOGIN)
                .authorizedScopes(Set.of())
                .accessToken(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "old-access",
                        refreshIssuedAt, refreshIssuedAt.plusSeconds(900)))
                .refreshToken(new OAuth2RefreshToken("refresh-1", refreshIssuedAt, refreshExpiresAt));
        if (sessionStartedAt != null) {
            builder.attribute(SESSION_STARTED_AT, sessionStartedAt.toString());
        }
        return builder.build();
    }

    /** Minimal access token - not a ClaimAccessor, so the plain accessToken(...) branch is used. */
    private record AccessOnly(String value, Instant issuedAt, Instant expiresAt) implements OAuth2Token {
        @Override
        public String getTokenValue() {
            return value;
        }

        @Override
        public Instant getIssuedAt() {
            return issuedAt;
        }

        @Override
        public Instant getExpiresAt() {
            return expiresAt;
        }
    }
}
