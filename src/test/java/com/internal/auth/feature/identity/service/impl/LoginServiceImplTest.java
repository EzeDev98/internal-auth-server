package com.internal.auth.feature.identity.service.impl;

import com.internal.auth.common.exception.AccountDisabledException;
import com.internal.auth.common.exception.AccountNotVerifiedException;
import com.internal.auth.common.exception.InvalidCredentialsException;
import com.internal.auth.feature.audit.event.UserLoggedInEvent;
import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.service.ClientApplicationService;
import com.internal.auth.feature.identity.dto.request.LoginRequest;
import com.internal.auth.feature.identity.dto.response.LoginResponse;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.identity.repository.UserRepository;
import com.internal.auth.feature.session.service.SessionManagementService;
import com.internal.auth.feature.rbac.model.Role;
import com.internal.auth.feature.rbac.repository.UserRolesRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/** Unit tests for UserLoginServiceImpl login flows. */
class LoginServiceImplTest {

    private static final Long CLIENT_APP_ID = 7L;
    private static final String SELF_ISSUER_URI = "https://auth.example.com";

    private final ApplicationEventPublisher eventPublisher = mock(ApplicationEventPublisher.class);
    private final UserRepository userRepository = mock(UserRepository.class);
    private final PasswordEncoder passwordEncoder = mock(PasswordEncoder.class);
    private final UserRolesRepository userRolesRepository = mock(UserRolesRepository.class);
    private final RegisteredClientRepository registeredClientRepository = mock(RegisteredClientRepository.class);
    private final OAuth2AuthorizationService authorizationService = mock(OAuth2AuthorizationService.class);
    @SuppressWarnings("unchecked")
    private final OAuth2TokenGenerator<OAuth2Token> tokenGenerator = mock(OAuth2TokenGenerator.class);
    private final AuthorizationServerSettings authorizationServerSettings =
            AuthorizationServerSettings.builder().issuer(SELF_ISSUER_URI).build();
    private final ClientApplicationService clientApplicationService = mock(ClientApplicationService.class);
    private final SessionManagementService sessionManagementService = mock(SessionManagementService.class);
    private final org.springframework.jdbc.core.JdbcTemplate jdbcTemplate = mock(org.springframework.jdbc.core.JdbcTemplate.class);

    private final UserLoginServiceImpl service = new UserLoginServiceImpl(
            eventPublisher, userRepository, passwordEncoder, userRolesRepository,
            registeredClientRepository, authorizationService, tokenGenerator, authorizationServerSettings,
            clientApplicationService, sessionManagementService, jdbcTemplate);

    @BeforeEach
    void wireSelfIssuerUri() {
        ReflectionTestUtils.setField(service, "selfIssuerUri", SELF_ISSUER_URI);
        when(clientApplicationService.getById(CLIENT_APP_ID)).thenReturn(clientApplication("TestApp"));
    }

    private static LoginRequest loginRequest(String username, String password) {
        return new LoginRequest(username, password);
    }

    private static User activeVerifiedUser() {
        User user = new User();
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
        return user;
    }

    private static Role role(String name) {
        Role role = new Role();
        role.setRoleName(name);
        return role;
    }

    private static RegisteredClient registeredClient(String id) {
        return RegisteredClient.withId(id)
                .clientId(id)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .build();
    }

    private static ClientApplication clientApplication(String name) {
        ClientApplication app = new ClientApplication();
        app.setName(name);
        return app;
    }

    private static final class PlainToken implements OAuth2Token {
        private final String value;
        private final Instant issuedAt;
        private final Instant expiresAt;

        PlainToken(String value, Instant issuedAt, Instant expiresAt) {
            this.value = value;
            this.issuedAt = issuedAt;
            this.expiresAt = expiresAt;
        }

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

    private static final class ClaimBearingToken implements OAuth2Token, ClaimAccessor {
        private final String value;
        private final Map<String, Object> claims;

        ClaimBearingToken(String value, Map<String, Object> claims) {
            this.value = value;
            this.claims = claims;
        }

        @Override
        public String getTokenValue() {
            return value;
        }

        @Override
        public Instant getIssuedAt() {
            return Instant.now();
        }

        @Override
        public Instant getExpiresAt() {
            return Instant.now().plusSeconds(3600);
        }

        @Override
        public Map<String, Object> getClaims() {
            return claims;
        }
    }

    private void stubSuccessfulMinting(User user, OAuth2Token generatedToken) {
        when(registeredClientRepository.findById(String.valueOf(CLIENT_APP_ID))).thenReturn(registeredClient("7"));
        when(userRolesRepository.findRolesByUserId(user.getId())).thenReturn(List.of(role("Buyer")));
        when(tokenGenerator.generate(any(OAuth2TokenContext.class))).thenReturn(generatedToken);
    }

    @Test
    void login_nullUsername_throwsInvalidCredentialsWithoutTouchingRepository() {
        assertThatThrownBy(() -> service.login(loginRequest(null, "Passw0rd!"), CLIENT_APP_ID))
                .isInstanceOfSatisfying(InvalidCredentialsException.class,
                        ex -> assertThat(ex.getMessage()).isEqualTo("Username or password is incorrect"));

        verifyNoInteractions(userRepository, passwordEncoder);
    }

    @Test
    void login_blankUsername_throwsInvalidCredentials() {
        assertThatThrownBy(() -> service.login(loginRequest("   ", "Passw0rd!"), CLIENT_APP_ID))
                .isInstanceOf(InvalidCredentialsException.class);

        verifyNoInteractions(userRepository);
    }

    @Test
    void login_nullPassword_throwsInvalidCredentialsWithoutTouchingRepository() {
        assertThatThrownBy(() -> service.login(loginRequest("alice", null), CLIENT_APP_ID))
                .isInstanceOf(InvalidCredentialsException.class);

        verifyNoInteractions(userRepository);
    }

    @Test
    void login_userNotFoundForTenant_throwsInvalidCredentialsAndNeverTouchesPasswordEncoder() {
        when(userRepository.findByUsernameAndClientApplicationId("alice", CLIENT_APP_ID)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.login(loginRequest("alice", "Passw0rd!"), CLIENT_APP_ID))
                .isInstanceOfSatisfying(InvalidCredentialsException.class,
                        ex -> assertThat(ex.getMessage()).isEqualTo("Username or password is incorrect"));

        verifyNoInteractions(passwordEncoder);
    }

    @Test
    void login_currentBehavior_userLookupIsScopedByClientApplicationIdNeverUnscoped() {
        when(userRepository.findByUsernameAndClientApplicationId("alice", CLIENT_APP_ID)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.login(loginRequest("alice", "Passw0rd!"), CLIENT_APP_ID))
                .isInstanceOf(InvalidCredentialsException.class);

        verify(userRepository, never()).findByUsername(anyString());
    }

    @Test
    void login_storedPasswordIsNull_throwsInvalidCredentialsAndNeverCallsPasswordEncoder() {
        User user = activeVerifiedUser();
        user.setPassword(null);
        when(userRepository.findByUsernameAndClientApplicationId("alice", CLIENT_APP_ID)).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> service.login(loginRequest("alice", "Passw0rd!"), CLIENT_APP_ID))
                .isInstanceOfSatisfying(InvalidCredentialsException.class,
                        ex -> assertThat(ex.getMessage()).isEqualTo("Username or password is incorrect"));

        verify(passwordEncoder, never()).matches(any(), any());
    }

    @Test
    void login_wrongPassword_throwsInvalidCredentialsWithSameGenericMessageAsUnknownUser() {
        User user = activeVerifiedUser();
        when(userRepository.findByUsernameAndClientApplicationId("alice", CLIENT_APP_ID)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("wrong", "hashed-pw")).thenReturn(false);

        assertThatThrownBy(() -> service.login(loginRequest("alice", "wrong"), CLIENT_APP_ID))
                .isInstanceOfSatisfying(InvalidCredentialsException.class,
                        ex -> assertThat(ex.getMessage()).isEqualTo("Username or password is incorrect"));
    }

    @Test
    void login_disabledAccount_afterPasswordConfirmedCorrect_throwsAccountDisabled() {
        User user = activeVerifiedUser();
        user.setEnabled(false);
        when(userRepository.findByUsernameAndClientApplicationId("alice", CLIENT_APP_ID)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("Passw0rd!", "hashed-pw")).thenReturn(true);

        assertThatThrownBy(() -> service.login(loginRequest("alice", "Passw0rd!"), CLIENT_APP_ID))
                .isInstanceOfSatisfying(AccountDisabledException.class,
                        ex -> assertThat(ex.getMessage()).isEqualTo("This account has been disabled."));

        verifyNoInteractions(eventPublisher, tokenGenerator);
    }

    @Test
    void login_unverifiedEmailOnly_throwsAccountNotVerifiedWithEmailMessage() {
        User user = activeVerifiedUser();
        user.setEmailVerified(false);
        user.setPhoneNumber(null);
        when(userRepository.findByUsernameAndClientApplicationId("alice", CLIENT_APP_ID)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("Passw0rd!", "hashed-pw")).thenReturn(true);

        assertThatThrownBy(() -> service.login(loginRequest("alice", "Passw0rd!"), CLIENT_APP_ID))
                .isInstanceOfSatisfying(AccountNotVerifiedException.class,
                        ex -> assertThat(ex.getMessage()).isEqualTo("Please verify your email before logging in."));
    }

    @Test
    void login_unverifiedPhoneOnly_throwsAccountNotVerifiedWithPhoneMessage() {
        User user = activeVerifiedUser();
        user.setEmail(null);
        user.setPhoneVerified(false);
        when(userRepository.findByUsernameAndClientApplicationId("alice", CLIENT_APP_ID)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("Passw0rd!", "hashed-pw")).thenReturn(true);

        assertThatThrownBy(() -> service.login(loginRequest("alice", "Passw0rd!"), CLIENT_APP_ID))
                .isInstanceOfSatisfying(AccountNotVerifiedException.class,
                        ex -> assertThat(ex.getMessage()).isEqualTo("Please verify your phone number before logging in."));
    }

    @Test
    void login_unverifiedEmailAndPhone_throwsAccountNotVerifiedWithCombinedMessage() {
        User user = activeVerifiedUser();
        user.setEmailVerified(false);
        user.setPhoneVerified(false);
        when(userRepository.findByUsernameAndClientApplicationId("alice", CLIENT_APP_ID)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("Passw0rd!", "hashed-pw")).thenReturn(true);

        assertThatThrownBy(() -> service.login(loginRequest("alice", "Passw0rd!"), CLIENT_APP_ID))
                .isInstanceOfSatisfying(AccountNotVerifiedException.class,
                        ex -> assertThat(ex.getMessage()).isEqualTo("Please verify your email or phone number before logging in."));
    }

    @Test
    void login_verifiedEmailWithUnverifiedPhone_loginSucceeds() {
        User user = activeVerifiedUser();
        user.setEmailVerified(true);
        user.setPhoneVerified(false);
        when(userRepository.findByUsernameAndClientApplicationId("alice", CLIENT_APP_ID)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("Passw0rd!", "hashed-pw")).thenReturn(true);
        stubSuccessfulMinting(user, new PlainToken("tok", Instant.now(), Instant.now().plusSeconds(60)));

        LoginResponse response = service.login(loginRequest("alice", "Passw0rd!"), CLIENT_APP_ID);

        assertThat(response.getMessage()).isEqualTo("Login successful.");
    }

    @Test
    void login_currentBehavior_absentContactMethodIsNeverALoginBlocker() {
        User user = activeVerifiedUser();
        user.setEmail(null);
        user.setEmailVerified(false);
        user.setPhoneNumber(null);
        user.setPhoneVerified(false);
        when(userRepository.findByUsernameAndClientApplicationId("alice", CLIENT_APP_ID)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("Passw0rd!", "hashed-pw")).thenReturn(true);
        stubSuccessfulMinting(user, new PlainToken("tok", Instant.now(), Instant.now().plusSeconds(60)));

        LoginResponse response = service.login(loginRequest("alice", "Passw0rd!"), CLIENT_APP_ID);

        assertThat(response.getMessage()).isEqualTo("Login successful.");
    }

    @Test
    void login_success_mintsAccessTokenAndPersistsAuthorizationBuiltFromContext() {
        User user = activeVerifiedUser();
        when(userRepository.findByUsernameAndClientApplicationId("alice", CLIENT_APP_ID)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("Passw0rd!", "hashed-pw")).thenReturn(true);

        RegisteredClient client = registeredClient("7");
        when(registeredClientRepository.findById("7")).thenReturn(client);
        when(userRolesRepository.findRolesByUserId(1L)).thenReturn(List.of(role("ADMIN"), role("Buyer")));
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plusSeconds(3600);
        PlainToken generatedToken = new PlainToken("abc.def.ghi", issuedAt, expiresAt);
        when(tokenGenerator.generate(any(OAuth2TokenContext.class))).thenReturn(generatedToken);

        LoginResponse response = service.login(loginRequest("alice", "Passw0rd!"), CLIENT_APP_ID);

        assertThat(response.getUserId()).isEqualTo(1L);
        assertThat(response.getUsername()).isEqualTo("alice");
        assertThat(response.getMessage()).isEqualTo("Login successful.");
        assertThat(response.getAccessToken()).isEqualTo("abc.def.ghi");

        verify(eventPublisher).publishEvent(new UserLoggedInEvent(user.getId(), user.getUsername(), CLIENT_APP_ID));

        ArgumentCaptor<OAuth2TokenContext> contextCaptor = ArgumentCaptor.forClass(OAuth2TokenContext.class);
        verify(tokenGenerator).generate(contextCaptor.capture());
        OAuth2TokenContext context = contextCaptor.getValue();
        assertThat(context.getRegisteredClient()).isSameAs(client);
        assertThat(context.getAuthorizedScopes()).isEmpty();
        assertThat(context.getAuthorizationGrantType()).isEqualTo(new AuthorizationGrantType("local_login"));

        UsernamePasswordAuthenticationToken principal = context.getPrincipal();
        assertThat(principal.getName()).isEqualTo("alice");
        assertThat(principal.getDetails()).isEqualTo(CLIENT_APP_ID);
        Set<String> authorityNames = principal.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(java.util.stream.Collectors.toSet());
        assertThat(authorityNames).containsExactlyInAnyOrder("admin", "buyer");

        ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
        verify(authorizationService).save(authorizationCaptor.capture());
        OAuth2Authorization authorization = authorizationCaptor.getValue();
        assertThat(authorization.getPrincipalName()).isEqualTo("alice");
        assertThat(authorization.getAuthorizationGrantType()).isEqualTo(new AuthorizationGrantType("local_login"));
        assertThat(authorization.getAccessToken().getToken().getTokenValue()).isEqualTo("abc.def.ghi");
        assertThat(authorization.getAccessToken().getClaims()).isNull();
    }

    @Test
    void login_success_currentBehavior_rolesAreLookedUpByUserIdNeverByUsername() {
        User user = activeVerifiedUser();
        when(userRepository.findByUsernameAndClientApplicationId("alice", CLIENT_APP_ID)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("Passw0rd!", "hashed-pw")).thenReturn(true);
        stubSuccessfulMinting(user, new PlainToken("tok", Instant.now(), Instant.now().plusSeconds(60)));

        service.login(loginRequest("alice", "Passw0rd!"), CLIENT_APP_ID);

        verify(userRolesRepository).findRolesByUserId(1L);
        verify(userRolesRepository, never()).findRolesByUsername(anyString());
    }

    @Test
    void login_currentBehavior_auditIsRecordedBeforeTokenMintingEvenIfMintingSubsequentlyFails() {
        User user = activeVerifiedUser();
        when(userRepository.findByUsernameAndClientApplicationId("alice", CLIENT_APP_ID)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("Passw0rd!", "hashed-pw")).thenReturn(true);
        when(registeredClientRepository.findById("7")).thenReturn(null);

        assertThatThrownBy(() -> service.login(loginRequest("alice", "Passw0rd!"), CLIENT_APP_ID))
                .isInstanceOf(IllegalStateException.class);

        verify(eventPublisher).publishEvent(new UserLoggedInEvent(user.getId(), user.getUsername(), CLIENT_APP_ID));
    }

    @Test
    void login_mintAccessToken_registeredClientNotFound_throwsIllegalStateException() {
        User user = activeVerifiedUser();
        when(userRepository.findByUsernameAndClientApplicationId("alice", CLIENT_APP_ID)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("Passw0rd!", "hashed-pw")).thenReturn(true);
        when(registeredClientRepository.findById("7")).thenReturn(null);

        assertThatThrownBy(() -> service.login(loginRequest("alice", "Passw0rd!"), CLIENT_APP_ID))
                .isInstanceOfSatisfying(IllegalStateException.class,
                        ex -> assertThat(ex.getMessage()).contains("No RegisteredClient found for client application id 7"));

        verifyNoInteractions(tokenGenerator, authorizationService);
    }

    @Test
    void login_mintAccessToken_tokenGeneratorReturnsNull_throwsIllegalStateException() {
        User user = activeVerifiedUser();
        when(userRepository.findByUsernameAndClientApplicationId("alice", CLIENT_APP_ID)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("Passw0rd!", "hashed-pw")).thenReturn(true);
        when(registeredClientRepository.findById("7")).thenReturn(registeredClient("7"));
        when(userRolesRepository.findRolesByUserId(1L)).thenReturn(List.of());
        when(tokenGenerator.generate(any(OAuth2TokenContext.class))).thenReturn(null);

        assertThatThrownBy(() -> service.login(loginRequest("alice", "Passw0rd!"), CLIENT_APP_ID))
                .isInstanceOfSatisfying(IllegalStateException.class,
                        ex -> assertThat(ex.getMessage()).contains("The token generator failed to generate a self-issued access token for user id 1"));

        verifyNoInteractions(authorizationService);
    }

    @Test
    void login_mintAccessToken_claimAccessorToken_authorizationCapturesClaimsMetadata() {
        User user = activeVerifiedUser();
        when(userRepository.findByUsernameAndClientApplicationId("alice", CLIENT_APP_ID)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("Passw0rd!", "hashed-pw")).thenReturn(true);
        Map<String, Object> claims = Map.of("sub", "alice", "client_application_id", CLIENT_APP_ID);
        stubSuccessfulMinting(user, new ClaimBearingToken("claim.token.value", claims));

        service.login(loginRequest("alice", "Passw0rd!"), CLIENT_APP_ID);

        ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
        verify(authorizationService).save(authorizationCaptor.capture());
        OAuth2Authorization authorization = authorizationCaptor.getValue();
        assertThat(authorization.getAccessToken().getToken().getTokenValue()).isEqualTo("claim.token.value");
        assertThat(authorization.getAccessToken().getClaims()).isEqualTo(claims);
    }
}
