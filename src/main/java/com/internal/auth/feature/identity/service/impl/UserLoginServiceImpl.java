package com.internal.auth.feature.identity.service.impl;

import com.internal.auth.feature.audit.event.UserLoggedInEvent;
import com.internal.auth.common.exception.AccountDisabledException;
import com.internal.auth.common.exception.AccountNotVerifiedException;
import com.internal.auth.common.exception.InvalidCredentialsException;
import com.internal.auth.common.security.SelfIssuedAuthorizationServerContext;
import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.service.ClientApplicationService;
import com.internal.auth.common.exception.InvalidRefreshTokenException;
import com.internal.auth.feature.identity.dto.request.LoginRequest;
import com.internal.auth.feature.identity.dto.request.RefreshTokenRequest;
import com.internal.auth.feature.identity.dto.response.LoginResponse;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.identity.repository.UserRepository;
import com.internal.auth.feature.identity.service.UserLoginService;
import com.internal.auth.feature.rbac.model.Role;
import com.internal.auth.feature.rbac.repository.UserRolesRepository;
import com.internal.auth.feature.session.service.SessionManagementService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/** Authenticates users and refreshes their tokens. */
@Service
@RequiredArgsConstructor
public class UserLoginServiceImpl implements UserLoginService {

    private static final Logger log = LoggerFactory.getLogger(UserLoginServiceImpl.class);
    private static final String INVALID_CREDENTIALS_MESSAGE = "Username or password is incorrect";
    private static final String INVALID_REFRESH_TOKEN_MESSAGE = "Refresh token is invalid or expired";

    private static final String SESSION_STARTED_AT_ATTRIBUTE = "internal_auth.session_started_at";

    private static final AuthorizationGrantType LOCAL_LOGIN_GRANT_TYPE = new AuthorizationGrantType("local_login");

    private final ApplicationEventPublisher eventPublisher;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserRolesRepository userRolesRepository;
    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2TokenGenerator<OAuth2Token> tokenGenerator;
    private final AuthorizationServerSettings authorizationServerSettings;
    private final ClientApplicationService clientApplicationService;
    private final SessionManagementService sessionManagementService;
    private final JdbcTemplate jdbcTemplate;

    @Value("${app.self-issuer-uri}")
    private String selfIssuerUri;

    @Value("${app.authorization-server.refresh-token-ttl-days}")
    private long globalRefreshTokenTtlDays;

    @Override
    public LoginResponse login(LoginRequest request, Long clientApplicationId) {
        return login(request, clientApplicationId, null, null);
    }

    @Override
    public LoginResponse login(LoginRequest request, Long clientApplicationId, String ipAddress, String userAgent) {
        String username = request.getUsername() == null ? null : request.getUsername().trim();
        if (username == null || username.isBlank() || request.getPassword() == null) {
            throw new InvalidCredentialsException(INVALID_CREDENTIALS_MESSAGE);
        }

        Optional<User> userOptional = userRepository.findByUsernameAndClientApplicationId(username, clientApplicationId);
        if (userOptional.isEmpty()) {
            throw new InvalidCredentialsException(INVALID_CREDENTIALS_MESSAGE);
        }

        User user = userOptional.get();
        if (user.getPassword() == null || !passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new InvalidCredentialsException(INVALID_CREDENTIALS_MESSAGE);
        }

        if (!user.isEnabled()) {
            throw new AccountDisabledException("This account has been disabled.");
        }

        String verificationProblem = describeUnverifiedContactMethods(user);
        if (verificationProblem != null) {
            throw new AccountNotVerifiedException(verificationProblem);
        }

        log.info("User id {} logged in", user.getId());
        eventPublisher.publishEvent(new UserLoggedInEvent(user.getId(), user.getUsername(), clientApplicationId));
        if (clientApplicationService.getById(clientApplicationId).isRevokePriorSessionsOnLogin()) {
            revokePriorAuthorizations(user.getInternalAuthUserId(), clientApplicationId);
        }
        MintedTokens tokens = mintTokens(user, clientApplicationId);

        sessionManagementService.createSession(user.getId(), user.getPhoneNumber(), tokens.accessToken(), ipAddress, userAgent, tokens.authorizationId());

        return new LoginResponse(user.getId(), user.getUsername(), "Login successful.",
                tokens.accessToken(), tokens.refreshToken(), tokens.expiresIn(), tokens.refreshExpiresIn());
    }

    @Override
    public LoginResponse refreshToken(RefreshTokenRequest request, Long clientApplicationId) {
        String rawRefreshToken = request.getRefreshToken() == null ? null : request.getRefreshToken().trim();
        if (rawRefreshToken == null || rawRefreshToken.isBlank()) {
            throw new InvalidRefreshTokenException(INVALID_REFRESH_TOKEN_MESSAGE);
        }

        OAuth2Authorization authorization = authorizationService.findByToken(rawRefreshToken, OAuth2TokenType.REFRESH_TOKEN);
        if (authorization == null) {
            throw new InvalidRefreshTokenException(INVALID_REFRESH_TOKEN_MESSAGE);
        }

        if (!authorization.getRegisteredClientId().equals(String.valueOf(clientApplicationId))) {
            throw new InvalidRefreshTokenException(INVALID_REFRESH_TOKEN_MESSAGE);
        }

        OAuth2Authorization.Token<OAuth2RefreshToken> refreshTokenRecord = authorization.getRefreshToken();
        if (refreshTokenRecord == null || !refreshTokenRecord.isActive()) {
            throw new InvalidRefreshTokenException(INVALID_REFRESH_TOKEN_MESSAGE);
        }

        User user = userRepository.findByInternalAuthUserIdAndClientApplicationId(authorization.getPrincipalName(), clientApplicationId)
                .orElseThrow(() -> new InvalidRefreshTokenException(INVALID_REFRESH_TOKEN_MESSAGE));

        if (!user.isEnabled()) {
            throw new AccountDisabledException("This account has been disabled.");
        }

        ClientApplication client = clientApplicationService.getById(clientApplicationId);

        String previousAccessToken = authorization.getAccessToken() == null ? null : authorization.getAccessToken().getToken().getTokenValue();

        MintedTokens tokens;
        if (client.isRefreshTokenRotationEnabled()) {
            authorizationService.remove(authorization);
            log.info("User id {} refreshed their access token", user.getId());
            tokens = mintTokens(user, clientApplicationId);
        } else {
            Instant sessionDeadline = resolveSessionDeadline(authorization, client);
            if (sessionDeadline != null && !Instant.now().isBefore(sessionDeadline)) {
                authorizationService.remove(authorization);
                log.info("User id {} must sign in again: persistent session reached its {}-day maximum lifetime",
                        user.getId(), client.getRefreshTokenMaxLifetimeDays());
                throw new InvalidRefreshTokenException(INVALID_REFRESH_TOKEN_MESSAGE);
            }
            log.info("User id {} refreshed their access token (non-rotating client)", user.getId());
            tokens = renewAccessToken(authorization, user, client, sessionDeadline);
        }

        sessionManagementService.updateSessionOnRefresh(user.getId(), previousAccessToken, tokens.accessToken(), tokens.authorizationId());

        return new LoginResponse(user.getId(), user.getUsername(), "Token refreshed.",
                tokens.accessToken(), tokens.refreshToken(), tokens.expiresIn(), tokens.refreshExpiresIn());
    }

    private MintedTokens renewAccessToken(OAuth2Authorization existingAuthorization, User user, ClientApplication client, Instant sessionDeadline) {
        RegisteredClient registeredClient = registeredClientRepository.findById(String.valueOf(client.getId()));
        if (registeredClient == null) {
            throw new IllegalStateException("No RegisteredClient found for client application id " + client.getId());
        }

        List<Role> roles = userRolesRepository.findRolesByUserId(user.getId());
        Collection<GrantedAuthority> authorities = roles.stream()
                .map(role -> (GrantedAuthority) new SimpleGrantedAuthority(role.getRoleName().toLowerCase(Locale.ROOT)))
                .collect(Collectors.toSet());
        UsernamePasswordAuthenticationToken userPrincipal = new UsernamePasswordAuthenticationToken(user.getInternalAuthUserId(), null, authorities);
        userPrincipal.setDetails(client.getId());

        AuthorizationServerContext authorizationServerContext =
                new SelfIssuedAuthorizationServerContext(selfIssuerUri, authorizationServerSettings);

        DefaultOAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(userPrincipal)
                .authorizationServerContext(authorizationServerContext)
                .authorizedScopes(Set.of())
                .authorizationGrantType(LOCAL_LOGIN_GRANT_TYPE)
                .authorizationGrant(userPrincipal)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .build();

        OAuth2Token generatedAccessToken = tokenGenerator.generate(tokenContext);
        if (generatedAccessToken == null) {
            throw new IllegalStateException("The token generator failed to generate a self-issued access token for user id " + user.getId());
        }

        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                generatedAccessToken.getTokenValue(),
                generatedAccessToken.getIssuedAt(),
                generatedAccessToken.getExpiresAt());

        OAuth2RefreshToken currentRefreshToken = existingAuthorization.getRefreshToken().getToken();
        Instant now = Instant.now();
        Instant newRefreshExpiry = now.plus(resolveRefreshTokenTtl(client));
        if (sessionDeadline != null && newRefreshExpiry.isAfter(sessionDeadline)) {
            newRefreshExpiry = sessionDeadline;
        }
        OAuth2RefreshToken renewedRefreshToken = new OAuth2RefreshToken(currentRefreshToken.getTokenValue(), now, newRefreshExpiry);

        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.from(existingAuthorization);
        if (generatedAccessToken instanceof ClaimAccessor claimAccessor) {
            authorizationBuilder.token(accessToken, metadata ->
                    metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, claimAccessor.getClaims()));
        } else {
            authorizationBuilder.accessToken(accessToken);
        }
        authorizationBuilder.refreshToken(renewedRefreshToken);
        if (existingAuthorization.getAttribute(SESSION_STARTED_AT_ATTRIBUTE) == null) {
            authorizationBuilder.attribute(SESSION_STARTED_AT_ATTRIBUTE, now.toString());
        }

        OAuth2Authorization renewedAuthorization = authorizationBuilder.build();
        authorizationService.save(renewedAuthorization);

        Long expiresIn = accessToken.getExpiresAt() == null ? null
                : Duration.between(accessToken.getIssuedAt(), accessToken.getExpiresAt()).getSeconds();
        Long refreshExpiresIn = Duration.between(renewedRefreshToken.getIssuedAt(), renewedRefreshToken.getExpiresAt()).getSeconds();

        return new MintedTokens(
                accessToken.getTokenValue(),
                renewedRefreshToken.getTokenValue(),
                expiresIn,
                refreshExpiresIn,
                renewedAuthorization.getId());
    }

    private Instant resolveSessionDeadline(OAuth2Authorization authorization, ClientApplication client) {
        Integer maxLifetimeDays = client.getRefreshTokenMaxLifetimeDays();
        if (maxLifetimeDays == null) {
            return null;
        }
        String startedAt = authorization.getAttribute(SESSION_STARTED_AT_ATTRIBUTE);
        Instant sessionStart = startedAt != null ? Instant.parse(startedAt) : Instant.now();
        return sessionStart.plus(Duration.ofDays(maxLifetimeDays));
    }

    private Duration resolveRefreshTokenTtl(ClientApplication client) {
        Integer perClientDays = client.getRefreshTokenTtlDays();
        return Duration.ofDays(perClientDays != null ? perClientDays : globalRefreshTokenTtlDays);
    }

    private void revokePriorAuthorizations(String internalAuthUserId, Long clientApplicationId) {
        int removed = jdbcTemplate.update(
                "DELETE FROM oauth2_authorization WHERE principal_name = ? AND registered_client_id = ?",
                internalAuthUserId, String.valueOf(clientApplicationId));
        if (removed > 0) {
            log.info("Revoked {} prior authorization(s) for user id {} on new login", removed, internalAuthUserId);
        }
    }

    private MintedTokens mintTokens(User user, Long clientApplicationId) {
        RegisteredClient registeredClient = registeredClientRepository.findById(String.valueOf(clientApplicationId));
        if (registeredClient == null) {
            throw new IllegalStateException("No RegisteredClient found for client application id " + clientApplicationId);
        }

        List<Role> roles = userRolesRepository.findRolesByUserId(user.getId());
        Collection<GrantedAuthority> authorities = roles.stream()
                .map(role -> (GrantedAuthority) new SimpleGrantedAuthority(role.getRoleName().toLowerCase(Locale.ROOT)))
                .collect(Collectors.toSet());
        UsernamePasswordAuthenticationToken userPrincipal = new UsernamePasswordAuthenticationToken(user.getInternalAuthUserId(), null, authorities);
        userPrincipal.setDetails(clientApplicationId);

        AuthorizationServerContext authorizationServerContext =
                new SelfIssuedAuthorizationServerContext(selfIssuerUri, authorizationServerSettings);

        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(userPrincipal)
                .authorizationServerContext(authorizationServerContext)
                .authorizedScopes(Set.of())
                .authorizationGrantType(LOCAL_LOGIN_GRANT_TYPE)
                .authorizationGrant(userPrincipal);

        OAuth2Token generatedAccessToken = tokenGenerator.generate(tokenContextBuilder.tokenType(OAuth2TokenType.ACCESS_TOKEN).build());
        if (generatedAccessToken == null) {
            throw new IllegalStateException("The token generator failed to generate a self-issued access token for user id " + user.getId());
        }

        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                generatedAccessToken.getTokenValue(),
                generatedAccessToken.getIssuedAt(),
                generatedAccessToken.getExpiresAt());

        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(user.getInternalAuthUserId())
                .authorizationGrantType(LOCAL_LOGIN_GRANT_TYPE)
                .authorizedScopes(Set.of())
                .attribute(SESSION_STARTED_AT_ATTRIBUTE, Instant.now().toString());

        if (generatedAccessToken instanceof ClaimAccessor claimAccessor) {
            authorizationBuilder.token(accessToken, metadata ->
                    metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, claimAccessor.getClaims()));
        } else {
            authorizationBuilder.accessToken(accessToken);
        }

        OAuth2RefreshToken refreshToken = null;
        if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)) {
            OAuth2Token generatedRefreshToken = tokenGenerator.generate(tokenContextBuilder.tokenType(OAuth2TokenType.REFRESH_TOKEN).build());
            if (generatedRefreshToken instanceof OAuth2RefreshToken rt) {
                refreshToken = rt;
                authorizationBuilder.refreshToken(refreshToken);
            } else {
                log.warn("Client id {} is configured for refresh_token but the token generator did not return one for user id {}", registeredClient.getClientId(), user.getId());
            }
        }

        OAuth2Authorization authorization = authorizationBuilder.build();
        authorizationService.save(authorization);

        Long expiresIn = accessToken.getExpiresAt() == null ? null
                : Duration.between(accessToken.getIssuedAt(), accessToken.getExpiresAt()).getSeconds();
        Long refreshExpiresIn = refreshToken == null || refreshToken.getExpiresAt() == null ? null
                : Duration.between(refreshToken.getIssuedAt(), refreshToken.getExpiresAt()).getSeconds();

        return new MintedTokens(
                accessToken.getTokenValue(),
                refreshToken == null ? null : refreshToken.getTokenValue(),
                expiresIn,
                refreshExpiresIn,
                authorization.getId());
    }

    private record MintedTokens(String accessToken, String refreshToken, Long expiresIn, Long refreshExpiresIn, String authorizationId) {}

    private String describeUnverifiedContactMethods(User user) {
        boolean hasEmail = user.getEmail() != null && !user.getEmail().isBlank();
        boolean hasPhone = user.getPhoneNumber() != null && !user.getPhoneNumber().isBlank();

        boolean emailVerified = hasEmail && user.isEmailVerified();
        boolean phoneVerified = hasPhone && user.isPhoneVerified();

        if (!hasEmail && !hasPhone) {
            return null;
        }
        if (emailVerified || phoneVerified) {
            return null;
        }
        if (hasEmail && hasPhone) {
            return "Please verify your email or phone number before logging in.";
        }
        return hasEmail ? "Please verify your email before logging in." : "Please verify your phone number before logging in.";
    }
}
