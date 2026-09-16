package com.internal.auth.feature.identity.service.impl;

import com.internal.auth.feature.audit.event.UserLoggedInEvent;
import com.internal.auth.common.exception.AccountDisabledException;
import com.internal.auth.common.exception.AccountNotVerifiedException;
import com.internal.auth.common.exception.InvalidCredentialsException;
import com.internal.auth.common.exception.OtpInvalidException;
import com.internal.auth.common.reset.OtpResetEngine;
import com.internal.auth.common.reset.OtpService;
import com.internal.auth.common.reset.delivery.OtpDeliveryService;
import com.internal.auth.common.security.SelfIssuedAuthorizationServerContext;
import com.internal.auth.feature.client.model.ClientApplication;
import com.internal.auth.feature.client.service.ClientApplicationService;
import com.internal.auth.feature.identity.config.LoginMfaProperties;
import com.internal.auth.common.exception.InvalidRefreshTokenException;
import com.internal.auth.feature.identity.dto.request.LoginRequest;
import com.internal.auth.feature.identity.dto.request.RefreshTokenRequest;
import com.internal.auth.feature.identity.dto.request.VerifyLoginOtpRequest;
import com.internal.auth.feature.identity.dto.response.LoginResponse;
import com.internal.auth.feature.identity.model.LoginMfaOtp;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.identity.repository.LoginMfaOtpRepository;
import com.internal.auth.feature.identity.repository.UserRepository;
import com.internal.auth.common.reset.ResetStatus;
import com.internal.auth.feature.identity.service.UserLoginService;
import com.internal.auth.feature.rbac.model.Role;
import com.internal.auth.feature.rbac.repository.UserRolesRepository;
import com.internal.auth.feature.session.service.SessionManagementService;
import lombok.RequiredArgsConstructor;
import org.redisson.api.RBucket;
import org.redisson.api.RedissonClient;
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

import static com.internal.auth.common.constant.AppConstant.LOGIN_MFA_OTP_COOLDOWN_KEY_PREFIX;

/**
 * Step 11A/11E - authenticates a credential against the local User table,
 * with an optional OTP step-up (Step 11E) for accounts with
 * mfaEnabled=true.
 *
 * mfaEnabled is opt-in per user and SMS-OTP-based, reusing the exact
 * OtpResetEngine/OtpService/OtpDeliveryService machinery password reset
 * already uses rather than a separate implementation. Because SMS is the
 * channel, mfaEnabled can only be turned on for an account with a
 * phoneNumber on file - enforced in MfaAdminServiceImpl, not here; by the
 * time login() runs, mfaEnabled=true already implies a phone number exists.
 *
 * Two-step flow when MFA is on: login() confirms the password (same
 * enumeration-resistant check order as before) and, instead of completing,
 * generates and sends an OTP and returns mfaRequired=true. The caller then
 * calls verifyLoginOtp() with the phone number and code to actually
 * complete the login. No token is issued at either step - Step 11A's
 * scoping decision (token issuance is Step 12) still holds.
 *
 * Multi-tenant redesign: clientApplicationId is resolved by
 * LoginController from the caller's HTTP Basic client credentials for
 * both login() and verifyLoginOtp() now, and scopes the username lookup
 * (see User's class Javadoc, V8) and the login-MFA OTP lookup/cooldown
 * key (see LoginMfaOtp's class Javadoc, V9) respectively.
 *
 * sendLoginOtp() sends via OtpDeliveryService#sendLoginOtp (its own
 * accurate message text, branded with the calling app's display name via
 * ClientApplicationService#getById) rather than reusing
 * sendPasswordResetOtp, which previously texted "Your password reset
 * code is..." for what is actually a login step-up code.
 *
 * <p><b>Step 12F - token issuance:</b> mints a real self-issued bearer
 * token directly in-process (mintAccessToken()) once login() (no MFA) or
 * verifyLoginOtp() actually succeeds, using the same OAuth2TokenGenerator/
 * OAuth2AuthorizationService beans AuthorizationServerConfig declares for
 * the /oauth2/token endpoint - see that class's javadoc on those beans for
 * why they're declared explicitly. This deliberately does NOT route
 * through /oauth2/token as a grant-type request: LoginController already
 * authenticates the calling ClientApplication via HTTP Basic before this
 * service ever runs, and the two-step SMS OTP step-up above doesn't map
 * cleanly onto a single token-endpoint call anyway (see the Step 12F
 * design discussion - option C was chosen over a custom grant type or a
 * redeemable one-time code for exactly this reason). The resulting JWT
 * uses the same signing key/JWKS as every other self-issued token, so it
 * validates identically against WebSecurityConfig's jwtDecoder() - it's
 * just minted from here instead of from the authorization server's own
 * endpoint. AuthorizationServerContextHolder is not reliably populated on
 * this request path (see SelfIssuedAuthorizationServerContext's javadoc),
 * so a context is built directly from selfIssuerUri and the
 * authorizationServerSettings() bean instead of read off that holder.
 *
 * This-patch addition: the principal built here carries clientApplicationId
 * in its details (Authentication#setDetails) so
 * AuthorizationServerConfig#jwtTokenCustomizer can stamp it onto the
 * minted token as a "client_application_id" claim
 * (AuthenticationHelper#getCurrentClientApplicationId reads it back) -
 * fixes MfaAdminServiceImpl's previously-unscoped username lookup for the
 * self-service MFA path, which has no admin-supplied clientId to resolve
 * it from the way the admin path now does.
 */
@Service
@RequiredArgsConstructor
public class UserLoginServiceImpl implements UserLoginService {

    private static final Logger log = LoggerFactory.getLogger(UserLoginServiceImpl.class);
    private static final String INVALID_CREDENTIALS_MESSAGE = "Username or password is incorrect";
    private static final String INVALID_REFRESH_TOKEN_MESSAGE = "Refresh token is invalid or expired";

    // Step 12F: a dedicated grant-type marker for tokens minted this way,
    // purely for audit/introspection on the persisted OAuth2Authorization
    // record - this never routes through anything that checks grant-type
    // membership against a RegisteredClient's own configured grant types
    // (see class javadoc), so this is a label, not an enforced value.
    private static final AuthorizationGrantType LOCAL_LOGIN_GRANT_TYPE = new AuthorizationGrantType("local_login");

    private final ApplicationEventPublisher eventPublisher;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final LoginMfaOtpRepository loginMfaOtpRepository;
    private final OtpService otpService;
    private final OtpDeliveryService otpDeliveryService;
    private final OtpResetEngine otpResetEngine;
    private final LoginMfaProperties loginMfaProperties;
    private final RedissonClient redissonClient;
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

    // Part B (refresh-token-fix doc): same global default
    // ClientApplicationRegisteredClientRepository falls back to when a
    // client's own refreshTokenTtlDays is unset - see resolveRefreshTokenTtl().
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

        // Password confirmed correct beyond this point - safe to be
        // specific about why login still can't proceed.
        if (!user.isEnabled()) {
            throw new AccountDisabledException("This account has been disabled.");
        }

        String verificationProblem = describeUnverifiedContactMethods(user);
        if (verificationProblem != null) {
            throw new AccountNotVerifiedException(verificationProblem);
        }

        if (user.isMfaEnabled()) {
            sendLoginOtp(user, clientApplicationId);
            return new LoginResponse(null, user.getUsername(), "A verification code has been sent to your registered phone number.", true, null, null, null, null);
        }

        log.info("User id {} logged in", user.getId());
        eventPublisher.publishEvent(new UserLoggedInEvent(user.getId(), user.getUsername(), clientApplicationId));
        revokePriorAuthorizations(user.getInternalAuthUserId(), clientApplicationId);
        MintedTokens tokens = mintTokens(user, clientApplicationId);

        sessionManagementService.createSession(user.getId(), user.getPhoneNumber(), tokens.accessToken(), ipAddress, userAgent);

        return new LoginResponse(user.getId(), user.getUsername(), "Login successful.", false,
                tokens.accessToken(), tokens.refreshToken(), tokens.expiresIn(), tokens.refreshExpiresIn());
    }

    @Override
    public LoginResponse verifyLoginOtp(VerifyLoginOtpRequest request, Long clientApplicationId) {
        return verifyLoginOtp(request, clientApplicationId, null, null);
    }

    @Override
    public LoginResponse verifyLoginOtp(VerifyLoginOtpRequest request, Long clientApplicationId, String ipAddress, String userAgent) {
        String phoneNumber = request.getPhoneNumber();
        if (phoneNumber == null || phoneNumber.isBlank()) {
            throw new OtpInvalidException("The verification code is invalid.");
        }

        LoginMfaOtp otp = loginMfaOtpRepository.findTopByPhoneNumberAndClientApplicationIdAndStatusOrderByCreatedAtDesc(phoneNumber, clientApplicationId, ResetStatus.ACTIVE)
                .orElseThrow(() -> new OtpInvalidException("The verification code is invalid."));

        otpResetEngine.verify(otp, request.getOtp(), loginMfaOtpRepository::save);

        User user = userRepository.findById(otp.getUserId())
                .orElseThrow(() -> new InvalidCredentialsException(INVALID_CREDENTIALS_MESSAGE));

        log.info("User id {} completed MFA login step-up", user.getId());
        eventPublisher.publishEvent(new UserLoggedInEvent(user.getId(), user.getUsername(), clientApplicationId));
        revokePriorAuthorizations(user.getInternalAuthUserId(), clientApplicationId);
        MintedTokens tokens = mintTokens(user, clientApplicationId);
        sessionManagementService.createSession(user.getId(), user.getPhoneNumber(), tokens.accessToken(), ipAddress, userAgent);
        return new LoginResponse(user.getId(), user.getUsername(), "Login successful.", false,
                tokens.accessToken(), tokens.refreshToken(), tokens.expiresIn(), tokens.refreshExpiresIn());
    }

    /**
     * Step 15C, Part B (refresh-token-fix doc) - redeems a refresh token
     * minted by mintTokens()/renewAccessToken(). Every failure path below
     * throws the exact same InvalidRefreshTokenException/message
     * regardless of which specific thing was wrong (missing, unknown,
     * wrong-client, expired, disabled account) - same enumeration-
     * resistance reasoning as login()'s INVALID_CREDENTIALS_MESSAGE.
     *
     * <p>Branches on the calling ClientApplication's
     * refreshTokenRotationEnabled: true (default, every client today)
     * keeps the exact original behavior - remove the spent authorization,
     * mint a brand-new one. false is the non-destructive path added for
     * clients like SyncPoint that need a durable, non-single-use refresh
     * token - see renewAccessToken().
     */
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

        // A refresh token minted for one ClientApplication must never be
        // redeemable by another, even though the raw token value itself
        // carries no visible client identity - this is the check that
        // enforces that boundary.
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
            // Deliberately distinct from INVALID_REFRESH_TOKEN_MESSAGE, same
            // as login()'s equivalent check - the refresh token itself was
            // genuinely valid, so there's no enumeration risk in saying why
            // the request still can't proceed.
            throw new AccountDisabledException("This account has been disabled.");
        }

        ClientApplication client = clientApplicationService.getById(clientApplicationId);

        MintedTokens tokens;
        if (client.isRefreshTokenRotationEnabled()) {
            // Rotation (TokenSettings.reuseRefreshTokens(false)): the spent
            // refresh token must stop working the instant a new one is
            // issued, not remain valid until its own TTL expires. Removing
            // the whole authorization row - rather than only marking it
            // invalidated - is simplest given mintTokens() always creates a
            // brand-new OAuth2Authorization rather than mutating this one
            // in place. Exactly today's behavior, unchanged.
            authorizationService.remove(authorization);
            log.info("User id {} refreshed their access token", user.getId());
            tokens = mintTokens(user, clientApplicationId);
        } else {
            // Non-destructive refresh (Part B): this client's refresh token
            // is a durable session pointer, not single-use - see the
            // refresh-token-fix doc's root-cause section 2b. Only a new
            // access token is minted; the existing refresh token keeps its
            // exact value (so it's never invalidated out from under a
            // caller whose response gets lost) and just has its expiry
            // pushed forward.
            log.info("User id {} refreshed their access token (non-rotating client)", user.getId());
            tokens = renewAccessToken(authorization, user, client);
        }

        // Keeps the UserSession row's tokenHash pointing at the token that
        // is now actually in use, so a later logout (SessionManagementService
        // #invalidateSession, keyed by token hash) still finds it - without
        // this, the session row would keep pointing at the now-defunct
        // pre-refresh access token forever.
        sessionManagementService.updateSessionOnRefresh(user.getId(), tokens.accessToken());

        return new LoginResponse(user.getId(), user.getUsername(), "Token refreshed.", false,
                tokens.accessToken(), tokens.refreshToken(), tokens.expiresIn(), tokens.refreshExpiresIn());
    }

    /**
     * Part B non-destructive counterpart to mintTokens(): used only when
     * the calling client has refreshTokenRotationEnabled=false. Mints a
     * fresh access token exactly like mintTokens() does, but updates the
     * existing OAuth2Authorization row in place instead of replacing it -
     * the refresh token keeps its exact token value (the client-held
     * token is never invalidated) while its expiry slides forward to
     * now + the client's refreshTokenTtlDays (or the global default when
     * unset) - a rolling session window, not a fixed one.
     */
    private MintedTokens renewAccessToken(OAuth2Authorization existingAuthorization, User user, ClientApplication client) {
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
        OAuth2RefreshToken renewedRefreshToken = new OAuth2RefreshToken(currentRefreshToken.getTokenValue(), now, newRefreshExpiry);

        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.from(existingAuthorization);
        if (generatedAccessToken instanceof ClaimAccessor claimAccessor) {
            authorizationBuilder.token(accessToken, metadata ->
                    metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, claimAccessor.getClaims()));
        } else {
            authorizationBuilder.accessToken(accessToken);
        }
        authorizationBuilder.refreshToken(renewedRefreshToken);

        authorizationService.save(authorizationBuilder.build());

        Long expiresIn = accessToken.getExpiresAt() == null ? null
                : Duration.between(accessToken.getIssuedAt(), accessToken.getExpiresAt()).getSeconds();
        Long refreshExpiresIn = Duration.between(renewedRefreshToken.getIssuedAt(), renewedRefreshToken.getExpiresAt()).getSeconds();

        return new MintedTokens(
                accessToken.getTokenValue(),
                renewedRefreshToken.getTokenValue(),
                expiresIn,
                refreshExpiresIn);
    }

    private Duration resolveRefreshTokenTtl(ClientApplication client) {
        Integer perClientDays = client.getRefreshTokenTtlDays();
        return Duration.ofDays(perClientDays != null ? perClientDays : globalRefreshTokenTtlDays);
    }

    /**
     * Part B hygiene fix: revokes every prior OAuth2Authorization for this
     * user+client before minting new tokens on a genuinely new login, so
     * a previous device's refresh token can never remain valid once this
     * login has happened. Harmless for rotation-enabled clients (the old
     * authorization is already single-use-dead within one call); load-
     * bearing for non-rotating clients, where a refresh token can now
     * outlive a single call and would otherwise survive indefinitely
     * across logins. Raw SQL against oauth2_authorization directly -
     * OAuth2AuthorizationService's interface has no "find/remove all for
     * this principal" operation, only single-record
     * findById/findByToken/remove (see JdbcOAuth2AuthorizationService).
     */
    private void revokePriorAuthorizations(String internalAuthUserId, Long clientApplicationId) {
        int removed = jdbcTemplate.update(
                "DELETE FROM oauth2_authorization WHERE principal_name = ? AND registered_client_id = ?",
                internalAuthUserId, String.valueOf(clientApplicationId));
        if (removed > 0) {
            log.info("Revoked {} prior authorization(s) for user id {} on new login", removed, internalAuthUserId);
        }
    }

    private void sendLoginOtp(User user, Long clientApplicationId) {
        String phoneNumber = user.getPhoneNumber();

        // Composite cooldown key (multi-tenant redesign) - see
        // PasswordResetServiceImpl.requestOtp for the same reasoning.
        String cooldownKey = clientApplicationId + ":" + phoneNumber;
        RBucket<String> cooldownBucket = otpResetEngine.getCooldownBucket(redissonClient, LOGIN_MFA_OTP_COOLDOWN_KEY_PREFIX, cooldownKey);
        otpResetEngine.rejectIfCoolingDown(cooldownBucket);

        otpResetEngine.invalidateExisting(
                loginMfaOtpRepository.findTopByPhoneNumberAndClientApplicationIdAndStatusOrderByCreatedAtDesc(phoneNumber, clientApplicationId, ResetStatus.ACTIVE),
                loginMfaOtpRepository::save);

        String rawOtp = otpService.generateOtp(loginMfaProperties.getOtpLength());

        LoginMfaOtp otpEntity = new LoginMfaOtp();
        otpEntity.setUserId(user.getId());
        otpEntity.setClientApplicationId(clientApplicationId);
        otpResetEngine.populateNewOtp(otpEntity, phoneNumber, rawOtp, loginMfaProperties.getOtpExpirationMinutes(), loginMfaProperties.getMaxAttempts());
        loginMfaOtpRepository.save(otpEntity);

        // Own accurate message text (was: reused sendPasswordResetOtp,
        // which texted "Your password reset code is..." for a login
        // step-up code), branded per calling app.
        String appName = clientApplicationService.getById(clientApplicationId).getName();
        otpDeliveryService.sendLoginOtp(phoneNumber, rawOtp, appName);

        otpResetEngine.startCooldown(cooldownBucket, loginMfaProperties.getResendCooldownSeconds());
    }

    /**
     * Step 12F/15B - mints and persists a real self-issued access token
     * (and, when the calling client is configured for it, a refresh
     * token) for a user whose login just actually succeeded. See the
     * class javadoc for why this happens in-process instead of via
     * /oauth2/token, and SelfIssuedAuthorizationServerContext's javadoc
     * for why the authorization-server context is built directly here
     * rather than read off AuthorizationServerContextHolder.
     *
     * <p>Step 15B: whether a refresh token is minted is gated on
     * {@code registeredClient.getAuthorizationGrantTypes().contains(
     * AuthorizationGrantType.REFRESH_TOKEN)} - i.e. whether the calling
     * ClientApplication's own {@code grantTypes} column includes
     * "refresh_token" (see ClientApplicationRegisteredClientRepository).
     * This mirrors the same check Spring's own
     * OAuth2AuthorizationCodeAuthenticationProvider makes before
     * requesting a refresh token, even though OAuth2RefreshTokenGenerator
     * itself doesn't enforce it (it only refuses public
     * authorization_code clients). Enforcing it here means refresh tokens
     * are opt-in per client rather than minted for every client the
     * moment this generator exists - a client with only
     * "client_credentials" (today's default when grantTypes is empty -
     * see that repository's javadoc) gets accessToken/expiresIn only,
     * with refreshToken/refreshExpiresIn coming back null, until an admin
     * explicitly adds "refresh_token" to its grantTypes.
     */
    private MintedTokens mintTokens(User user, Long clientApplicationId) {
        RegisteredClient registeredClient = registeredClientRepository.findById(String.valueOf(clientApplicationId));
        if (registeredClient == null) {
            // Shouldn't happen - LoginController already authenticated this
            // exact client application via HTTP Basic before LoginServiceImpl
            // ever runs, so a RegisteredClient for it must exist.
            throw new IllegalStateException("No RegisteredClient found for client application id " + clientApplicationId);
        }

        // Scoped by user_id, not username - see UserRolesRepository.findRolesByUserId javadoc
        // (fixes cross-tenant privilege escalation: usernames are only unique per-tenant).
        List<Role> roles = userRolesRepository.findRolesByUserId(user.getId());
        Collection<GrantedAuthority> authorities = roles.stream()
                .map(role -> (GrantedAuthority) new SimpleGrantedAuthority(role.getRoleName().toLowerCase(Locale.ROOT)))
                .collect(Collectors.toSet());
        UsernamePasswordAuthenticationToken userPrincipal = new UsernamePasswordAuthenticationToken(user.getInternalAuthUserId(), null, authorities);
        // See class javadoc: read back by AuthorizationServerConfig's
        // jwtTokenCustomizer to stamp a "client_application_id" claim onto
        // the minted token.
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
                .authorizedScopes(Set.of());

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
                // Shouldn't happen given the grant-type check above, but a
                // silently-missing refresh token would be a confusing bug
                // to chase later - fail loudly instead.
                log.warn("Client id {} is configured for refresh_token but the token generator did not return one for user id {}", registeredClient.getClientId(), user.getId());
            }
        }

        authorizationService.save(authorizationBuilder.build());

        Long expiresIn = accessToken.getExpiresAt() == null ? null
                : Duration.between(accessToken.getIssuedAt(), accessToken.getExpiresAt()).getSeconds();
        Long refreshExpiresIn = refreshToken == null || refreshToken.getExpiresAt() == null ? null
                : Duration.between(refreshToken.getIssuedAt(), refreshToken.getExpiresAt()).getSeconds();

        return new MintedTokens(
                accessToken.getTokenValue(),
                refreshToken == null ? null : refreshToken.getTokenValue(),
                expiresIn,
                refreshExpiresIn);
    }

    /** Step 15B - small carrier so mintTokens can return both minted tokens plus their TTLs in seconds without a 4-arg tuple at every call site. */
    private record MintedTokens(String accessToken, String refreshToken, Long expiresIn, Long refreshExpiresIn) {}

    /**
     * Strict per-field gate: blocks login if ANY contact method the user
     * supplied at registration is still unverified, per User's class
     * Javadoc (Step 10E) - an account with both phone and email needs
     * both flags true. This method itself never treats one as a
     * substitute for the other. The reason verifying phone alone is
     * often enough in practice is PhoneVerificationServiceImpl#verify,
     * which auto-sets emailVerified too as a deliberate, one-directional
     * product decision (see that method's comment for why the reverse
     * isn't also done) - by the time this runs, that account's
     * emailVerified may already be true for a reason unrelated to the
     * email flow itself.
     */
    private String describeUnverifiedContactMethods(User user) {
        boolean hasEmail = user.getEmail() != null && !user.getEmail().isBlank();
        boolean hasPhone = user.getPhoneNumber() != null && !user.getPhoneNumber().isBlank();

        boolean emailUnverified = hasEmail && !user.isEmailVerified();
        boolean phoneUnverified = hasPhone && !user.isPhoneVerified();

        if (emailUnverified && phoneUnverified) {
            return "Please verify your email and phone number before logging in.";
        }
        if (emailUnverified) {
            return "Please verify your email before logging in.";
        }
        if (phoneUnverified) {
            return "Please verify your phone number before logging in.";
        }
        return null;
    }
}