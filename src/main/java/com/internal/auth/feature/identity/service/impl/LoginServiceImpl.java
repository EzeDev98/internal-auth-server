package com.internal.auth.feature.identity.service.impl;

import com.internal.auth.common.exception.AccountDisabledException;
import com.internal.auth.common.exception.AccountNotVerifiedException;
import com.internal.auth.common.exception.InvalidCredentialsException;
import com.internal.auth.common.exception.OtpInvalidException;
import com.internal.auth.common.reset.OtpResetEngine;
import com.internal.auth.common.reset.OtpService;
import com.internal.auth.common.reset.delivery.OtpDeliveryService;
import com.internal.auth.config.auth.SelfIssuedAuthorizationServerContext;
import com.internal.auth.feature.identity.config.LoginMfaProperties;
import com.internal.auth.feature.identity.dto.LoginRequest;
import com.internal.auth.feature.identity.dto.LoginResponse;
import com.internal.auth.feature.identity.dto.VerifyLoginOtpRequest;
import com.internal.auth.feature.identity.model.LoginMfaOtp;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.identity.repository.LoginMfaOtpRepository;
import com.internal.auth.feature.identity.repository.UserRepository;
import com.internal.auth.feature.identity.service.LoginService;
import com.internal.auth.feature.passwordreset.enums.PasswordResetStatus;
import com.internal.auth.feature.rbac.model.Role;
import com.internal.auth.feature.rbac.repository.UserRolesRepository;
import lombok.RequiredArgsConstructor;
import org.redisson.api.RBucket;
import org.redisson.api.RedissonClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.stereotype.Service;

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
 */
@Service
@RequiredArgsConstructor
public class LoginServiceImpl implements LoginService {

    private static final Logger log = LoggerFactory.getLogger(LoginServiceImpl.class);
    private static final String INVALID_CREDENTIALS_MESSAGE = "Username or password is incorrect";

    // Step 12F: a dedicated grant-type marker for tokens minted this way,
    // purely for audit/introspection on the persisted OAuth2Authorization
    // record - this never routes through anything that checks grant-type
    // membership against a RegisteredClient's own configured grant types
    // (see class javadoc), so this is a label, not an enforced value.
    private static final AuthorizationGrantType LOCAL_LOGIN_GRANT_TYPE = new AuthorizationGrantType("local_login");

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

    @Value("${app.self-issuer-uri}")
    private String selfIssuerUri;

    @Override
    public LoginResponse login(LoginRequest request, Long clientApplicationId) {
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
            return new LoginResponse(null, user.getUsername(), "A verification code has been sent to your registered phone number.", true, null);
        }

        log.info("User id {} logged in", user.getId());
        String accessToken = mintAccessToken(user, clientApplicationId);
        return new LoginResponse(user.getId(), user.getUsername(), "Login successful.", false, accessToken);
    }

    @Override
    public LoginResponse verifyLoginOtp(VerifyLoginOtpRequest request, Long clientApplicationId) {
        String phoneNumber = request.getPhoneNumber();
        if (phoneNumber == null || phoneNumber.isBlank()) {
            throw new OtpInvalidException("The verification code is invalid.");
        }

        LoginMfaOtp otp = loginMfaOtpRepository.findTopByPhoneNumberAndClientApplicationIdAndStatusOrderByCreatedAtDesc(phoneNumber, clientApplicationId, PasswordResetStatus.ACTIVE)
                .orElseThrow(() -> new OtpInvalidException("The verification code is invalid."));

        otpResetEngine.verify(otp, request.getOtp(), loginMfaOtpRepository::save);

        User user = userRepository.findById(otp.getUserId())
                .orElseThrow(() -> new InvalidCredentialsException(INVALID_CREDENTIALS_MESSAGE));

        log.info("User id {} completed MFA login step-up", user.getId());
        String accessToken = mintAccessToken(user, clientApplicationId);
        return new LoginResponse(user.getId(), user.getUsername(), "Login successful.", false, accessToken);
    }

    private void sendLoginOtp(User user, Long clientApplicationId) {
        String phoneNumber = user.getPhoneNumber();

        // Composite cooldown key (multi-tenant redesign) - see
        // PasswordResetServiceImpl.requestOtp for the same reasoning.
        String cooldownKey = clientApplicationId + ":" + phoneNumber;
        RBucket<String> cooldownBucket = otpResetEngine.getCooldownBucket(redissonClient, LOGIN_MFA_OTP_COOLDOWN_KEY_PREFIX, cooldownKey);
        otpResetEngine.rejectIfCoolingDown(cooldownBucket);

        otpResetEngine.invalidateExisting(
                loginMfaOtpRepository.findTopByPhoneNumberAndClientApplicationIdAndStatusOrderByCreatedAtDesc(phoneNumber, clientApplicationId, PasswordResetStatus.ACTIVE),
                loginMfaOtpRepository::save);

        String rawOtp = otpService.generateOtp(loginMfaProperties.getOtpLength());

        LoginMfaOtp otpEntity = new LoginMfaOtp();
        otpEntity.setUserId(user.getId());
        otpEntity.setClientApplicationId(clientApplicationId);
        otpResetEngine.populateNewOtp(otpEntity, phoneNumber, rawOtp, loginMfaProperties.getOtpExpirationMinutes(), loginMfaProperties.getMaxAttempts());
        loginMfaOtpRepository.save(otpEntity);

        // Reused despite the method's password-reset-specific name - it's
        // really just "send an OTP over SMS" (see OtpDeliveryService).
        otpDeliveryService.sendPasswordResetOtp(phoneNumber, rawOtp);

        otpResetEngine.startCooldown(cooldownBucket, loginMfaProperties.getResendCooldownSeconds());
    }

    /**
     * Step 12F - mints and persists a real self-issued access token for a
     * user whose login just actually succeeded. See the class javadoc for
     * why this happens in-process instead of via /oauth2/token, and
     * SelfIssuedAuthorizationServerContext's javadoc for why the
     * authorization-server context is built directly here rather than read
     * off AuthorizationServerContextHolder.
     */
    private String mintAccessToken(User user, Long clientApplicationId) {
        RegisteredClient registeredClient = registeredClientRepository.findById(String.valueOf(clientApplicationId));
        if (registeredClient == null) {
            // Shouldn't happen - LoginController already authenticated this
            // exact client application via HTTP Basic before LoginServiceImpl
            // ever runs, so a RegisteredClient for it must exist.
            throw new IllegalStateException("No RegisteredClient found for client application id " + clientApplicationId);
        }

        List<Role> roles = userRolesRepository.findRolesByUsername(user.getUsername());
        Collection<GrantedAuthority> authorities = roles.stream()
                .map(role -> (GrantedAuthority) new SimpleGrantedAuthority(role.getRoleName().toLowerCase(Locale.ROOT)))
                .collect(Collectors.toSet());
        Authentication userPrincipal = new UsernamePasswordAuthenticationToken(user.getUsername(), null, authorities);

        AuthorizationServerContext authorizationServerContext =
                new SelfIssuedAuthorizationServerContext(selfIssuerUri, authorizationServerSettings);

        OAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(userPrincipal)
                .authorizationServerContext(authorizationServerContext)
                .authorizedScopes(Set.of())
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(LOCAL_LOGIN_GRANT_TYPE)
                .authorizationGrant(userPrincipal)
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

        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(user.getUsername())
                .authorizationGrantType(LOCAL_LOGIN_GRANT_TYPE)
                .authorizedScopes(Set.of());

        if (generatedAccessToken instanceof ClaimAccessor claimAccessor) {
            authorizationBuilder.token(accessToken, metadata ->
                    metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, claimAccessor.getClaims()));
        } else {
            authorizationBuilder.accessToken(accessToken);
        }

        authorizationService.save(authorizationBuilder.build());

        return accessToken.getTokenValue();
    }

    private String describeUnverifiedContactMethods(User user) {
        boolean emailProblem = user.getEmail() != null && !user.getEmail().isBlank() && !user.isEmailVerified();
        boolean phoneProblem = user.getPhoneNumber() != null && !user.getPhoneNumber().isBlank() && !user.isPhoneVerified();

        if (emailProblem && phoneProblem) {
            return "Please verify your email and phone number before logging in.";
        }
        if (emailProblem) {
            return "Please verify your email before logging in.";
        }
        if (phoneProblem) {
            return "Please verify your phone number before logging in.";
        }
        return null;
    }
}
