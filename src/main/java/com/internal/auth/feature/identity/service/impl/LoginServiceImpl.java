package com.internal.auth.feature.identity.service.impl;

import com.internal.auth.common.exception.AccountDisabledException;
import com.internal.auth.common.exception.AccountNotVerifiedException;
import com.internal.auth.common.exception.InvalidCredentialsException;
import com.internal.auth.common.exception.OtpInvalidException;
import com.internal.auth.common.reset.OtpResetEngine;
import com.internal.auth.common.reset.OtpService;
import com.internal.auth.common.reset.delivery.OtpDeliveryService;
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
import lombok.RequiredArgsConstructor;
import org.redisson.api.RBucket;
import org.redisson.api.RedissonClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

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
 */
@Service
@RequiredArgsConstructor
public class LoginServiceImpl implements LoginService {

    private static final Logger log = LoggerFactory.getLogger(LoginServiceImpl.class);
    private static final String INVALID_CREDENTIALS_MESSAGE = "Username or password is incorrect";

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final LoginMfaOtpRepository loginMfaOtpRepository;
    private final OtpService otpService;
    private final OtpDeliveryService otpDeliveryService;
    private final OtpResetEngine otpResetEngine;
    private final LoginMfaProperties loginMfaProperties;
    private final RedissonClient redissonClient;

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
            return new LoginResponse(null, user.getUsername(), "A verification code has been sent to your registered phone number.", true);
        }

        log.info("User id {} logged in", user.getId());
        return new LoginResponse(user.getId(), user.getUsername(), "Login successful.", false);
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
        return new LoginResponse(user.getId(), user.getUsername(), "Login successful.", false);
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
