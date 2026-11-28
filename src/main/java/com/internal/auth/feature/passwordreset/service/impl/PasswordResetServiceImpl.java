package com.internal.auth.feature.passwordreset.service.impl;

import com.internal.auth.common.exception.OtpInvalidException;
import com.internal.auth.common.exception.BadRequestException;
import com.internal.auth.common.email.EmailDeliveryService;
import com.internal.auth.feature.passwordreset.dto.request.EmailPasswordResetRequest;
import com.internal.auth.feature.passwordreset.dto.request.EmailVerifyOtpRequest;
import com.internal.auth.common.exception.ResetTokenInvalidException;
import com.internal.auth.common.exception.UserNotFoundException;
import com.internal.auth.common.reset.OtpResetEngine;
import com.internal.auth.common.reset.OtpService;
import com.internal.auth.common.reset.ResetValidator;
import com.internal.auth.common.reset.delivery.OtpDeliveryService;
import com.internal.auth.common.reset.dto.VerifyOtpRequest;
import com.internal.auth.common.reset.dto.VerifyOtpResponse;
import com.internal.auth.feature.client.service.ClientApplicationService;
import com.internal.auth.feature.passwordreset.config.PasswordResetProperties;
import com.internal.auth.feature.passwordreset.dto.request.CompletePasswordResetRequest;
import com.internal.auth.feature.passwordreset.dto.request.PasswordResetRequest;
import com.internal.auth.feature.passwordreset.dto.response.PasswordResetResponse;
import com.internal.auth.common.reset.ResetStatus;
import com.internal.auth.feature.passwordreset.model.PasswordResetOtp;
import com.internal.auth.feature.passwordreset.model.PasswordResetToken;
import com.internal.auth.feature.passwordreset.repository.PasswordResetOtpRepository;
import com.internal.auth.feature.passwordreset.repository.PasswordResetTokenRepository;
import com.internal.auth.feature.passwordreset.service.PasswordResetService;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.identity.repository.UserRepository;
import com.internal.auth.feature.session.service.SessionManagementService;
import lombok.RequiredArgsConstructor;

import org.redisson.api.RBucket;
import org.redisson.api.RedissonClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;

import static com.internal.auth.common.constant.AppConstant.GENERIC_REQUEST_MESSAGE;
import static com.internal.auth.common.constant.AppConstant.PASSWORD_RESET_COOLDOWN_KEY_PREFIX;

/** Orchestrates the password reset flow. */
@RequiredArgsConstructor
@Service
public class PasswordResetServiceImpl implements PasswordResetService {

    private static final Logger log = LoggerFactory.getLogger(PasswordResetServiceImpl.class);

    private final UserRepository userRepository;
    private final PasswordResetOtpRepository passwordResetOtpRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final OtpService otpService;
    private final OtpDeliveryService otpDeliveryService;
    private final SessionManagementService sessionManagementService;
    private final PasswordEncoder passwordEncoder;
    private final PasswordResetProperties properties;
    private final ResetValidator resetValidator;
    private final RedissonClient redissonClient;
    private final OtpResetEngine otpResetEngine;
    private final ClientApplicationService clientApplicationService;
    private final EmailDeliveryService emailDeliveryService;

    @Override
    @Transactional
    public PasswordResetResponse requestOtp(PasswordResetRequest request, Long clientApplicationId) {
        resetValidator.validatePhoneNumberFoResetOperations(request.getPhoneNumber());
        String phoneNumber = request.getPhoneNumber();

        String cooldownKey = clientApplicationId + ":" + phoneNumber;
        RBucket<String> cooldownBucket = otpResetEngine.getCooldownBucket(redissonClient, PASSWORD_RESET_COOLDOWN_KEY_PREFIX, cooldownKey);
        otpResetEngine.rejectIfCoolingDown(cooldownBucket);

        Optional<User> userOptional = userRepository.findByPhoneNumberAndClientApplicationId(phoneNumber, clientApplicationId);

        if (userOptional.isPresent()) {
            User user = userOptional.get();
            otpResetEngine.invalidateExisting(
                    passwordResetOtpRepository.findTopByPhoneNumberAndClientApplicationIdAndStatusOrderByCreatedAtDesc(phoneNumber, clientApplicationId, ResetStatus.ACTIVE),
                    passwordResetOtpRepository::save);

            String rawOtp = otpService.generateOtp(properties.getOtp().getLength());

            PasswordResetOtp otpEntity = new PasswordResetOtp();
            otpEntity.setUserId(user.getId());
            otpEntity.setClientApplicationId(clientApplicationId);
            otpResetEngine.populateNewOtp(otpEntity, phoneNumber, rawOtp, properties.getOtp().getExpirationMinutes(), properties.getOtp().getMaxAttempts());
            passwordResetOtpRepository.save(otpEntity);

            String appName = clientApplicationService.getById(clientApplicationId).getName();
            otpDeliveryService.sendPasswordResetOtp(phoneNumber, rawOtp, appName);
            log.info("Password reset OTP requested for a registered phone number");
        } else {
            log.info("Password reset OTP requested for an unregistered phone number");
        }

        otpResetEngine.startCooldown(cooldownBucket, properties.getOtp().getResendCooldownSeconds());

        return new PasswordResetResponse(GENERIC_REQUEST_MESSAGE, 200, null);
    }

    @Override
    @Transactional
    public VerifyOtpResponse verifyOtp(VerifyOtpRequest request, Long clientApplicationId) {
        resetValidator.validatePhoneNumberFoResetOperations(request.getPhoneNumber());
        resetValidator.validateOtpFormat(request.getOtp(), properties.getOtp().getLength());

        String phoneNumber = request.getPhoneNumber();
        PasswordResetOtp otpEntity = passwordResetOtpRepository.findTopByPhoneNumberAndClientApplicationIdAndStatusOrderByCreatedAtDesc(phoneNumber, clientApplicationId, ResetStatus.ACTIVE)
                .orElseThrow(() -> new OtpInvalidException("The verification code is invalid."));

        otpResetEngine.verify(otpEntity, request.getOtp(), passwordResetOtpRepository::save);

        String rawResetToken = otpService.generateResetToken();
        PasswordResetToken resetToken = new PasswordResetToken();
        resetToken.setUserId(otpEntity.getUserId());
        otpResetEngine.populateNewToken(resetToken, rawResetToken, properties.getToken().getExpirationMinutes());
        passwordResetTokenRepository.save(resetToken);

        return new VerifyOtpResponse(rawResetToken);
    }

    @Override
    @Transactional
    public PasswordResetResponse requestEmailOtp(EmailPasswordResetRequest request, Long clientApplicationId) {
        String email = request.getEmail() == null ? "" : request.getEmail().trim();
        if (email.isEmpty() || !email.contains("@")) {
            throw new BadRequestException("A valid email address is required.");
        }

        String cooldownKey = clientApplicationId + ":email:" + email.toLowerCase();
        RBucket<String> cooldownBucket = otpResetEngine.getCooldownBucket(redissonClient, PASSWORD_RESET_COOLDOWN_KEY_PREFIX, cooldownKey);
        otpResetEngine.rejectIfCoolingDown(cooldownBucket);

        Optional<User> userOptional = userRepository.findByEmailAndClientApplicationId(email, clientApplicationId);

        if (userOptional.isPresent()) {
            User user = userOptional.get();
            otpResetEngine.invalidateExisting(
                    passwordResetOtpRepository.findTopByEmailAndClientApplicationIdAndStatusOrderByCreatedAtDesc(email, clientApplicationId, ResetStatus.ACTIVE),
                    passwordResetOtpRepository::save);

            String rawOtp = otpService.generateOtp(properties.getOtp().getLength());

            PasswordResetOtp otpEntity = new PasswordResetOtp();
            otpEntity.setUserId(user.getId());
            otpEntity.setClientApplicationId(clientApplicationId);
            otpResetEngine.populateNewOtp(otpEntity, null, rawOtp, properties.getOtp().getExpirationMinutes(), properties.getOtp().getMaxAttempts());
            otpEntity.setEmail(email);
            passwordResetOtpRepository.save(otpEntity);

            String appName = clientApplicationService.getById(clientApplicationId).getName();
            emailDeliveryService.sendPasswordResetOtpEmail(email, rawOtp, appName);
            log.info("Password reset email OTP requested for a registered email address");
        } else {
            log.info("Password reset email OTP requested for an unregistered email address");
        }

        otpResetEngine.startCooldown(cooldownBucket, properties.getOtp().getResendCooldownSeconds());

        return new PasswordResetResponse(GENERIC_REQUEST_MESSAGE, 200, null);
    }

    @Override
    @Transactional
    public VerifyOtpResponse verifyEmailOtp(EmailVerifyOtpRequest request, Long clientApplicationId) {
        resetValidator.validateOtpFormat(request.getOtp(), properties.getOtp().getLength());

        String email = request.getEmail() == null ? "" : request.getEmail().trim();
        PasswordResetOtp otpEntity = passwordResetOtpRepository.findTopByEmailAndClientApplicationIdAndStatusOrderByCreatedAtDesc(email, clientApplicationId, ResetStatus.ACTIVE)
                .orElseThrow(() -> new OtpInvalidException("The verification code is invalid."));

        otpResetEngine.verify(otpEntity, request.getOtp(), passwordResetOtpRepository::save);

        String rawResetToken = otpService.generateResetToken();
        PasswordResetToken resetToken = new PasswordResetToken();
        resetToken.setUserId(otpEntity.getUserId());
        otpResetEngine.populateNewToken(resetToken, rawResetToken, properties.getToken().getExpirationMinutes());
        passwordResetTokenRepository.save(resetToken);

        return new VerifyOtpResponse(rawResetToken);
    }

    @Override
    @Transactional
    public PasswordResetResponse completeReset(CompletePasswordResetRequest request) {
        resetValidator.validateNewPassword(request.getNewPassword(), request.getConfirmPassword());

        if (request.getResetToken() == null || request.getResetToken().isBlank()) {
            throw new ResetTokenInvalidException("Your password reset session has expired. Please start again.");
        }

        String tokenHash = otpService.hashResetToken(request.getResetToken());
        PasswordResetToken resetToken = passwordResetTokenRepository.findByTokenHash(tokenHash)
                .orElseThrow(() -> new ResetTokenInvalidException("Your password reset session has expired. Please start again."));

        otpResetEngine.assertUsable(resetToken, "Your password reset session has expired. Please start again.");

        User user = userRepository.findById(resetToken.getUserId())
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        user.setPasswordChangedAt(LocalDateTime.now());
        userRepository.save(user);

        otpResetEngine.markUsed(resetToken, passwordResetTokenRepository::save);

        sessionManagementService.invalidateActiveSessionForUser(user.getId());

        log.info("Password reset completed successfully for user id {}", user.getId());
        return new PasswordResetResponse("Password reset successful. Please log in with your new password.", 200, user.getPhoneNumber());
    }
}
