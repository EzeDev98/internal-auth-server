package com.internal.auth.feature.identity.service.impl;

import com.internal.auth.common.exception.OtpInvalidException;
import com.internal.auth.common.exception.UserNotFoundException;
import com.internal.auth.common.reset.OtpResetEngine;
import com.internal.auth.common.reset.OtpService;
import com.internal.auth.common.reset.ResetValidator;
import com.internal.auth.common.reset.delivery.OtpDeliveryService;
import com.internal.auth.common.reset.dto.VerifyOtpRequest;
import com.internal.auth.feature.client.service.ClientApplicationService;
import com.internal.auth.feature.identity.config.PhoneVerificationProperties;
import com.internal.auth.feature.identity.dto.response.ActivationResponse;
import com.internal.auth.feature.identity.model.PhoneVerificationOtp;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.identity.repository.PhoneVerificationOtpRepository;
import com.internal.auth.feature.identity.repository.UserRepository;
import com.internal.auth.feature.identity.service.PhoneVerificationService;
import com.internal.auth.common.reset.ResetStatus;
import lombok.RequiredArgsConstructor;
import org.redisson.api.RBucket;
import org.redisson.api.RedissonClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import static com.internal.auth.common.constant.AppConstant.PHONE_VERIFICATION_COOLDOWN_KEY_PREFIX;

/**
 * Self-service phone verification (fixes the previously-permanent
 * phone-only-account login gate - see User's class Javadoc and
 * LoginServiceImpl#describeUnverifiedContactMethods). Reuses the same
 * OTP-lifecycle machinery password reset and login MFA already use
 * (OtpResetEngine/OtpService/OtpDeliveryService/ResetValidator) rather than
 * a link/token like email verification - SMS is the channel, so a code the
 * user types back in is the natural fit.
 *
 * SMS is sent via OtpDeliveryService#sendPhoneVerificationOtp, branded
 * with the calling app's display name (ClientApplicationService#getById)
 * rather than a single global sender name.
 */
@Service
@RequiredArgsConstructor
public class PhoneVerificationServiceImpl implements PhoneVerificationService {

    private static final Logger log = LoggerFactory.getLogger(PhoneVerificationServiceImpl.class);
    private static final String GENERIC_RESEND_MESSAGE =
            "If this phone number is registered and not yet verified, a verification code has been sent.";

    private final UserRepository userRepository;
    private final PhoneVerificationOtpRepository phoneVerificationOtpRepository;
    private final OtpService otpService;
    private final OtpDeliveryService otpDeliveryService;
    private final OtpResetEngine otpResetEngine;
    private final ResetValidator resetValidator;
    private final PhoneVerificationProperties properties;
    private final RedissonClient redissonClient;
    private final ClientApplicationService clientApplicationService;

    @Override
    @Transactional
    public void sendVerificationOtp(User user) {
        if (user.getPhoneNumber() == null || user.getPhoneNumber().isBlank() || user.isPhoneVerified()) {
            return;
        }
        try {
            String phoneNumber = user.getPhoneNumber();

            otpResetEngine.invalidateExisting(
                    phoneVerificationOtpRepository.findTopByPhoneNumberAndClientApplicationIdAndStatusOrderByCreatedAtDesc(
                            phoneNumber, user.getClientApplicationId(), ResetStatus.ACTIVE),
                    phoneVerificationOtpRepository::save);

            String rawOtp = otpService.generateOtp(properties.getOtpLength());

            PhoneVerificationOtp otpEntity = new PhoneVerificationOtp();
            otpEntity.setUserId(user.getId());
            otpEntity.setClientApplicationId(user.getClientApplicationId());
            otpResetEngine.populateNewOtp(otpEntity, phoneNumber, rawOtp, properties.getOtpExpirationMinutes(), properties.getMaxAttempts());
            phoneVerificationOtpRepository.save(otpEntity);

            String appName = clientApplicationService.getById(user.getClientApplicationId()).getName();
            otpDeliveryService.sendPhoneVerificationOtp(phoneNumber, rawOtp, appName);
        } catch (Exception e) {
            // Delivery/provider failures must never block registration or
            // resend from otherwise succeeding - mirrors
            // EmailVerificationServiceImpl#sendVerificationEmail.
            log.warn("Failed to send phone verification OTP for user id {}: {}", user.getId(), e.getMessage());
        }
    }

    @Override
    @Transactional
    public ActivationResponse verify(VerifyOtpRequest request, Long clientApplicationId) {
        resetValidator.validatePhoneNumberFoResetOperations(request.getPhoneNumber());
        resetValidator.validateOtpFormat(request.getOtp(), properties.getOtpLength());

        String phoneNumber = request.getPhoneNumber();
        PhoneVerificationOtp otp = phoneVerificationOtpRepository
                .findTopByPhoneNumberAndClientApplicationIdAndStatusOrderByCreatedAtDesc(phoneNumber, clientApplicationId, ResetStatus.ACTIVE)
                .orElseThrow(() -> new OtpInvalidException("The verification code is invalid."));

        otpResetEngine.verify(otp, request.getOtp(), phoneVerificationOtpRepository::save);

        User user = userRepository.findById(otp.getUserId())
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        user.setPhoneVerified(true);

        // Product decision: verifying phone is sufficient proof of account
        // ownership to also clear the email leg of the login gate (see
        // User's class Javadoc / UserLoginServiceImpl#describeUnverifiedContactMethods)
        // for an account that supplied both. Deliberately one-directional -
        // EmailVerificationServiceImpl#activate does NOT set phoneVerified
        // in return, since phoneVerified also gates MfaAdminServiceImpl's
        // SMS-MFA-enable check and email verification is not proof anyone
        // received anything at the phone number on file.
        if (user.getEmail() != null && !user.getEmail().isBlank() && !user.isEmailVerified()) {
            user.setEmailVerified(true);
            log.info("Email auto-verified for user id {} via phone verification", user.getId());
        }

        userRepository.save(user);

        log.info("Phone number verified for user id {}", user.getId());
        return new ActivationResponse("Your phone number has been verified.");
    }

    @Override
    @Transactional
    public ActivationResponse resendVerification(String phoneNumber, Long clientApplicationId) {
        // User-enumeration protection: an unregistered phone number, an
        // already-verified user, and a genuinely-sent OTP must all produce
        // the exact same response - mirrors PasswordResetServiceImpl's
        // "silently no-op for an unregistered phone number" approach.
        if (phoneNumber == null || phoneNumber.isBlank() || clientApplicationId == null) {
            return new ActivationResponse(GENERIC_RESEND_MESSAGE);
        }

        String cooldownKey = clientApplicationId + ":" + phoneNumber;
        RBucket<String> cooldownBucket = otpResetEngine.getCooldownBucket(redissonClient, PHONE_VERIFICATION_COOLDOWN_KEY_PREFIX, cooldownKey);
        otpResetEngine.rejectIfCoolingDown(cooldownBucket);

        userRepository.findByPhoneNumberAndClientApplicationId(phoneNumber.trim(), clientApplicationId)
                // sendVerificationOtp() already no-ops for an already-verified
                // user, so this is safe to call unconditionally here.
                .ifPresent(this::sendVerificationOtp);

        log.info("Phone verification resend requested for a phone number");

        otpResetEngine.startCooldown(cooldownBucket, properties.getResendCooldownSeconds());

        return new ActivationResponse(GENERIC_RESEND_MESSAGE);
    }
}
