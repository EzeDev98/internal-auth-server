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

/** Issues and verifies phone verification OTPs. */
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
        if (phoneNumber == null || phoneNumber.isBlank() || clientApplicationId == null) {
            return new ActivationResponse(GENERIC_RESEND_MESSAGE);
        }

        String cooldownKey = clientApplicationId + ":" + phoneNumber;
        RBucket<String> cooldownBucket = otpResetEngine.getCooldownBucket(redissonClient, PHONE_VERIFICATION_COOLDOWN_KEY_PREFIX, cooldownKey);
        otpResetEngine.rejectIfCoolingDown(cooldownBucket);

        userRepository.findByPhoneNumberAndClientApplicationId(phoneNumber.trim(), clientApplicationId)
                .ifPresent(this::sendVerificationOtp);

        log.info("Phone verification resend requested for a phone number");

        otpResetEngine.startCooldown(cooldownBucket, properties.getResendCooldownSeconds());

        return new ActivationResponse(GENERIC_RESEND_MESSAGE);
    }
}
