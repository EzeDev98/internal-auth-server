package com.internal.auth.feature.identity.service.impl;

import com.internal.auth.common.crypto.TokenHasher;
import com.internal.auth.common.email.EmailDeliveryService;
import com.internal.auth.common.exception.ResetTokenInvalidException;
import com.internal.auth.common.exception.UserNotFoundException;
import com.internal.auth.common.reset.OtpResetEngine;
import com.internal.auth.feature.client.service.ClientApplicationService;
import com.internal.auth.feature.identity.config.EmailVerificationProperties;
import com.internal.auth.feature.identity.dto.response.ActivationResponse;
import com.internal.auth.feature.identity.model.EmailVerificationToken;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.identity.repository.EmailVerificationTokenRepository;
import com.internal.auth.feature.identity.repository.UserRepository;
import com.internal.auth.feature.identity.service.EmailVerificationService;
import lombok.RequiredArgsConstructor;
import org.redisson.api.RBucket;
import org.redisson.api.RedissonClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Base64;

import static com.internal.auth.common.constant.AppConstant.EMAIL_VERIFICATION_COOLDOWN_KEY_PREFIX;
import static com.internal.auth.common.constant.AppConstant.RESET_TOKEN_BYTES;
import static com.internal.auth.common.constant.AppConstant.SECURE_RANDOM;

/** Issues and verifies email activation tokens. */
@Service
@RequiredArgsConstructor
public class EmailVerificationServiceImpl implements EmailVerificationService {

    private static final Logger log = LoggerFactory.getLogger(EmailVerificationServiceImpl.class);
    private static final String GENERIC_RESEND_MESSAGE = "A new verification link has been sent.";

    private final UserRepository userRepository;
    private final EmailVerificationTokenRepository tokenRepository;
    private final TokenHasher tokenHasher;
    private final OtpResetEngine otpResetEngine;
    private final EmailDeliveryService emailDeliveryService;
    private final EmailVerificationProperties properties;
    private final RedissonClient redissonClient;
    private final ClientApplicationService clientApplicationService;

    @Value("${base-url}")
    private String baseUrl;

    @Override
    @Transactional
    public void sendVerificationEmail(User user) {
        if (user.getEmail() == null || user.getEmail().isBlank()) {
            return;
        }
        try {
            String rawToken = generateToken();

            EmailVerificationToken token = new EmailVerificationToken();
            token.setUserId(user.getId());
            otpResetEngine.populateNewToken(token, rawToken, properties.getTokenExpirationMinutes());
            tokenRepository.save(token);

            String link = baseUrl + "/api/v1/auth/activate?token=" + rawToken;
            String appName = clientApplicationService.getById(user.getClientApplicationId()).getName();
            emailDeliveryService.sendVerificationEmail(user.getEmail(), link, appName);
        } catch (Exception e) {
            log.warn("Failed to send verification email for user id {}: {}", user.getId(), e.getMessage());
        }
    }

    @Override
    @Transactional
    public ActivationResponse activate(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            throw new ResetTokenInvalidException("This verification link is invalid or has expired.");
        }

        String tokenHash = tokenHasher.sha256Hex(rawToken);
        EmailVerificationToken token = tokenRepository.findByTokenHash(tokenHash)
                .orElseThrow(() -> new ResetTokenInvalidException("This verification link is invalid or has expired."));

        if (token.isUsed()) {
            User alreadyVerifiedUser = userRepository.findById(token.getUserId()).orElse(null);
            if (alreadyVerifiedUser != null && alreadyVerifiedUser.isEmailVerified()) {
                return new ActivationResponse("Your email has been verified.");
            }
            throw new ResetTokenInvalidException("This verification link is invalid or has expired.");
        }

        otpResetEngine.assertUsable(token, "This verification link is invalid or has expired.");

        User user = userRepository.findById(token.getUserId())
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        user.setEmailVerified(true);
        userRepository.save(user);

        otpResetEngine.markUsed(token, tokenRepository::save);

        log.info("Email verified for user id {}", user.getId());
        return new ActivationResponse("Your email has been verified.");
    }

    @Override
    @Transactional
    public ActivationResponse resendVerification(String email, Long clientApplicationId) {
        if (email == null || email.isBlank()) {
            return new ActivationResponse(GENERIC_RESEND_MESSAGE);
        }

        String cooldownKey = clientApplicationId + ":" + email;
        RBucket<String> cooldownBucket = otpResetEngine.getCooldownBucket(
                redissonClient, EMAIL_VERIFICATION_COOLDOWN_KEY_PREFIX, cooldownKey);
        otpResetEngine.rejectIfCoolingDown(cooldownBucket);

        userRepository.findByEmailAndClientApplicationId(email.trim(), clientApplicationId)
                .filter(user -> !user.isEmailVerified())
                .ifPresent(this::sendVerificationEmail);

        otpResetEngine.startCooldown(cooldownBucket, properties.getResendCooldownSeconds());

        return new ActivationResponse(GENERIC_RESEND_MESSAGE);
    }

    private String generateToken() {
        byte[] bytes = new byte[RESET_TOKEN_BYTES];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
