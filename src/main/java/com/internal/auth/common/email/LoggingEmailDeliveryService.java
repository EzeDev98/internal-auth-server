package com.internal.auth.common.email;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

/** Default email delivery implementation that logs messages instead of sending them. */
@Service
@ConditionalOnProperty(prefix = "app.email", name = "provider", havingValue = "logging", matchIfMissing = true)
public class LoggingEmailDeliveryService implements EmailDeliveryService {

    private static final Logger log = LoggerFactory.getLogger(LoggingEmailDeliveryService.class);

    @Value("${app.email.log-to-console:false}")
    private boolean logToConsole;

    @Override
    public void sendVerificationEmail(String email, String verificationLink, String appName) {
        if (logToConsole) {
            log.info("[DEV ONLY] Email verification link for {} (app={}): {}", email, appName, verificationLink);
        } else {
            log.info("Email verification link generated for {} (app={}, delivery provider not configured)", email, appName);
        }
    }

    @Override
    public void sendPasswordResetOtpEmail(String email, String otp, String appName) {
        if (logToConsole) {
            log.info("[DEV ONLY] Password reset code for {} (app={}): {}", email, appName, otp);
        } else {
            log.info("Password reset code generated for {} (app={}, delivery provider not configured)", email, appName);
        }
    }
}
