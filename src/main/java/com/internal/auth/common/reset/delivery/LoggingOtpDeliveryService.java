package com.internal.auth.common.reset.delivery;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

/**
 * Development-friendly OtpDeliveryService implementation.
 *
 * Active by default (app.otp.provider=logging, or unset) so the OTP delivery
 * abstraction has a working implementation without contaminating callers
 * with provider-specific detail. Logs the OTP instead of sending it over SMS.
 *
 * IMPORTANT: logging the raw OTP is strictly a development convenience and
 * is gated behind app.otp.log-to-console, which must be disabled (false)
 * in production. To use a real provider instead, set app.otp.provider to
 * that provider's name (e.g. "contiguity") — see ContiguityOtpDeliveryService.
 * Callers require no changes either way.
 */
@Service
@ConditionalOnProperty(prefix = "app.otp", name = "provider", havingValue = "logging", matchIfMissing = true)
public class LoggingOtpDeliveryService implements OtpDeliveryService {

    private static final Logger log = LoggerFactory.getLogger(LoggingOtpDeliveryService.class);

    @Value("${app.otp.log-to-console:false}")
    private boolean logToConsole;

    @Override
    public void sendPasswordResetOtp(String phoneNumber, String otp, String appName) {
        logOtp("Password reset", phoneNumber, otp, appName);
    }

    @Override
    public void sendPhoneVerificationOtp(String phoneNumber, String otp, String appName) {
        logOtp("Phone verification", phoneNumber, otp, appName);
    }

    @Override
    public void sendLoginOtp(String phoneNumber, String otp, String appName) {
        logOtp("Login", phoneNumber, otp, appName);
    }

    private void logOtp(String purpose, String phoneNumber, String otp, String appName) {
        // Never log the raw OTP unless explicitly enabled for local development.
        if (logToConsole) {
            log.info("[DEV ONLY] {} OTP for {} (app={}): {}", purpose, phoneNumber, appName, otp);
        } else {
            log.info("{} OTP generated for {} (app={}, delivery provider not configured)", purpose, phoneNumber, appName);
        }
    }
}
