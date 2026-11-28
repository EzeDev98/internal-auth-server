package com.internal.auth.common.reset.delivery;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

/** Default OTP delivery implementation that logs OTPs instead of sending them. */
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

    private void logOtp(String purpose, String phoneNumber, String otp, String appName) {
        if (logToConsole) {
            log.info("[DEV ONLY] {} OTP for {} (app={}): {}", purpose, phoneNumber, appName, otp);
        } else {
            log.info("{} OTP generated for {} (app={}, delivery provider not configured)", purpose, phoneNumber, appName);
        }
    }
}
