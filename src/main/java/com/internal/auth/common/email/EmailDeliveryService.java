package com.internal.auth.common.email;

/** Abstraction for sending transactional emails. */
public interface EmailDeliveryService {
    void sendVerificationEmail(String email, String verificationLink, String appName);

    void sendPasswordResetOtpEmail(String email, String otp, String appName);
}
