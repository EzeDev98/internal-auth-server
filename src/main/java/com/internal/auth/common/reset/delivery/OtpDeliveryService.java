package com.internal.auth.common.reset.delivery;

/** Abstraction for delivering an OTP to a phone number. */
public interface OtpDeliveryService {
    void sendPasswordResetOtp(String phoneNumber, String otp, String appName);

    void sendPhoneVerificationOtp(String phoneNumber, String otp, String appName);
}
