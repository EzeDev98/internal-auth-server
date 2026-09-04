package com.internal.auth.common.reset.delivery;

/**
 * Decoupled abstraction for delivering an OTP to a user's phone number.
 * Business logic depends only on this interface and never on a specific
 * provider (Termii, Twilio, Africa's Talking, etc.).
 *
 * Every send method takes the calling app's display name
 * (ClientApplication.name, e.g. "SyncPoint"/"Notare") so the SMS text is
 * branded per app rather than one global sender name - see
 * ContiguityOtpDeliveryService.
 */
public interface OtpDeliveryService {

    /**
     * Send a password-reset OTP to the given phone number.
     *
     * @param phoneNumber the recipient's registered phone number
     * @param otp         the raw (unhashed) OTP to deliver
     * @param appName     the calling app's display name, for SMS branding
     */
    void sendPasswordResetOtp(String phoneNumber, String otp, String appName);

    /**
     * Send a phone-verification OTP to the given phone number
     * (self-service phone verification). Kept distinct from
     * sendPasswordResetOtp so the delivered SMS text is accurate rather
     * than saying "password reset" for what is actually an account
     * activation code.
     *
     * @param phoneNumber the recipient's registered phone number
     * @param otp         the raw (unhashed) OTP to deliver
     * @param appName     the calling app's display name, for SMS branding
     */
    void sendPhoneVerificationOtp(String phoneNumber, String otp, String appName);

    /**
     * Send a login-MFA step-up OTP to the given phone number
     * (LoginServiceImpl#sendLoginOtp). Kept distinct from
     * sendPasswordResetOtp for the same reason sendPhoneVerificationOtp
     * is - this previously reused sendPasswordResetOtp and texted "Your
     * password reset code is..." for what was actually a login step-up
     * code.
     *
     * @param phoneNumber the recipient's registered phone number
     * @param otp         the raw (unhashed) OTP to deliver
     * @param appName     the calling app's display name, for SMS branding
     */
    void sendLoginOtp(String phoneNumber, String otp, String appName);
}
