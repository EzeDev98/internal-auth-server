package com.internal.auth.common.constant;

import java.security.SecureRandom;
import java.time.Duration;

/**
 * Stage 1 punch-list item 8: this class used to carry ~35 additional
 * constants for a wallet/payments/PIN domain this app doesn't implement
 * (SENDER_WALLET_ID, MAX_DAILY_PAYMENT_LIMIT, CURRENCY, WALLET_LOCKED_DURATION,
 * REQUIRED_CONFIRMATION = "WIPE-EVERYTHING", etc.) — confirmed zero
 * references anywhere in this codebase before removal. Only the constants
 * this app actually uses remain below.
 */
public class AppConstant {

    public static final String DEFAULT_PERMISSION_GROUP = "default-group";

    public static final String DEFAULT_PERMISSION_GROUP_DESCRIPTION = "Default group for all new users. Provides basic access permissions.";

    public static final String DEFAULT_ROLE = "basic_access";

    public static final String DEFAULT_ROLE_DESCRIPTION = "Default role for all new users. Provides basic access permissions";

    public static final String REPLACED_BY_NEW_LOGIN = "REPLACED_BY_NEW_LOGIN";

    public static final String LOGOUT = "LOGOUT";

    public static final String ADMIN_ACTION = "ADMIN_ACTION";

    public static final String TTL_EXPIRED = "TTL_EXPIRED";

    public static final String PASSWORD_RESET_COOLDOWN_KEY_PREFIX = "password-reset:otp-cooldown:";

    public static final String GENERIC_REQUEST_MESSAGE = "If an account is associated with this phone number, a verification code has been sent.";

    public static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(10);

    public static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public static final int RESET_TOKEN_BYTES = 32;

    public static final long SESSION_TTL_DAYS = 60;

    public static final int RESET_PASSWORD_RATE_LIMIT_DURATION = 24;

    public static final int MAX_RESET_PASSWORD_REQUEST = 5;

    /**
     * Step 10C: Redis cooldown-bucket key prefix for email-verification
     * resend requests, mirroring PASSWORD_RESET_COOLDOWN_KEY_PREFIX's
     * pattern (see EmailVerificationServiceImpl / EmailVerificationProperties).
     */
    public static final String EMAIL_VERIFICATION_COOLDOWN_KEY_PREFIX = "email-verification:resend-cooldown:";

    /**
     * Step 10D: byte length of the SecureRandom-generated client secret for
     * admin-registered client applications (see ClientApplicationServiceImpl).
     */
    public static final int CLIENT_SECRET_BYTES = 32;

    /**
     * Step 11E: Redis cooldown-bucket key prefix for login-MFA OTP resends
     * (see LoginServiceImpl).
     */
    public static final String LOGIN_MFA_OTP_COOLDOWN_KEY_PREFIX = "login-mfa:otp-cooldown:";

    /**
     * Step 11F: /verify-otp previously had no rate limiting of its own —
     * only the per-OTP attemptCount (max 5, see PasswordOtp.maxAttempts)
     * guarded it, and that counter resets every time a fresh OTP is
     * requested. Keyed by phone number, same as the request-side limiter
     * above, so guessing is capped independently of how many separate OTPs
     * were issued rather than relying solely on /request's pacing.
     */
    public static final String VERIFY_OTP_RATE_LIMIT_KEY_PREFIX = "ratelimit:password-reset-verify:phone:";

    public static final int VERIFY_OTP_RATE_LIMIT_DURATION_HOURS = 24;

    public static final int MAX_VERIFY_OTP_REQUEST = 10;

    /**
     * Step 11F: /complete carries no phone number (only resetToken,
     * newPassword, confirmPassword), so it can't be keyed the same way.
     * Its resetToken is a 256-bit random value (see OtpService.generateResetToken),
     * cryptographically infeasible to brute force, so this is generic
     * abuse/DoS protection rather than a guessing defense — keyed by
     * client IP instead.
     */
    public static final String COMPLETE_RESET_RATE_LIMIT_KEY_PREFIX = "ratelimit:password-reset-complete:ip:";

    public static final int COMPLETE_RESET_RATE_LIMIT_DURATION_HOURS = 1;

    public static final int MAX_COMPLETE_RESET_REQUEST = 10;

    /**
     * Step 14C: rate limits login attempts by client IP. No per-account
     * lockout exists yet (confirmed absent from User/LoginServiceImpl), so
     * this is the first line of brute-force defense on this endpoint.
     */
    public static final String LOGIN_RATE_LIMIT_KEY_PREFIX = "ratelimit:login:ip:";
    public static final int LOGIN_RATE_LIMIT_DURATION_MINUTES = 15;
    public static final int MAX_LOGIN_REQUEST = 10;

    /**
     * Step 14C: rate limits login MFA OTP verification attempts by client
     * IP, mirroring LOGIN_RATE_LIMIT_* above.
     */
    public static final String LOGIN_OTP_VERIFY_RATE_LIMIT_KEY_PREFIX = "ratelimit:login-otp-verify:ip:";
    public static final int LOGIN_OTP_VERIFY_RATE_LIMIT_DURATION_MINUTES = 15;
    public static final int MAX_LOGIN_OTP_VERIFY_REQUEST = 10;

    /**
     * Step 14C: rate limits the admin-only session-invalidate endpoint by
     * caller IP. Already @PreAuthorize-gated to admins, so this is
     * abuse-prevention rather than brute-force defense, hence the more
     * generous limit.
     */
    public static final String SESSION_INVALIDATE_RATE_LIMIT_KEY_PREFIX = "ratelimit:session-invalidate:ip:";
    public static final int SESSION_INVALIDATE_RATE_LIMIT_DURATION_HOURS = 1;
    public static final int MAX_SESSION_INVALIDATE_REQUEST = 20;

    /**
     * Step 14D: grace period an old signing key stays ACTIVE (verifiable)
     * after being superseded as current, before SigningKeyServiceImpl
     * retires it on the next rotation.
     */
    public static final int SIGNING_KEY_GRACE_PERIOD_DAYS = 7;

    /**
     * Step 14D: rate limits the admin-only signing-key rotation endpoint
     * by caller IP, same abuse-prevention rationale as
     * SESSION_INVALIDATE_RATE_LIMIT_* above.
     */
    public static final String SIGNING_KEY_ROTATE_RATE_LIMIT_KEY_PREFIX = "ratelimit:signing-key-rotate:ip:";
    public static final int SIGNING_KEY_ROTATE_RATE_LIMIT_DURATION_DAYS = 1;
    public static final int MAX_SIGNING_KEY_ROTATE_REQUEST = 5;
}
