package com.internal.auth.common.constant;

import java.security.SecureRandom;
import java.time.Duration;

/** Application-wide constants for default roles, groups, session end reasons and rate limits. */
public class AppConstant {

    public static final String DEFAULT_PERMISSION_GROUP = "default-group";

    public static final String DEFAULT_PERMISSION_GROUP_DESCRIPTION = "Default group for all new users. Provides basic access permissions.";

    public static final String DEFAULT_ROLE = "basic_access";

    public static final String DEFAULT_ROLE_DESCRIPTION = "Default role for all new users. Provides basic access permissions";

    public static final String REPLACED_BY_NEW_LOGIN = "REPLACED_BY_NEW_LOGIN";

    public static final String LOGOUT = "LOGOUT";

    public static final String ADMIN_ACTION = "ADMIN_ACTION";

    public static final String TTL_EXPIRED = "TTL_EXPIRED";
    
    public static final String REFRESH_TOKEN_ENDED = "REFRESH_TOKEN_ENDED";

    public static final String SESSION_LIMIT_REACHED = "SESSION_LIMIT_REACHED";

    public static final String SIGNED_OUT_FROM_ANOTHER_DEVICE = "SIGNED_OUT_FROM_ANOTHER_DEVICE";

    public static final int MAX_ACTIVE_SESSIONS_CEILING = 20;

    public static final String PASSWORD_RESET_COOLDOWN_KEY_PREFIX = "password-reset:otp-cooldown:";

    public static final String GENERIC_REQUEST_MESSAGE = "A verification code has been sent.";

    public static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(10);

    public static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public static final int RESET_TOKEN_BYTES = 32;

    public static final long SESSION_TTL_DAYS = 60;

    public static final int RESET_PASSWORD_RATE_LIMIT_DURATION = 24;

    public static final int MAX_RESET_PASSWORD_REQUEST = 5;

    public static final String EMAIL_VERIFICATION_COOLDOWN_KEY_PREFIX = "email-verification:resend-cooldown:";

    public static final int CLIENT_SECRET_BYTES = 32;

    public static final String VERIFY_OTP_RATE_LIMIT_KEY_PREFIX = "ratelimit:password-reset-verify:phone:";

    public static final int VERIFY_OTP_RATE_LIMIT_DURATION_HOURS = 24;

    public static final int MAX_VERIFY_OTP_REQUEST = 10;

    public static final String COMPLETE_RESET_RATE_LIMIT_KEY_PREFIX = "ratelimit:password-reset-complete:ip:";

    public static final int COMPLETE_RESET_RATE_LIMIT_DURATION_HOURS = 1;

    public static final int MAX_COMPLETE_RESET_REQUEST = 10;

    public static final String LOGIN_RATE_LIMIT_KEY_PREFIX = "ratelimit:login:ip:";
    public static final int LOGIN_RATE_LIMIT_DURATION_MINUTES = 15;
    public static final int MAX_LOGIN_REQUEST = 10;

    public static final String LOGIN_ACCOUNT_RATE_LIMIT_KEY_PREFIX = "ratelimit:login:account:";
    public static final int LOGIN_ACCOUNT_RATE_LIMIT_DURATION_MINUTES = 15;
    public static final int MAX_LOGIN_ACCOUNT_REQUEST = 5;

    public static final String REFRESH_TOKEN_RATE_LIMIT_KEY_PREFIX = "ratelimit:refresh-token:ip:";
    public static final int REFRESH_TOKEN_RATE_LIMIT_DURATION_MINUTES = 15;
    public static final int MAX_REFRESH_TOKEN_REQUEST = 30;

    public static final String SESSION_INVALIDATE_RATE_LIMIT_KEY_PREFIX = "ratelimit:session-invalidate:ip:";
    public static final int SESSION_INVALIDATE_RATE_LIMIT_DURATION_HOURS = 1;
    public static final int MAX_SESSION_INVALIDATE_REQUEST = 20;
    public static final String SESSION_STATUS_RATE_LIMIT_KEY_PREFIX = "ratelimit:session-status:ip:";
    public static final int SESSION_STATUS_RATE_LIMIT_DURATION_HOURS = 1;
    public static final int MAX_SESSION_STATUS_REQUEST = 600;

    public static final int SIGNING_KEY_GRACE_PERIOD_DAYS = 7;

    public static final String SIGNING_KEY_ROTATE_RATE_LIMIT_KEY_PREFIX = "ratelimit:signing-key-rotate:ip:";
    public static final int SIGNING_KEY_ROTATE_RATE_LIMIT_DURATION_DAYS = 1;
    public static final int MAX_SIGNING_KEY_ROTATE_REQUEST = 5;

    public static final String PHONE_VERIFICATION_COOLDOWN_KEY_PREFIX = "phone-verification:resend-cooldown:";

    public static final String PHONE_VERIFICATION_VERIFY_RATE_LIMIT_KEY_PREFIX = "ratelimit:phone-verification-verify:phone:";
    public static final int PHONE_VERIFICATION_VERIFY_RATE_LIMIT_DURATION_HOURS = 24;
    public static final int MAX_PHONE_VERIFICATION_VERIFY_REQUEST = 10;

    public static final String CLIENT_SECRET_ROTATE_RATE_LIMIT_KEY_PREFIX = "ratelimit:client-secret-rotate:ip:";
    public static final int CLIENT_SECRET_ROTATE_RATE_LIMIT_DURATION_DAYS = 1;
    public static final int MAX_CLIENT_SECRET_ROTATE_REQUEST = 5;
    public static final String ADMIN_ROLE = "create-admin";

    public static final String ADMIN_ROLE_DESCRIPTION = "Full administrative access - equivalent to Keycloak's realm-admin role. Can manage users, roles, permission groups, client applications, sessions, and signing keys.";

    public static final String ADMIN_PERMISSION_GROUP = "admin-group";

    public static final String ADMIN_PERMISSION_GROUP_DESCRIPTION = "Administrative group granting full platform access.";

    public static final String INTERNAL_ADMIN_CLIENT_ID = "internal-auth-admin-console";

}
