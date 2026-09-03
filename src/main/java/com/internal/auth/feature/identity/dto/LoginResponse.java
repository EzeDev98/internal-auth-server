package com.internal.auth.feature.identity.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Response body for POST /api/v1/auth/login and
 * POST /api/v1/auth/login/verify-otp (Steps 11A/11E). No token field -
 * per the Step 11A scoping decision, still no bearer token until Step 12.
 * mfaRequired=true (Step 11E) means the password was correct but a login
 * OTP was sent and must be verified via verify-otp before login is
 * actually complete; userId is omitted in that case, since login hasn't
 * finished yet.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class LoginResponse {
    private Long userId;
    private String username;
    private String message;
    private boolean mfaRequired;
}
