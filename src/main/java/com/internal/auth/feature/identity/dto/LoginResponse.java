package com.internal.auth.feature.identity.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Response body for POST /api/v1/auth/login and
 * POST /api/v1/auth/login/verify-otp (Steps 11A/11E).
 * mfaRequired=true (Step 11E) means the password was correct but a login
 * OTP was sent and must be verified via verify-otp before login is
 * actually complete; userId and accessToken are both omitted in that
 * case, since login hasn't finished yet.
 * <p>Step 12F: accessToken carries a real self-issued bearer token, minted
 * directly by LoginServiceImpl once login actually completes (see that
 * class's javadoc for why this happens in-process rather than via a
 * separate /oauth2/token round trip). Null whenever mfaRequired=true.
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
    private String accessToken;
}
