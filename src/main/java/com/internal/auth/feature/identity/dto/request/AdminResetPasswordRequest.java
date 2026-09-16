package com.internal.auth.feature.identity.dto.request;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Request body for POST ${app.title}/users/{username}/credentials/reset -
 * an admin setting a new password directly for a user's account, as
 * opposed to PasswordResetServiceImpl's OTP-then-token self-service flow.
 * Validated by the same ResetValidator#validateNewPassword rule that flow
 * and AdminUserServiceImpl#createUser already use.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class AdminResetPasswordRequest {
    private String newPassword;
    private String confirmPassword;
}
