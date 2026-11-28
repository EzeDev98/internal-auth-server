package com.internal.auth.feature.identity.dto.request;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Request body for an admin setting a user's password. */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class AdminResetPasswordRequest {
    private String newPassword;
    private String confirmPassword;
}
