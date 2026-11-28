package com.internal.auth.feature.passwordreset.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Response for password reset requests. */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class PasswordResetResponse {
    private String message;
    private int statusCode;
    private String phoneNumber;
}
