package com.internal.auth.feature.passwordreset.dto.request;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Request body for verifying an emailed password reset OTP. */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class EmailVerifyOtpRequest {
    private String email;
    private String otp;
}
