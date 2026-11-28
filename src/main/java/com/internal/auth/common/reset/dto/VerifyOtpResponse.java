package com.internal.auth.common.reset.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Response carrying the short-lived reset token issued after OTP verification. */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class VerifyOtpResponse {
    private String resetToken;
}
