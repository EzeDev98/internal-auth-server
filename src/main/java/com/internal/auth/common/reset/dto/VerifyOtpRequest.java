package com.internal.auth.common.reset.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Request body for verifying a reset OTP. */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class VerifyOtpRequest {
    private String phoneNumber;
    private String otp;
}
