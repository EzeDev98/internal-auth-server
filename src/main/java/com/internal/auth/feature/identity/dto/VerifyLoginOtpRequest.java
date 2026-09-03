package com.internal.auth.feature.identity.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Request body for POST /api/v1/auth/login/verify-otp (Step 11E). */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class VerifyLoginOtpRequest {
    private String phoneNumber;
    private String otp;
}
