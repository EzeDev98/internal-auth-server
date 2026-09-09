package com.internal.auth.feature.identity.dto.request;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Request body for POST /api/v1/auth/resend-phone-verification. */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class ResendPhoneVerificationRequest {
    private String phoneNumber;
}
