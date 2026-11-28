package com.internal.auth.feature.identity.dto.request;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Request body for resending a phone verification OTP. */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class ResendPhoneVerificationRequest {
    private String phoneNumber;
}
