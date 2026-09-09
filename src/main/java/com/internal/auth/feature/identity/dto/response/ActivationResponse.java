package com.internal.auth.feature.identity.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Shared response shape for activate/resend-activation (Step 10C). */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class ActivationResponse {
    private String message;
}
