package com.internal.auth.feature.identity.dto.request;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Request body for resending an activation email. */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class ResendActivationRequest {
    private String email;
}
