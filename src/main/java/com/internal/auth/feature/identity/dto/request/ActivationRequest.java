package com.internal.auth.feature.identity.dto.request;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Request body for activating an account. */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class ActivationRequest {
    private String token;
}
