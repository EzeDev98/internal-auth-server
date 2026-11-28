package com.internal.auth.feature.identity.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Response for admin registration. */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class AdminRegisterResponse {
    private Long userId;
    private String username;
    private String message;
}
