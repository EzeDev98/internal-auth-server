package com.internal.auth.feature.identity.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Response for user registration. */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class RegisterResponse {
    private String internalAuthUserId;
    private String username;
    private String message;
}
