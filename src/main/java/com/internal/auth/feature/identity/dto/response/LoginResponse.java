package com.internal.auth.feature.identity.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Response for login and token refresh. */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class LoginResponse {
    private Long userId;
    private String username;
    private String message;
    private String accessToken;
    private String refreshToken;
    private Long expiresIn;
    private Long refreshExpiresIn;
}
