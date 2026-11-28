package com.internal.auth.feature.identity.dto.request;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Request body for logging in. */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class LoginRequest {
    private String username;
    private String password;

    private String userAgent;

    public LoginRequest(String username, String password) {
        this(username, password, null);
    }
}
