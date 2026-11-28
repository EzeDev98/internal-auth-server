package com.internal.auth.feature.identity.dto.request;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Request body for registering an admin. */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class AdminRegisterRequest {
    private String username;
    private String phoneNumber;
    private String email;
    private String password;
    private String confirmPassword;
}
