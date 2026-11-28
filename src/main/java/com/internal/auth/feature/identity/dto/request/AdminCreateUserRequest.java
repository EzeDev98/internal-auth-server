package com.internal.auth.feature.identity.dto.request;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Request body for an admin creating a user. */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class AdminCreateUserRequest {
    private String username;
    private String phoneNumber;
    private String email;
    private String password;
    private String confirmPassword;
}
