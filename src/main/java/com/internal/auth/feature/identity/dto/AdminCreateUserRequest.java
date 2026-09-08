package com.internal.auth.feature.identity.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Request body for POST ${app.title}/users (Step 2G). Same shape as
 * RegisterRequest/AdminRegisterRequest (phoneNumber/email both optional
 * individually, at least one required - see
 * RegistrationValidator#validateContactInfoPresent) - kept as its own type
 * rather than reused so this admin-create flow can evolve independently of
 * self-registration and the admin-bootstrap flow.
 */
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
