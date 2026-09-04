package com.internal.auth.feature.identity.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Request body for POST /api/v1/admin/register. Same shape as
 * RegisterRequest (phoneNumber/email both optional individually, at least
 * one required - see RegistrationValidator#validateContactInfoPresent) -
 * kept as its own type rather than reused so the admin bootstrap flow can
 * evolve independently of regular tenant registration.
 */
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
