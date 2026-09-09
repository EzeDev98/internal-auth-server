package com.internal.auth.feature.identity.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

/**
 * Single-user profile shape for GET/PATCH ${app.title}/users/{username}
 * (Step 2A, React Admin Client plan v4): email, phone, verified flags,
 * enabled, MFA status, created date - exactly the plan's Step 2A spec.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class UserProfileResponse {
    private Long id;
    private String username;
    private String phoneNumber;
    private String email;
    private boolean enabled;
    private boolean emailVerified;
    private boolean phoneVerified;
    private boolean mfaEnabled;
    private LocalDateTime createdAt;
}
