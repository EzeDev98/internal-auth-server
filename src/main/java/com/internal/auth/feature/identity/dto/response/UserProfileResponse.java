package com.internal.auth.feature.identity.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

/** Profile details of a single user. */
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
    private LocalDateTime createdAt;
}
