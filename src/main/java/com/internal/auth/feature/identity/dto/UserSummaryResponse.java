package com.internal.auth.feature.identity.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

/**
 * List-row shape for GET ${app.title}/users (Step 2A, React Admin Client
 * plan v4) - deliberately lighter than UserProfileResponse (no verified
 * flags), matching what the Users - List screen's table actually renders.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class UserSummaryResponse {
    private Long id;
    private String username;
    private String phoneNumber;
    private String email;
    private boolean enabled;
    private boolean mfaEnabled;
    private LocalDateTime createdAt;
}
