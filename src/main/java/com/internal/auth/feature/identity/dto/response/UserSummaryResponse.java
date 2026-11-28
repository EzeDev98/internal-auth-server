package com.internal.auth.feature.identity.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

/** List row for a user. */
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
    private LocalDateTime createdAt;
    private String clientId;
}
