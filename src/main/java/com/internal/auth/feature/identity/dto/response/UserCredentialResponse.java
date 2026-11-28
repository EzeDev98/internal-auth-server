package com.internal.auth.feature.identity.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

/** Credential details shown for a user. */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class UserCredentialResponse {
    private String type;
    private LocalDateTime createdAt;
}
