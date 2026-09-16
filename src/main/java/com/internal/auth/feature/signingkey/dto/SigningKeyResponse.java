package com.internal.auth.feature.signingkey.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class SigningKeyResponse {
    private String kid;
    private String status;
    private boolean current;
    private LocalDateTime createdAt;
    private LocalDateTime retiredAt;
}
