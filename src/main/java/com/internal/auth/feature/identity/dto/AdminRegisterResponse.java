package com.internal.auth.feature.identity.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Response body for POST /api/v1/admin/register. Deliberately carries no
 * token - use POST /api/v1/admin/login separately to get one, same
 * register-then-login split as the regular tenant flow.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class AdminRegisterResponse {
    private Long userId;
    private String username;
    private String message;
}
