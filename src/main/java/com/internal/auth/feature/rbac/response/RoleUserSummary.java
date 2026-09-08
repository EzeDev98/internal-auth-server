package com.internal.auth.feature.rbac.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Users-in-role row for GET ${app.title}/roles/{id} (Step 2C, React
 * Admin Client plan v4).
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class RoleUserSummary {
    private Long id;
    private String username;
}
