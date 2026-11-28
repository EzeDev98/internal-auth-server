package com.internal.auth.feature.rbac.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** User row shown on a role's detail view. */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class RoleUserSummary {
    private Long id;
    private String username;
    private String email;
}
