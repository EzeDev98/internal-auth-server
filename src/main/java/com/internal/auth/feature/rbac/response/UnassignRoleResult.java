package com.internal.auth.feature.rbac.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Result of unassigning a role. */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class UnassignRoleResult {
    private String username;
    private String roleName;
}
