package com.internal.auth.feature.rbac.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Request body for assigning a role to a sub-group. */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class AssignRoleToSubGroupRequest {
    private String roleName;
}
