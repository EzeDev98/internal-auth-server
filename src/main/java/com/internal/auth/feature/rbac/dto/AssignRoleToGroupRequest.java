package com.internal.auth.feature.rbac.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Request body for assigning a role to a group. */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class AssignRoleToGroupRequest {
    private String roleName;
}
