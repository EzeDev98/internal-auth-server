package com.internal.auth.feature.rbac.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Pairing of a group name and a role name. */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class GroupRoleMapping {
    private String groupName;
    private String roleName;
}
