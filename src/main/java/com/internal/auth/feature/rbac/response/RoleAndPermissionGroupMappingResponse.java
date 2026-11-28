package com.internal.auth.feature.rbac.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** A role and the permission group it is mapped to. */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class RoleAndPermissionGroupMappingResponse {

    private Long id;
    private String roleName;
    private String groupName;
}
