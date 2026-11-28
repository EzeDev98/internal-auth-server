package com.internal.auth.feature.rbac.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Permission row shown on a role's detail view. */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class RolePermissionSummary {
    private Long id;
    private String permissionName;
    private String description;
}
