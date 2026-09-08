package com.internal.auth.feature.rbac.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Fine-grained-permission row for GET ${app.title}/roles/{id} (Step 2C,
 * React Admin Client plan v4) - see RoleQueryServiceImpl's Javadoc for why
 * this is currently always an empty list for every role.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class RolePermissionSummary {
    private Long id;
    private String permissionName;
    private String description;
}
