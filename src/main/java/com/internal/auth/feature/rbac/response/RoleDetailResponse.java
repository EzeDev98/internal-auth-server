package com.internal.auth.feature.rbac.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Single-role detail shape for GET ${app.title}/roles/{id} (Step 2C,
 * React Admin Client plan v4) - see RoleQueryServiceImpl's Javadoc for
 * why permissions/permissionGroups/usersInRole are three separate lists
 * rather than one.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class RoleDetailResponse {
    private Long id;
    private String roleName;
    private String description;
    private Long clientApplicationId;
    private LocalDateTime createdAt;
    private List<RolePermissionSummary> permissions;
    private List<String> permissionGroups;
    private List<RoleUserSummary> usersInRole;
}
