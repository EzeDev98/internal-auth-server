package com.internal.auth.feature.rbac.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.List;

/** Detail view of a single role. */
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
