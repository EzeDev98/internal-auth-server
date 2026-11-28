package com.internal.auth.feature.rbac.service;


import com.internal.auth.feature.rbac.response.RoleAndPermissionGroupMappingResponse;

/** Operations for assigning roles to groups. */
public interface GroupRoleService {
    RoleAndPermissionGroupMappingResponse assignRoleToGroup(String groupName, String roleName);
    RoleAndPermissionGroupMappingResponse assignRoleToSubGroup(String groupName, String roleName);
}
