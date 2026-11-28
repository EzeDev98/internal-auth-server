package com.internal.auth.feature.rbac.service;


import com.internal.auth.common.response.BaseResponse;
import com.internal.auth.feature.rbac.response.GroupCreationResponse;
import com.internal.auth.feature.rbac.response.RoleResponse;
import com.internal.auth.feature.rbac.response.SubGroupCreationResponse;

/** Operations for creating and managing roles and groups. */
public interface PermissionEntityService {
    RoleResponse createRole(String roleName, String description);
    GroupCreationResponse createSuperGroup(String groupName, String description);
    SubGroupCreationResponse createSubGroup(String groupName, String description, String parentGroupName);
    BaseResponse getPermissionGroupUsersByGroupName(String groupName);
    void deleteSuperGroup(String groupName);
    void deleteSubGroup(String parentGroupName, String subGroupName);
    SubGroupCreationResponse renameSubGroup(String parentGroupName, String subGroupName, String newGroupName);
    SubGroupCreationResponse moveSubGroup(String parentGroupName, String subGroupName, String newParentGroupName);
    BaseResponse getSubGroupByName(String parentGroupName, String subGroupName);
    BaseResponse getSubPermissionGroupUsersByGroupName(String superGroupName, String subGroupName);
    BaseResponse retrieveUserGroups(String username);
    BaseResponse retrieveUserRoles(String username);
}
