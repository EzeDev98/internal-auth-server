package com.internal.auth.feature.rbac.service;


import com.internal.auth.common.response.BaseResponse;
import com.internal.auth.feature.rbac.response.GroupCreationResponse;
import com.internal.auth.feature.rbac.response.RoleResponse;
import com.internal.auth.feature.rbac.response.SubGroupCreationResponse;

public interface PermissionEntityService {
    RoleResponse createRole(String roleName, String description, String keycloakId);
    GroupCreationResponse createSuperGroup(String groupName, String description, String groupId);
    SubGroupCreationResponse createSubGroup(String groupName, String description, String parentGroupId, String groupId);
    BaseResponse getPermissionGroupUsersByGroupName(String groupName);
    void deleteSuperGroup(String groupName);
    BaseResponse getSubGroupByName(String parentGroupName, String subGroupName);
    BaseResponse getSubPermissionGroupUsersByGroupName(String superGroupName, String subGroupName);
    BaseResponse retrieveUserGroups(String username);
    BaseResponse retrieveUserRoles(String username);
}