package com.internal.auth.feature.rbac.service;

import com.internal.auth.common.response.BaseResponse;

import java.util.List;

public interface PermissionManagementService {
    BaseResponse createRole(String name, String description);
    BaseResponse createSuperGroup(String groupName, String description);
    BaseResponse createSubGroup(String groupName, String description, String parentGroupName);
    BaseResponse assignRoleToUser(String username, String role);
    BaseResponse assignRoleToGroup(String groupName, String role);
    BaseResponse addUserToGroup(String username, String groupName);
    BaseResponse addUserToSubGroup(String username, String superGroupName, String subGroupName);
    BaseResponse addUserToSubGroups(String username, String superGroupName, List<String> subGroupName);
    BaseResponse assignRoleToSubGroup(String superGroupName, String groupName, String role);
    BaseResponse unassignRole(String username, String roleName);
    BaseResponse removeUserFromGroup(String username, String groupName);
    BaseResponse deleteSuperGroup(String groupName);
    BaseResponse deleteSubGroup(String parentGroupName, String subGroupName);
}