package com.internal.auth.feature.rbac.service;

import com.internal.auth.feature.rbac.response.RemoveUserResponse;
import com.internal.auth.feature.rbac.response.UserPermissionGroupResponse;
import com.internal.auth.feature.rbac.response.UserSubPermissionGroupResponse;

import java.util.List;

/** Operations for managing users' group memberships. */
public interface UserPermissionGroupService {
    RemoveUserResponse removeUserFromPermissionGroup(String username, String groupName);
    UserPermissionGroupResponse addUserToGroup(String username, String groupName);
    UserSubPermissionGroupResponse addUserToSubGroup(String username, String groupName, String subGroupName);
    List<UserPermissionGroupResponse> addUserToSubGroups(String username, String groupName, List<String> subGroupNames);
}
