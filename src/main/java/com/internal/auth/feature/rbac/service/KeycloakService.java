package com.internal.auth.feature.rbac.service;

import com.internal.auth.feature.rbac.response.*;

import java.util.List;

public interface KeycloakService {
    KeycloakRoleCreationResponse createRoleInKeycloak(String roleName, String description);
    boolean deleteRole(String keycloakRoleId);
    KeycloakGroupCreationResponse createSuperGroupInKeycloak(String groupName, String description);
    KeycloakSubGroupCreationResponse createSubGroupInKeycloak(String groupName, String parentGroupId, String description);
    boolean deleteGroup(String keycloakGroupId);
    KeycloakRoleAssignmentResponse assignRoleToUser(String username, String role);
    boolean removeRoleFromUser(String username, String role);
    KeycloakGroupRoleAssignmentResponse assignRoleToGroup(String groupName, String roleName);
    boolean removeRoleFromGroup(String groupName, String role);
    JoinGroupResponse addUserToGroup(String username, String groupName);
    boolean removeUserFromGroup(String username, String groupName);
    boolean removeUserFromSubGroup(String username, String superGroupName, String subGroupName);
    int removeUserFromSubGroups(String username, String superGroupName, List<String> subGroupNames);
    JoinGroupResponse addUserToSubGroup(String username, String superGroupName, String subGroupName);
    JoinGroupResponse addUserToSubGroups(String username, String superGroupName, List<String> subGroupName);
    KeycloakGroupRoleAssignmentResponse assignRoleToSubgroup(String parentGroupName, String subgroupName, String roleName);
    void assignRolesToUser(String username, List<String> roles);
    void deleteUser(String username);
    BulkGroupAssignmentResponse addUsersToAnyPermissionGroup(List<String> usernames, String groupName);
    BulkGroupRemovalResponse removeUsersFromGroup(List<String> usernames, String groupName);
    DefaultPermissionGroupResponse addAllExistingUsersToDefaultPermissionGroup(String groupName);
    void resetPassword(String keycloakId, String newPassword);
}
