package com.internal.auth.feature.rbac.service;

import com.internal.auth.feature.rbac.response.BulkRoleAssignmentResponse;
import com.internal.auth.feature.rbac.response.RemoveRoleResponse;
import com.internal.auth.feature.rbac.response.UserRoleResponse;

import java.util.List;

/** Operations for managing users' roles. */
public interface UserRoleService {
    void assignRoles(String username, List<String> roles);
    UserRoleResponse assignRole(String username, String role);
    RemoveRoleResponse unassignRole(String username, String roleName);
    void removeAllRoleForUser(String username);
    BulkRoleAssignmentResponse bulkRoleAssignment(List<String> usernames, List<String> roles);
}
