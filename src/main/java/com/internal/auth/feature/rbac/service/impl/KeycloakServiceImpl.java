package com.internal.auth.feature.rbac.service.impl;

import com.internal.auth.feature.rbac.response.*;
import com.internal.auth.feature.rbac.service.KeycloakService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

/**
 * TEMPORARY local-only stand-in for Keycloak.
 *
 * <p>Per the Stage 1 architecture assessment, "Internal Auth will be our
 * own authentication and authorization platform. Keycloak will NOT be
 * used" — and no working KeycloakService implementation existed anywhere
 * in the repo to begin with. Rather than build a real Keycloak Admin REST
 * client for a dependency that's being retired, this implementation treats
 * the local database as authoritative: every "create/assign/remove in
 * Keycloak" call below is a no-op that reports success (with a synthetic
 * id where one is needed downstream), so PermissionManagementServiceImpl /
 * UserServiceImpl fall straight through to their local-persistence step.
 *
 * <p>This makes RBAC admin operations functionally work end-to-end against
 * the local database alone. What it does NOT do is anything Keycloak
 * itself used to be responsible for outside RBAC mirroring (issuing
 * tokens, hosting the login page, enforcing its own password policy) —
 * that's the rest of the Stage 2-5 roadmap.
 *
 * <p>Replace or delete this class once the Keycloak-mirroring control flow
 * in the callers above is redesigned around local-DB-as-source-of-truth
 * directly (see the assessment's "Keycloak Coupling" section) — at that
 * point these methods shouldn't be called at all, not just stubbed.
 */
@Slf4j
@Service
public class KeycloakServiceImpl implements KeycloakService {

    private static String syntheticId() {
        return "local-" + UUID.randomUUID();
    }

    @Override
    public KeycloakRoleCreationResponse createRoleInKeycloak(String roleName, String description) {
        log.debug("Keycloak integration disabled — treating role '{}' as created locally only", roleName);
        return new KeycloakRoleCreationResponse(HttpServletResponse.SC_CREATED, "Role created (local only)", roleName, description, syntheticId());
    }

    @Override
    public boolean deleteRole(String keycloakRoleId) {
        return true;
    }

    @Override
    public KeycloakGroupCreationResponse createSuperGroupInKeycloak(String groupName, String description) {
        log.debug("Keycloak integration disabled — treating group '{}' as created locally only", groupName);
        return new KeycloakGroupCreationResponse(HttpServletResponse.SC_CREATED, "Group created (local only)", groupName, description, syntheticId());
    }

    @Override
    public KeycloakSubGroupCreationResponse createSubGroupInKeycloak(String groupName, String parentGroupId, String description) {
        log.debug("Keycloak integration disabled — treating subgroup '{}' as created locally only", groupName);
        return new KeycloakSubGroupCreationResponse(HttpServletResponse.SC_CREATED, "Subgroup created (local only)", groupName, description, parentGroupId, syntheticId());
    }

    @Override
    public boolean deleteGroup(String keycloakGroupId) {
        return true;
    }

    @Override
    public KeycloakRoleAssignmentResponse assignRoleToUser(String username, String role) {
        return new KeycloakRoleAssignmentResponse("Role assigned (local only)", HttpServletResponse.SC_CREATED, username, role);
    }

    @Override
    public boolean removeRoleFromUser(String username, String role) {
        return true;
    }

    @Override
    public KeycloakGroupRoleAssignmentResponse assignRoleToGroup(String groupName, String roleName) {
        return new KeycloakGroupRoleAssignmentResponse("Role assigned to group (local only)", HttpServletResponse.SC_CREATED, groupName, roleName);
    }

    @Override
    public boolean removeRoleFromGroup(String groupName, String role) {
        return true;
    }

    @Override
    public JoinGroupResponse addUserToGroup(String username, String groupName) {
        return new JoinGroupResponse("User added to group (local only)", HttpServletResponse.SC_CREATED, groupName, username);
    }

    @Override
    public boolean removeUserFromGroup(String username, String groupName) {
        return true;
    }

    @Override
    public boolean removeUserFromSubGroup(String username, String superGroupName, String subGroupName) {
        return true;
    }

    @Override
    public int removeUserFromSubGroups(String username, String superGroupName, List<String> subGroupNames) {
        return subGroupNames.size();
    }

    @Override
    public JoinGroupResponse addUserToSubGroup(String username, String superGroupName, String subGroupName) {
        return new JoinGroupResponse("User added to subgroup (local only)", HttpServletResponse.SC_CREATED, subGroupName, username);
    }

    @Override
    public JoinGroupResponse addUserToSubGroups(String username, String superGroupName, List<String> subGroupNames) {
        return new JoinGroupResponse("User added to subgroups (local only)", HttpServletResponse.SC_CREATED, subGroupNames, username);
    }

    @Override
    public KeycloakGroupRoleAssignmentResponse assignRoleToSubgroup(String parentGroupName, String subgroupName, String roleName) {
        return new KeycloakGroupRoleAssignmentResponse("Role assigned to subgroup (local only)", HttpServletResponse.SC_CREATED, subgroupName, roleName);
    }

    @Override
    public void assignRolesToUser(String username, List<String> roles) {
        // no-op — local persistence of each role happens in the caller
    }

    @Override
    public void deleteUser(String username) {
        // no-op — nothing to delete in an identity provider we no longer call
    }

    @Override
    public BulkGroupAssignmentResponse addUsersToAnyPermissionGroup(List<String> usernames, String groupName) {
        return new BulkGroupAssignmentResponse(HttpServletResponse.SC_CREATED, "Users added to group (local only)", usernames, java.util.Map.of());
    }

    @Override
    public BulkGroupRemovalResponse removeUsersFromGroup(List<String> usernames, String groupName) {
        return new BulkGroupRemovalResponse(usernames.size(), usernames.size(), 0, 0, usernames, List.of(), List.of());
    }

    @Override
    public DefaultPermissionGroupResponse addAllExistingUsersToDefaultPermissionGroup(String groupName) {
        return new DefaultPermissionGroupResponse(HttpServletResponse.SC_CREATED, "Existing users added to default group (local only)", List.of());
    }

    @Override
    public void resetPassword(String keycloakId, String newPassword) {
        log.debug("Keycloak integration disabled — password is updated on the local User record only");
    }
}
