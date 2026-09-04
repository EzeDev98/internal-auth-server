package com.internal.auth.feature.rbac.controller;

import com.internal.auth.config.auth.AuthenticationHelper;
import com.internal.auth.config.auth.Roles;
import com.internal.auth.feature.rbac.service.PermissionEntityService;
import com.internal.auth.feature.rbac.service.PermissionManagementService;
import com.internal.auth.common.response.BaseResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping("${app.title}")
@Tag(name = "User Roles And Permissions API", description = "Comprehensive management of roles, groups, and user permissions")
public class PermissionController {

    private final PermissionManagementService permissionService;

    private final PermissionEntityService permissionEntityService;

    private final AuthenticationHelper authenticationHelper;

    /**
     * Stage 1 assessment, "Immediate Next Steps" #3 - the service-to-service
     * role-assignment endpoint below had no allow-list at all: any caller
     * holding the "service" authority could grant ANY role, including an
     * admin-tier one, to any user. Fail-closed by default: unless an
     * operator explicitly lists which roles service credentials may assign,
     * none are permitted (the admin-only /roles/assign/user endpoint is
     * unaffected - it can still assign any role, as intended).
     */
    private final Set<String> serviceAssignableRoles;

    public PermissionController(PermissionManagementService permissionService,
                                 PermissionEntityService permissionEntityService,
                                 AuthenticationHelper authenticationHelper,
                                 @Value("${app.service-role-assignment.allowed-roles:}") String serviceAssignableRolesRaw) {
        this.permissionService = permissionService;
        this.permissionEntityService = permissionEntityService;
        this.authenticationHelper = authenticationHelper;
        this.serviceAssignableRoles = parseAllowedRoles(serviceAssignableRolesRaw);
    }

    private static Set<String> parseAllowedRoles(String raw) {
        if (raw == null || raw.isBlank()) {
            return Collections.emptySet();
        }
        return Arrays.stream(raw.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .map(s -> s.toLowerCase(Locale.ROOT))
                .collect(Collectors.toUnmodifiableSet());
    }

    @PreAuthorize(Roles.HAS_ADMIN)
    @Operation(summary = "Create a new role", description = "Creates a role in the local database. Roles define permissions that can be assigned to users or groups.")
    @PostMapping("/roles/create")
    public ResponseEntity<?> createRole(
            @Parameter(description = "Name of the role to create", required = true, example = "ROLE_ADMIN")
            @RequestParam String roleName,

            @Parameter(description = "Description of the role's purpose", example = "Administrator with full access")
            @RequestParam String description) {
        BaseResponse roleResponse = permissionService.createRole(roleName, description);
        return ResponseEntity.ok(roleResponse);
    }

    @PreAuthorize(Roles.HAS_ADMIN_OR_SERVICE)
    @Operation(summary = "Create a parent group", description = "Creates a top-level group in the database. Parent groups can contain subgroups and users.")
    @PostMapping("/groups/create/super")
    public ResponseEntity<?> createSuperGroup(
            @Parameter(description = "Name of the parent group", required = true, example = "FOOD_SELLERS")
            @RequestParam String groupName,

            @Parameter(description = "Description of the group's purpose", example = "Food seller's group")
            @RequestParam String description) {
        BaseResponse groupResponse = permissionService.createSuperGroup(groupName, description);
        return ResponseEntity.ok(groupResponse);
    }

    @PreAuthorize(Roles.HAS_ADMIN_OR_SERVICE)
    @Operation(summary = "Create a subgroup", description = "Creates a child group under a specified, already-existing parent group.")
    @PostMapping("/groups/create/sub")
    public ResponseEntity<?> createSubGroup(

            @Parameter(description = "Name of the subgroup", required = true, example = "FOOD_SELLERS")
            @RequestParam String groupName,

            @Parameter(description = "Description of the subgroup", example = "This group will contain specific type of sellers")
            @RequestParam String description,

            @Parameter(description = "Name of the existing parent group", required = true, example = "SELLERS_GROUP")
            @RequestParam String parentGroupName) {
        BaseResponse groupResponse = permissionService.createSubGroup(groupName, description, parentGroupName);
        return ResponseEntity.ok(groupResponse);
    }

    @PreAuthorize(Roles.HAS_SERVICE)
    @Operation(summary = "Assign role to user automatically", description = "Grants a specific role to a user and records the assignment in the local database automatically. For automatic service-to-service usage. Restricted to the roles configured in app.service-role-assignment.allowed-roles.")
    @PostMapping("/service/roles/assign/user")
    public ResponseEntity<?> assignRoleToUserForServiceToService(
            @Parameter(description = "Username to assign role to", required = true, example = "Sarah")
            @RequestParam String username,

            @Parameter(description = "Role name to assign", required = true, example = "ADMIN")
            @RequestParam String role) {
        if (!serviceAssignableRoles.contains(role.trim().toLowerCase(Locale.ROOT))) {
            throw new AccessDeniedException("Service credentials are not permitted to assign role '" + role + "'. " + "Configure app.service-role-assignment.allowed-roles to permit specific roles.");
        }
        BaseResponse roleResponse = permissionService.assignRoleToUser(username, role);
        return ResponseEntity.ok(roleResponse);
    }

    @PreAuthorize(Roles.HAS_ADMIN)
    @Operation(summary = "Assign role to user", description = "Grants a specific role to a user and records the assignment in the local database.")
    @PostMapping("/roles/assign/user")
    public ResponseEntity<?> assignRoleToUser(
            @Parameter(description = "Username to assign role to", required = true, example = "Sarah")
            @RequestParam String username,

            @Parameter(description = "Role name to assign", required = true, example = "ADMIN")
            @RequestParam String role) {
        BaseResponse roleResponse = permissionService.assignRoleToUser(username, role);
        return ResponseEntity.ok(roleResponse);
    }

    @PreAuthorize(Roles.HAS_ADMIN)
    @Operation(summary = "Assign role to parent group", description = "Assigns a role to all members of a parent group. All users in the group inherit the role.")
    @PostMapping("/roles/assign/super-group")
    public ResponseEntity<?> assignRoleToGroup(
            @Parameter(description = "Name of the parent group", required = true, example = "SELLER'S_GROUP")
            @RequestParam String groupName,

            @Parameter(description = "Role name to assign", required = true, example = "SERVICE_PROVIDER")
            @RequestParam String role) {
        BaseResponse roleResponse = permissionService.assignRoleToGroup(groupName, role);
        return ResponseEntity.ok(roleResponse);
    }

    @PreAuthorize(Roles.HAS_ADMIN)
    @Operation(summary = "Assign role to subgroup", description = "Assigns a role to a specific subgroup within a parent group hierarchy.")
    @PostMapping("/roles/assign/sub-group")
    public ResponseEntity<?> assignRoleToSubGroup(
            @Parameter(description = "Name of the parent group", required = true, example = "SELLER'S_GROUP")
            @RequestParam String superGroup,

            @Parameter(description = "Name of the subgroup", required = true, example = "FOOD_SELLERS")
            @RequestParam String subGroup,

            @Parameter(description = "Role name to assign", required = true, example = "SERVICE_PROVIDER")
            @RequestParam String role) {
        BaseResponse roleResponse = permissionService.assignRoleToSubGroup(superGroup, subGroup, role);
        return ResponseEntity.ok(roleResponse);
    }

    @PreAuthorize(Roles.HAS_ADMIN_OR_SERVICE)
    @Operation(summary = "Add user to parent group", description = "Adds a user directly to a parent group, granting them all roles assigned to that group.")
    @PostMapping("/users/add/super-group")
    public ResponseEntity<?> addUsersToParentGroup(
            @Parameter(description = "Username to add", required = true, example = "Sarah")
            @RequestParam String username,

            @Parameter(description = "Name of the parent group", required = true, example = "SELLER'S_GROUP")
            @RequestParam String groupName) {
        BaseResponse response = permissionService.addUserToParentGroup(username, groupName);
        return ResponseEntity.ok(response);
    }

    @PreAuthorize(Roles.HAS_ADMIN_OR_SERVICE)
    @Operation(summary = "Add user to subgroup", description = "Adds a user to a specific subgroup within a parent group hierarchy.")
    @PostMapping("/users/add/sub-group")
    public ResponseEntity<?> addUsersToSubGroup(
            @Parameter(description = "Username to add", required = true, example = "Sarah")
            @RequestParam String username,

            @Parameter(description = "Name of the parent group", required = true, example = "SELLER'S_GROUP")
            @RequestParam String superGroupName,

            @Parameter(description = "Name of the subgroup", required = true, example = "FOOD_SELLERS")
            @RequestParam String subGroupName) {
        BaseResponse response = permissionService.addUserToSubGroup(username, superGroupName, subGroupName);
        return ResponseEntity.ok(response);
    }

    @PreAuthorize(Roles.HAS_ADMIN)
    @Operation(summary = "Add user to multiple subgroups", description = "Adds a user to several subgroups within the same parent group in a single operation.")
    @PostMapping("/users/add/sub-groups")
    public ResponseEntity<?> addUsersToSubGroups(
            @Parameter(description = "Username to add", required = true, example = "sarah")
            @RequestParam String username,

            @Parameter(description = "Name of the parent group", required = true, example = "SELLER'S_GROUP")
            @RequestParam String superGroupName,

            @Parameter(description = "List of subgroup names", required = true, example = "[\"FOOD_SELLERS\", \"CLOTHE_SELLERS\"]")
            @RequestParam List<String> subGroupNames) {
        BaseResponse response = permissionService.addUserToSubGroups(username, superGroupName, subGroupNames);
        return ResponseEntity.ok(response);
    }

    @PreAuthorize(Roles.HAS_ADMIN)
    @Operation(summary = "Unassigns a role to a user", description = "Removes the role that has been assigned to a user in the local database.")
    @PostMapping("/users/remove/role")
    public ResponseEntity<?> unassignRole(@RequestParam String username, @RequestParam String roleName) {
        BaseResponse response = permissionService.unassignRole(username, roleName);
        return ResponseEntity.ok(response);
    }

    @PreAuthorize(Roles.HAS_ADMIN)
    @Operation(summary = "Removes a user from a permission group", description = "Removes a user from a permission in the local database.")
    @PostMapping("/users/remove/group")
    public ResponseEntity<?> removeUserFromGroup(@RequestParam String username, @RequestParam String groupName) {
        BaseResponse response = permissionService.removeUserFromGroup(username, groupName);
        return ResponseEntity.ok(response);
    }

    @PreAuthorize(Roles.HAS_ADMIN)
    @Operation(summary = "Delete a parent permission group", description = "Deletes a parent permission group in the local database.")
    @DeleteMapping("/delete/group/parent")
    public ResponseEntity<?> deleteParentGroup(@RequestParam String groupName) {
        BaseResponse response = permissionService.deleteSuperGroup(groupName);
        return ResponseEntity.ok(response);
    }

    @PreAuthorize(Roles.HAS_SERVICE)
    @Operation(summary = "Fetch a permission group", description = "Fetches a permission group from the local database using the group name as a parameter.")
    @GetMapping("/group/by-name")
    public ResponseEntity<?> fetchPermissionGroupByName(@RequestParam String groupName) {
        BaseResponse response = permissionEntityService.getPermissionGroupUsersByGroupName(groupName);
        return ResponseEntity.ok(response);
    }

    @PreAuthorize(Roles.HAS_SERVICE)
    @Operation(summary = "Fetch a sub permission group", description = "Fetches a sub permission group from the local database using the sub group name as a parameter.")
    @GetMapping("/subgroup/by-name")
    public ResponseEntity<?> fetchSubPermissionGroupByName(@RequestParam String parentGroupName, @RequestParam String subGroupName) {
        BaseResponse response = permissionEntityService.getSubGroupByName(parentGroupName, subGroupName);
        return ResponseEntity.ok(response);
    }

    @PreAuthorize(Roles.HAS_SERVICE)
    @Operation(summary = "Fetch all the users in a specific sub permission group", description = "Fetches all users in a sub permission group from the local database using the super group name and the sub group name as a parameter.")
    @GetMapping("/subgroup/users/by-name")
    public ResponseEntity<?> fetchSubPermissionGroupUsersByName(@RequestParam String parentGroupName, @RequestParam String subGroupName) {
        BaseResponse response = permissionEntityService.getSubPermissionGroupUsersByGroupName(parentGroupName, subGroupName);
        return ResponseEntity.ok(response);
    }

    @PreAuthorize(Roles.HAS_SERVICE)
    @Operation(summary = "Add user to a specific permission group", description = "Adds a user to any permission group using the group name and the username as a parameter.")
    @PostMapping("/groups/users/by-name")
    public ResponseEntity<?> addUserToAnyGroup(@RequestParam String username, @RequestParam String groupName) {
        BaseResponse response = permissionService.addUserToSpecificPermissionGroup(username, groupName);
        return ResponseEntity.ok(response);
    }

    @PreAuthorize(Roles.HAS_ADMIN_OR_USER)
    @Operation(summary = "Fetch all user permission groups", description = "Fetches all the permission groups a user belongs to from the local database using the user's username as a parameter. Callers without the admin role may only fetch their own.")
    @GetMapping("/groups/users/{username}")
    public ResponseEntity<?> fetchUserPermissionGroups(@PathVariable String username) {
        authenticationHelper.requireSelfOrAdmin(username);
        BaseResponse response = permissionEntityService.retrieveUserGroups(username);
        return ResponseEntity.ok(response);
    }

    @PreAuthorize(Roles.HAS_ADMIN)
    @Operation(summary = "Fetch all user roles", description = "Fetches all the roles a user belongs to from the local database using the user's username as a parameter.")
    @GetMapping("/roles/users/{username}")
    public ResponseEntity<?> fetchUserRoles(@PathVariable String username) {
        BaseResponse response = permissionEntityService.retrieveUserRoles(username);
        return ResponseEntity.ok(response);
    }

    @PreAuthorize(Roles.HAS_ADMIN)
    @Operation(summary = "Add users to a specific permission group", description = "Adds a list of users to any permission group using the group name and a list of usernames as a parameter.")
    @PostMapping("/groups/users/by-names")
    public ResponseEntity<?> addUsersToAnyGroup(@RequestParam List<String> usernames, @RequestParam String groupName) {
        BaseResponse response = permissionService.addUsersToAnyGroup(usernames, groupName);
        return ResponseEntity.ok(response);
    }
}
