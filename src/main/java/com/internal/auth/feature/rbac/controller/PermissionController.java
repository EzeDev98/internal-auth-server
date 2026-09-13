package com.internal.auth.feature.rbac.controller;

import com.internal.auth.common.security.AuthenticationHelper;
import com.internal.auth.config.auth.Roles;
import com.internal.auth.feature.rbac.response.RoleResponse;
import com.internal.auth.feature.rbac.response.GroupCreationResponse;
import com.internal.auth.feature.rbac.response.SubGroupCreationResponse;
import com.internal.auth.feature.rbac.response.UserRoleResponse;
import com.internal.auth.feature.rbac.response.RoleAndPermissionGroupMappingResponse;
import com.internal.auth.feature.rbac.response.GroupSummaryResponse;
import com.internal.auth.feature.rbac.response.SubGroupSummaryResponse;
import com.internal.auth.feature.rbac.service.GroupQueryService;
import com.internal.auth.feature.rbac.response.RoleDetailResponse;
import com.internal.auth.feature.rbac.response.RoleSummaryResponse;
import com.internal.auth.feature.rbac.response.UserPermissionGroupResponse;
import com.internal.auth.feature.rbac.response.UserSubPermissionGroupResponse;
import com.internal.auth.feature.rbac.response.GroupResponse;
import com.internal.auth.feature.rbac.response.SubGroupResponse;
import com.internal.auth.feature.rbac.response.PermissionGroupResponse;
import com.internal.auth.feature.rbac.response.UnassignRoleResult;
import com.internal.auth.feature.rbac.response.RemoveUserFromGroupResult;
import com.internal.auth.feature.rbac.model.SubPermissionGroup;
import com.internal.auth.feature.rbac.service.PermissionEntityService;
import com.internal.auth.feature.rbac.service.PermissionManagementService;
import com.internal.auth.feature.rbac.service.RoleQueryService;
import com.internal.auth.common.response.BaseResponse;
import com.internal.auth.feature.rbac.dto.*;
import com.internal.auth.common.response.InternalAuthApiResponse;
import io.swagger.v3.oas.annotations.Operation;
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

    private final GroupQueryService groupQueryService;

    private final RoleQueryService roleQueryService;

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
                                 GroupQueryService groupQueryService,
                                 RoleQueryService roleQueryService,
                                 @Value("${app.service-role-assignment.allowed-roles:}") String serviceAssignableRolesRaw) {
        this.permissionService = permissionService;
        this.permissionEntityService = permissionEntityService;
        this.authenticationHelper = authenticationHelper;
        this.groupQueryService = groupQueryService;
        this.roleQueryService = roleQueryService;
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

    /**
     * Step 2F (React Admin Client plan v4), scoped to the create/assign
     * endpoints only. permissionService.createRole still returns
     * BaseResponse internally, unchanged - PermissionManagementService's
     * interface and every test exercising it are untouched by this pass.
     * PermissionEntityServiceImpl always sets this call's data to the
     * RoleResponse it just built, so the cast below is safe, not a guess.
     */
    @PreAuthorize(Roles.HAS_ADMIN)
    @Operation(summary = "Create a new role", description = "Creates a role in the local database. Roles define permissions that can be assigned to users or groups.")
    @PostMapping("/roles")
    public ResponseEntity<InternalAuthApiResponse<RoleResponse>> createRole(@RequestBody RolesRequest request) {
        BaseResponse roleResponse = permissionService.createRole(request.getRoleName(), request.getDescription());
        return ResponseEntity.status(roleResponse.getStatusCode())
                .body(InternalAuthApiResponse.success(roleResponse.getDescription(), (RoleResponse) roleResponse.getData()));
    }

    /** Step 2F, same rationale as createRole above. */
    @PreAuthorize(Roles.HAS_ADMIN)
    @Operation(summary = "Create a parent group", description = "Creates a top-level group in the database. Parent groups can contain subgroups and users.")
    @PostMapping("/groups")
    public ResponseEntity<InternalAuthApiResponse<GroupCreationResponse>> createSuperGroup(@RequestBody GroupRequest request) {
        BaseResponse groupResponse = permissionService.createSuperGroup(request.getGroupName(), request.getDescription());
        return ResponseEntity.status(groupResponse.getStatusCode())
                .body(InternalAuthApiResponse.success(groupResponse.getDescription(), (GroupCreationResponse) groupResponse.getData()));
    }

    /** Step 2F, same rationale as createRole above. */
    @PreAuthorize(Roles.HAS_ADMIN)
    @Operation(summary = "Create a subgroup", description = "Creates a child group under a specified, already-existing parent group.")
    @PostMapping("/groups/{parentGroupName}/subgroups")
    public ResponseEntity<InternalAuthApiResponse<SubGroupCreationResponse>> createSubGroup(@PathVariable String parentGroupName, @RequestBody SubGroupRequest request) {
        BaseResponse groupResponse = permissionService.createSubGroup(request.getGroupName(), request.getDescription(), parentGroupName);
        return ResponseEntity.status(groupResponse.getStatusCode())
                .body(InternalAuthApiResponse.success(groupResponse.getDescription(), (SubGroupCreationResponse) groupResponse.getData()));
    }

    @PreAuthorize(Roles.HAS_ADMIN)
    @Operation(summary = "Assign role to user automatically", description = "Grants a specific role to a user and records the assignment in the local database automatically. For automatic service-to-service usage. Restricted to the roles configured in app.service-role-assignment.allowed-roles.")
    @PostMapping("/service/users/{username}/roles")
    public ResponseEntity<InternalAuthApiResponse<UserRoleResponse>> assignRoleToUserForServiceToService(@PathVariable String username, @RequestBody AssignRoleRequest request) {
        if (!serviceAssignableRoles.contains(request.getRoleName().trim().toLowerCase(Locale.ROOT))) {
            throw new AccessDeniedException("Service credentials are not permitted to assign role '" + request.getRoleName() + "'. " + "Configure app.service-role-assignment.allowed-roles to permit specific roles.");
        }
        BaseResponse roleResponse = permissionService.assignRoleToUser(username, request.getRoleName());
        return ResponseEntity.status(roleResponse.getStatusCode())
                .body(InternalAuthApiResponse.success(roleResponse.getDescription(), (UserRoleResponse) roleResponse.getData()));
    }

    /** Step 2F, same rationale as createRole above. */
    @PreAuthorize(Roles.HAS_ADMIN)
    @Operation(summary = "Assign role to user", description = "Grants a specific role to a user and records the assignment in the local database.")
    @PostMapping("/users/{username}/roles")
    public ResponseEntity<InternalAuthApiResponse<UserRoleResponse>> assignRoleToUser(@PathVariable String username, @RequestBody AssignRoleRequest request) {
        BaseResponse roleResponse = permissionService.assignRoleToUser(username, request.getRoleName());
        return ResponseEntity.status(roleResponse.getStatusCode())
                .body(InternalAuthApiResponse.success(roleResponse.getDescription(), (UserRoleResponse) roleResponse.getData()));
    }

    /**
     * Step 2F, same rationale as createRole above. Note the idempotent
     * "already assigned" branch in PermissionManagementServiceImpl sets
     * data to null - casting null is safe, so this stays typed either way.
     */
    @PreAuthorize(Roles.HAS_ADMIN)
    @Operation(summary = "Assign role to parent group", description = "Assigns a role to all members of a parent group. All users in the group inherit the role.")
    @PostMapping("/groups/{groupName}/roles")
    public ResponseEntity<InternalAuthApiResponse<RoleAndPermissionGroupMappingResponse>> assignRoleToGroup(@PathVariable String groupName, @RequestBody AssignRoleToGroupRequest request) {
        BaseResponse roleResponse = permissionService.assignRoleToGroup(groupName, request.getRoleName());
        return ResponseEntity.status(roleResponse.getStatusCode())
                .body(InternalAuthApiResponse.success(roleResponse.getDescription(), (RoleAndPermissionGroupMappingResponse) roleResponse.getData()));
    }

    /** Step 2F, same rationale as createRole above. */
    @PreAuthorize(Roles.HAS_ADMIN)
    @Operation(summary = "Assign role to subgroup", description = "Assigns a role to a specific subgroup within a parent group hierarchy.")
    @PostMapping("/groups/{parentGroupName}/subgroups/{subGroupName}/roles")
    public ResponseEntity<InternalAuthApiResponse<RoleAndPermissionGroupMappingResponse>> assignRoleToSubGroup(@PathVariable String parentGroupName, @PathVariable String subGroupName, @RequestBody AssignRoleToSubGroupRequest request) {
        BaseResponse roleResponse = permissionService.assignRoleToSubGroup(parentGroupName, subGroupName, request.getRoleName());
        return ResponseEntity.status(roleResponse.getStatusCode())
                .body(InternalAuthApiResponse.success(roleResponse.getDescription(), (RoleAndPermissionGroupMappingResponse) roleResponse.getData()));
    }

    @PreAuthorize(Roles.HAS_ADMIN)
    @Operation(summary = "Add user to parent group", description = "Adds a user directly to a parent group, granting them all roles assigned to that group.")
    @PostMapping("/groups/{groupName}/users")
    public ResponseEntity<InternalAuthApiResponse<UserPermissionGroupResponse>> addUsersToGroup(@PathVariable String groupName, @RequestBody AddUserToGroupRequest request) {
        BaseResponse response = permissionService.addUserToGroup(request.getUsername(), groupName);
        return ResponseEntity.status(response.getStatusCode())
                .body(InternalAuthApiResponse.success(response.getDescription(), (UserPermissionGroupResponse) response.getData()));
    }

    @PreAuthorize(Roles.HAS_ADMIN)
    @Operation(summary = "Add user to subgroup", description = "Adds a user to a specific subgroup within a parent group hierarchy.")
    @PostMapping("/groups/{parentGroupName}/subgroups/{subGroupName}/users")
    public ResponseEntity<InternalAuthApiResponse<UserSubPermissionGroupResponse>> addUsersToSubGroup(@PathVariable String parentGroupName, @PathVariable String subGroupName, @RequestBody AddUserToSubGroupRequest request) {
        BaseResponse response = permissionService.addUserToSubGroup(request.getUsername(), parentGroupName, subGroupName);
        return ResponseEntity.status(response.getStatusCode())
                .body(InternalAuthApiResponse.success(response.getDescription(), (UserSubPermissionGroupResponse) response.getData()));
    }

    @PreAuthorize(Roles.HAS_ADMIN)
    @Operation(summary = "Add user to multiple subgroups", description = "Adds a user to several subgroups within the same parent group in a single operation.")
    @PostMapping("/groups/{parentGroupName}/users/{username}/subgroups")
    @SuppressWarnings("unchecked")
    public ResponseEntity<InternalAuthApiResponse<List<UserPermissionGroupResponse>>> addUsersToSubGroups(@PathVariable String parentGroupName, @PathVariable String username, @RequestBody AddUserToSubGroupsRequest request) {
        BaseResponse response = permissionService.addUserToSubGroups(username, parentGroupName, request.getSubGroupNames());
        return ResponseEntity.status(response.getStatusCode())
                .body(InternalAuthApiResponse.success(response.getDescription(), (List<UserPermissionGroupResponse>) response.getData()));
    }

    @PreAuthorize(Roles.HAS_ADMIN)
    @Operation(summary = "Unassigns a role to a user", description = "Removes the role that has been assigned to a user in the local database.")
    @DeleteMapping("/users/{username}/roles/{roleName}")
    public ResponseEntity<InternalAuthApiResponse<UnassignRoleResult>> unassignRole(@PathVariable String username, @PathVariable String roleName) {
        BaseResponse response = permissionService.unassignRole(username, roleName);
        return ResponseEntity.status(response.getStatusCode())
                .body(InternalAuthApiResponse.success(response.getDescription(), (UnassignRoleResult) response.getData()));
    }

    @PreAuthorize(Roles.HAS_ADMIN)
    @Operation(summary = "Removes a user from a permission group", description = "Removes a user from a permission in the local database.")
    @DeleteMapping("/groups/{groupName}/users/{username}")
    public ResponseEntity<InternalAuthApiResponse<RemoveUserFromGroupResult>> removeUserFromGroup(@PathVariable String groupName, @PathVariable String username) {
        BaseResponse response = permissionService.removeUserFromGroup(username, groupName);
        return ResponseEntity.status(response.getStatusCode())
                .body(InternalAuthApiResponse.success(response.getDescription(), (RemoveUserFromGroupResult) response.getData()));
    }

    @PreAuthorize(Roles.HAS_ADMIN)
    @Operation(summary = "Delete a parent permission group", description = "Deletes a parent permission group in the local database.")
    @DeleteMapping("/groups/{groupName}")
    public ResponseEntity<InternalAuthApiResponse<Void>> deleteParentGroup(@PathVariable String groupName) {
        BaseResponse response = permissionService.deleteSuperGroup(groupName);
        return ResponseEntity.status(response.getStatusCode())
                .body(InternalAuthApiResponse.success(response.getDescription(), (Void) response.getData()));
    }

    @PreAuthorize(Roles.HAS_ADMIN)
    @Operation(summary = "Fetch a permission group", description = "Fetches a permission group from the local database using the group name as a parameter.")
    @GetMapping("/groups/{groupName}")
    public ResponseEntity<InternalAuthApiResponse<GroupResponse>> fetchPermissionGroupByName(@PathVariable String groupName) {
        BaseResponse response = permissionEntityService.getPermissionGroupUsersByGroupName(groupName);
        return ResponseEntity.status(response.getStatusCode())
                .body(InternalAuthApiResponse.success(response.getDescription(), (GroupResponse) response.getData()));
    }

    @PreAuthorize(Roles.HAS_ADMIN)
    @Operation(summary = "Fetch a sub permission group", description = "Fetches a sub permission group from the local database using the sub group name as a parameter.")
    @GetMapping("/groups/{parentGroupName}/subgroups/{subGroupName}")
    public ResponseEntity<InternalAuthApiResponse<SubPermissionGroup>> fetchSubPermissionGroupByName(@PathVariable String parentGroupName, @PathVariable String subGroupName) {
        BaseResponse response = permissionEntityService.getSubGroupByName(parentGroupName, subGroupName);
        return ResponseEntity.status(response.getStatusCode())
                .body(InternalAuthApiResponse.success(response.getDescription(), (SubPermissionGroup) response.getData()));
    }

    @PreAuthorize(Roles.HAS_ADMIN)
    @Operation(summary = "Fetch all the users in a specific sub permission group", description = "Fetches all users in a sub permission group from the local database using the super group name and the sub group name as a parameter.")
    @GetMapping("/groups/{parentGroupName}/subgroups/{subGroupName}/users")
    public ResponseEntity<InternalAuthApiResponse<SubGroupResponse>> fetchSubPermissionGroupUsersByName(@PathVariable String parentGroupName, @PathVariable String subGroupName) {
        BaseResponse response = permissionEntityService.getSubPermissionGroupUsersByGroupName(parentGroupName, subGroupName);
        return ResponseEntity.status(response.getStatusCode())
                .body(InternalAuthApiResponse.success(response.getDescription(), (SubGroupResponse) response.getData()));
    }

    @PreAuthorize(Roles.HAS_ADMIN_OR_USER)
    @Operation(summary = "Fetch all user permission groups", description = "Fetches all the permission groups a user belongs to from the local database using the user's username as a parameter. Callers without the admin role may only fetch their own.")
    @GetMapping("/users/{username}/permission-groups")
    @SuppressWarnings("unchecked")
    public ResponseEntity<InternalAuthApiResponse<List<PermissionGroupResponse>>> fetchUserPermissionGroups(@PathVariable String username) {
        authenticationHelper.requireSelfOrAdmin(username);
        BaseResponse response = permissionEntityService.retrieveUserGroups(username);
        return ResponseEntity.status(response.getStatusCode())
                .body(InternalAuthApiResponse.success(response.getDescription(), (List<PermissionGroupResponse>) response.getData()));
    }

    @PreAuthorize(Roles.HAS_ADMIN)
    @Operation(summary = "Fetch all user roles", description = "Fetches all the roles a user belongs to from the local database using the user's username as a parameter.")
    @GetMapping("/users/{username}/roles")
    @SuppressWarnings("unchecked")
    public ResponseEntity<InternalAuthApiResponse<List<RoleResponse>>> fetchUserRoles(@PathVariable String username) {
        BaseResponse response = permissionEntityService.retrieveUserRoles(username);
        return ResponseEntity.status(response.getStatusCode())
                .body(InternalAuthApiResponse.success(response.getDescription(), (List<RoleResponse>) response.getData()));
    }

    /**
     * Step 2C (React Admin Client plan v4). Deliberately typed
     * (InternalAuthApiResponse<List<RoleSummaryResponse>>) rather than the
     * untyped Object/BaseResponse pattern the rest of this controller still
     * uses - that cleanup is Step 2F's job for the existing endpoints above;
     * this is new code, so it starts typed.
     */
    @PreAuthorize(Roles.HAS_ADMIN)
    @Operation(summary = "List roles", description = "Lists every role in the local database.")
    @GetMapping("/roles")
    public ResponseEntity<InternalAuthApiResponse<List<RoleSummaryResponse>>> listRoles() {
        List<RoleSummaryResponse> response = roleQueryService.listRoles();
        return ResponseEntity.ok(InternalAuthApiResponse.success(response));
    }

    /**
     * Step 2C. permissions/permissionGroups/usersInRole are three distinct,
     * separately-populated concepts - see RoleQueryServiceImpl's Javadoc
     * for why the response carries all three instead of picking one.
     */
    @PreAuthorize(Roles.HAS_ADMIN)
    @Operation(summary = "Get role detail", description = "Single role's detail: description, fine-grained permissions, associated permission groups, and the users directly assigned this role.")
    @GetMapping("/roles/{id}")
    public ResponseEntity<InternalAuthApiResponse<RoleDetailResponse>> getRole(@PathVariable Long id) {
        RoleDetailResponse response = roleQueryService.getRoleDetail(id);
        return ResponseEntity.ok(InternalAuthApiResponse.success(response));
    }


    /**
     * Step 2D (React Admin Client plan v4): fixes "no way to enumerate
     * group names today" - the existing GET /groups/{groupName} requires
     * already knowing the name. Deliberately typed, same rationale as
     * Step 2C's listRoles/getRole above.
     */
    @PreAuthorize(Roles.HAS_ADMIN)
    @Operation(summary = "List top-level groups", description = "Lists every top-level permission group in the local database.")
    @GetMapping("/groups")
    public ResponseEntity<InternalAuthApiResponse<List<GroupSummaryResponse>>> listGroups() {
        List<GroupSummaryResponse> response = groupQueryService.listTopLevelGroups();
        return ResponseEntity.ok(InternalAuthApiResponse.success(response));
    }

    /**
     * Step 2D. Same gap as above, one level down: the existing GET
     * /groups/{parentGroupName}/subgroups/{subGroupName} requires already
     * knowing the subgroup's name. Keyed by the parent's numeric id
     * (rather than name, like every other group endpoint) because listing
     * by id is what actually solves "I don't know the names yet" - once
     * the frontend has this response, it has the names for every
     * name-keyed endpoint.
     */
    @PreAuthorize(Roles.HAS_ADMIN)
    @Operation(summary = "List subgroups", description = "Lists every subgroup under the given top-level group.")
    @GetMapping("/groups/{id}/subgroups")
    public ResponseEntity<InternalAuthApiResponse<List<SubGroupSummaryResponse>>> listSubgroups(@PathVariable Long id) {
        List<SubGroupSummaryResponse> response = groupQueryService.listSubgroups(id);
        return ResponseEntity.ok(InternalAuthApiResponse.success(response));
    }

    /**
     * Step 2D: fixes "only parent-group delete exists today" (DELETE
     * /groups/{groupName} above removes an entire parent group and
     * cascades to every subgroup under it) - this removes exactly one
     * subgroup, leaving the parent and its other subgroups untouched.
     */
    @PreAuthorize(Roles.HAS_ADMIN)
    @Operation(summary = "Delete a subgroup", description = "Deletes a single subgroup without affecting its parent group or sibling subgroups.")
    @DeleteMapping("/groups/{parentGroupName}/subgroups/{subGroupName}")
    public ResponseEntity<InternalAuthApiResponse<Void>> deleteSubGroup(@PathVariable String parentGroupName, @PathVariable String subGroupName) {
        BaseResponse response = permissionService.deleteSubGroup(parentGroupName, subGroupName);
        return ResponseEntity.status(response.getStatusCode())
                .body(InternalAuthApiResponse.success(response.getDescription(), (Void) response.getData()));
    }

}
