package com.internal.auth.feature.rbac.service.impl;

import com.internal.auth.common.exception.PermissionErrorCode;
import com.internal.auth.common.exception.PermissionException;
import com.internal.auth.common.response.BaseResponse;
import com.internal.auth.feature.rbac.response.*;
import com.internal.auth.feature.rbac.service.*;
import io.micrometer.common.util.StringUtils;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * Orchestrates RBAC writes against the local database.
 *
 * <p><b>Keycloak-mirroring control flow — decision record (Stage 1 punch-list
 * item 2):</b> every method here used to open with a call into
 * {@code KeycloakService} (create/assign/remove "in Keycloak"), only then
 * write locally, and on a local failure ran a manual "compensating
 * transaction" — delete/re-add the Keycloak-side object to keep the two
 * systems in sync. That two-phase saga made sense when Keycloak was a real,
 * independently-failing external system. It stopped making sense the moment
 * {@code KeycloakServiceImpl} became a local-only stub (Stage 1 punch-list
 * item 1) that cannot fail and mirrors nothing — at that point the
 * "compensating transaction" was compensating for a failure that could
 * never happen, while doing nothing to protect against the only failure
 * that actually can happen (a local database error), because
 * {@code @Transactional} already rolls that back automatically.
 *
 * <p>Per the architecture assessment — "Internal Auth will be our own
 * authentication and authorization platform. Keycloak will NOT be used" —
 * the local database is the sole source of truth for RBAC. This class no
 * longer calls {@code KeycloakService} at all. Each method below is now:
 * validate input → call exactly one local entity/mapping service → wrap its
 * response. All idempotency ("already exists") and persistence-failure
 * handling already lives in those local services (see
 * {@link PermissionEntityServiceImpl}, {@link GroupRoleServiceImpl},
 * {@link UserRoleServiceImpl}, {@link UserPermissionGroupServiceImpl}) —
 * each independently performs its own existence check before writing and
 * throws a specific {@link PermissionException} on conflict or DB failure,
 * so no separate check was ever needed at this layer once the Keycloak step
 * is gone.
 *
 * <p>{@code KeycloakService}/{@code KeycloakServiceImpl} are NOT deleted —
 * {@code PasswordResetServiceImpl} still uses {@code resetPassword} against
 * them, which is out of scope for this decision. The RBAC-mirroring methods
 * on that interface ({@code createRoleInKeycloak}, {@code assignRoleToUser},
 * etc.) are now unused dead surface; trimming the interface itself is a
 * separate, smaller follow-up, not a control-flow question, so it's left
 * for later rather than folded in here. {@code KeycloakUtils} — which
 * existed solely to answer "does this already exist in Keycloak" for the
 * idempotency branches this class no longer has — had no other callers and
 * has been deleted outright.
 */
@Service
public class PermissionManagementServiceImpl implements PermissionManagementService {

    private static final Logger log = LoggerFactory.getLogger(PermissionManagementServiceImpl.class);

    private final PermissionEntityService permissionEntityService;
    private final UserRoleService userRoleService;
    private final GroupRoleService groupRoleService;
    private final UserPermissionGroupService groupService;

    public PermissionManagementServiceImpl(PermissionEntityService permissionEntityService, UserRoleService userRoleService, GroupRoleService groupRoleService, UserPermissionGroupService groupService) {
        this.permissionEntityService = permissionEntityService;
        this.userRoleService = userRoleService;
        this.groupRoleService = groupRoleService;
        this.groupService = groupService;
    }


    // ══════════════════════════════════════════════════════════════════════════
    //  Role creation
    // ══════════════════════════════════════════════════════════════════════════

    @Override
    @Transactional
    public BaseResponse createRole(String roleName, String description) {

        if (StringUtils.isBlank(roleName)) {
            throw PermissionException.emptyField("Role name field is mandatory");
        }

        roleName = roleName.toLowerCase().trim();

        try {
            // No keycloakRoleId to mirror any more — pass null rather than a
            // synthetic placeholder, since there's no external system for the
            // value to mean anything about.
            RoleResponse roleResponse = permissionEntityService.createRole(roleName, description);
            return new BaseResponse(HttpStatus.CREATED.value(), "Role created successfully", roleResponse);
        } catch (PermissionException ex) {
            throw ex;
        } catch (Exception ex) {
            throw PermissionException.internalError("Unexpected error during role creation: " + ex.getMessage());
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Group creation
    // ══════════════════════════════════════════════════════════════════════════

    @Override
    @Transactional
    public BaseResponse createSuperGroup(String groupName, String description) {

        if (StringUtils.isBlank(groupName)) {
            throw PermissionException.emptyField("Group name field is mandatory");
        }

        groupName = groupName.toLowerCase().trim();

        try {
            GroupCreationResponse superGroupResponse = permissionEntityService.createSuperGroup(groupName, description);
            return new BaseResponse(HttpStatus.CREATED.value(), "Group created successfully", superGroupResponse);
        } catch (PermissionException ex) {
            throw ex;
        } catch (Exception ex) {
            throw PermissionException.internalError("Unexpected error during group creation: " + ex.getMessage());
        }
    }

    @Override
    @Transactional
    public BaseResponse createSubGroup(String groupName, String description, String parentGroupName) {

        if (StringUtils.isBlank(groupName) || StringUtils.isBlank(parentGroupName)) {
            throw PermissionException.emptyField("Subgroup name and the parent group name fields are mandatory");
        }

        groupName = groupName.toLowerCase().trim();
        parentGroupName = parentGroupName.toLowerCase().trim();

        try {
            SubGroupCreationResponse response = permissionEntityService.createSubGroup(groupName, description, parentGroupName);
            return new BaseResponse(HttpStatus.CREATED.value(), "Subgroup created successfully", response);
        } catch (PermissionException ex) {
            throw ex;
        } catch (Exception ex) {
            throw PermissionException.internalError("Unexpected error during subgroup creation: " + ex.getMessage());
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Role assignment
    // ══════════════════════════════════════════════════════════════════════════

    @Override
    @Transactional
    public BaseResponse assignRoleToUser(String username, String role) {

        if (StringUtils.isBlank(username) || StringUtils.isBlank(role)) {
            throw PermissionException.emptyField("Username and role fields are mandatory");
        }

        role = role.toLowerCase().trim();

        try {
            UserRoleResponse roleResponse = userRoleService.assignRole(username, role);
            return new BaseResponse(HttpServletResponse.SC_CREATED, "Role assigned successfully", roleResponse);
        } catch (PermissionException ex) {
            throw ex;
        } catch (Exception e) {
            log.error("Unexpected error assigning role: {}", e.getMessage(), e);
            throw PermissionException.internalError("Unexpected error during role assignment: " + e.getMessage());
        }
    }

    @Override
    @Transactional
    public BaseResponse assignRoleToGroup(String groupName, String role) {

        if (StringUtils.isBlank(groupName) || StringUtils.isBlank(role)) {
            throw PermissionException.emptyField("Group and role fields are mandatory");
        }

        role = role.toLowerCase().trim();
        groupName = groupName.toLowerCase().trim();

        try {
            RoleAndPermissionGroupMappingResponse response = groupRoleService.assignRoleToGroup(groupName, role);
            return new BaseResponse(HttpServletResponse.SC_CREATED, "Role assigned to group successfully", response);

        } catch (PermissionException ex) {
            // Idempotency: groupRoleService already checked the local mapping and
            // found it exists — treat a repeat request as a no-op success rather
            // than an error, same as every other "assign" endpoint in this class.
            if (ex.getErrorCode() == PermissionErrorCode.ALREADY_EXISTS) {
                return new BaseResponse(HttpServletResponse.SC_OK, "Role already assigned to group", null);
            }
            throw ex;

        } catch (Exception e) {
            log.error("Unexpected error assigning role to group: {}", e.getMessage(), e);
            throw PermissionException.internalError("Unexpected error during role assignment to group: " + e.getMessage());
        }
    }

    @Override
    @Transactional
    public BaseResponse assignRoleToSubGroup(String superGroupName, String groupName, String role) {

        if (StringUtils.isBlank(superGroupName)
                || StringUtils.isBlank(groupName)
                || StringUtils.isBlank(role)) {
            throw PermissionException.emptyField(
                    "Supergroup, Subgroup and role fields are mandatory");
        }

        groupName = groupName.toLowerCase().trim();
        role = role.toLowerCase().trim();

        try {
            RoleAndPermissionGroupMappingResponse response = groupRoleService.assignRoleToSubGroup(groupName, role);
            return new BaseResponse(
                    HttpServletResponse.SC_CREATED, "Role assigned to subgroup successfully", response);
        } catch (PermissionException ex) {
            throw ex;
        } catch (Exception e) {
            log.error("Unexpected error assigning role to subgroup: {}", e.getMessage(), e);
            throw PermissionException.internalError("Unexpected error during role assignment to subgroup: " + e.getMessage());
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  User-to-group assignment
    // ══════════════════════════════════════════════════════════════════════════

    @Override
    @Transactional
    public BaseResponse addUserToGroup(String username, String groupName) {

        if (StringUtils.isBlank(username) || StringUtils.isBlank(groupName)) {
            throw PermissionException.emptyField("Username and group name fields are mandatory");
        }

        username = username.toLowerCase().trim();
        groupName = groupName.toLowerCase().trim();

        try {
            UserPermissionGroupResponse userPermissionGroupResponse = groupService.addUserToGroup(username, groupName);
            return new BaseResponse(HttpServletResponse.SC_CREATED, "User successfully added to permission group", userPermissionGroupResponse);
        } catch (PermissionException ex) {
            throw ex;
        } catch (Exception e) {
            log.error("Unexpected error adding user to group: {}", e.getMessage(), e);
            throw PermissionException.internalError("Unexpected error during user assignment to group: " + e.getMessage());
        }
    }

    @Override
    @Transactional
    public BaseResponse addUserToSubGroup(String username, String superGroupName, String subGroupName) {

        if (StringUtils.isBlank(username)
                || StringUtils.isBlank(superGroupName)
                || StringUtils.isBlank(subGroupName)) {
            throw PermissionException.emptyField("All fields are mandatory");
        }

        username = username.toLowerCase().trim();
        superGroupName = superGroupName.toLowerCase().trim();
        subGroupName = subGroupName.toLowerCase().trim();

        try {
            UserSubPermissionGroupResponse userPermissionGroupResponse =
                    groupService.addUserToSubGroup(username, superGroupName, subGroupName);
            return new BaseResponse(HttpServletResponse.SC_CREATED,
                    "User successfully added to sub permission group", userPermissionGroupResponse);
        } catch (PermissionException ex) {
            throw ex;
        } catch (Exception e) {
            log.error("Unexpected error adding user to sub group: {}", e.getMessage(), e);
            throw PermissionException.internalError("Unexpected error during user assignment to sub group: " + e.getMessage());
        }
    }

    @Override
    @Transactional
    public BaseResponse addUserToSubGroups(
            String username, String superGroupName, List<String> subGroupNames) {

        if (StringUtils.isBlank(username) || StringUtils.isBlank(superGroupName)) {
            throw PermissionException.emptyField("All fields are mandatory");
        }

        if (subGroupNames == null || subGroupNames.isEmpty()) {
            throw PermissionException.emptyRequest("Subgroup name request is empty");
        }

        username = username.toLowerCase().trim();
        superGroupName = superGroupName.toLowerCase().trim();
        subGroupNames = subGroupNames.stream()
                .filter(Objects::nonNull)
                .map(String::trim)
                .map(String::toLowerCase)
                .filter(n -> !n.isEmpty())
                .collect(Collectors.toList());

        try {
            List<UserPermissionGroupResponse> responses =
                    groupService.addUserToSubGroups(username, superGroupName, subGroupNames);
            return new BaseResponse(
                    HttpServletResponse.SC_CREATED, "User successfully added to subgroups", responses);
        } catch (PermissionException ex) {
            throw ex;
        } catch (Exception e) {
            log.error("Unexpected error adding user to subgroups: {}", e.getMessage(), e);
            throw PermissionException.internalError("Unexpected error during user assignment to subgroups: " + e.getMessage());
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Role and group removal
    // ══════════════════════════════════════════════════════════════════════════

    @Transactional
    @Override
    public BaseResponse unassignRole(String username, String roleName) {

        if (StringUtils.isBlank(username) || StringUtils.isBlank(roleName)) {
            throw PermissionException.emptyField("Username and role name are required");
        }

        username = username.toLowerCase().trim();
        roleName = roleName.toLowerCase().trim();

        try {
            RemoveRoleResponse roleResponse = userRoleService.unassignRole(username, roleName);
            return new BaseResponse(HttpServletResponse.SC_OK, roleResponse.getMessage(),
                    Map.of("username", roleResponse.getUsername(),
                           "roleName", roleResponse.getRoleName()));
        } catch (PermissionException ex) {
            throw ex;
        } catch (Exception e) {
            log.error("Failed to unassign role '{}' from user '{}': {}",
                    roleName, username, e.getMessage());
            throw PermissionException.internalError(
                    "Database operation failed while unassigning role. Original error: " + e.getMessage());
        }
    }

    @Transactional
    @Override
    public BaseResponse removeUserFromGroup(String username, String groupName) {

        if (StringUtils.isBlank(username) || StringUtils.isBlank(groupName)) {
            throw PermissionException.emptyField("Username and group name are required");
        }

        username = username.toLowerCase().trim();
        groupName = groupName.toLowerCase().trim();

        try {
            RemoveUserResponse removeUserResponse = groupService.removeUserFromPermissionGroup(username, groupName);
            return new BaseResponse(HttpServletResponse.SC_OK, removeUserResponse.getMessage(), Map.of("username", removeUserResponse.getUsername(), "roleName", removeUserResponse.getGroupName()));
        } catch (PermissionException ex) {
            throw ex;
        } catch (Exception e) {
            log.error("Failed to remove user '{}' from group '{}': {}", username, groupName, e.getMessage());
            throw PermissionException.internalError("Database operation failed while removing user from group. Original error: " + e.getMessage());
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Group deletion
    // ══════════════════════════════════════════════════════════════════════════

    @Override
    @Transactional
    public BaseResponse deleteSuperGroup(String groupName) {

        if (StringUtils.isBlank(groupName)) {
            throw PermissionException.emptyField("Group name is required");
        }

        groupName = groupName.toLowerCase().trim();

        try {
            permissionEntityService.deleteSuperGroup(groupName);
            return new BaseResponse(HttpStatus.OK.value(), "Group deleted successfully: " + groupName);
        } catch (PermissionException e) {
            throw e;
        } catch (Exception ex) {
            throw PermissionException.internalError("Unexpected error deleting group: " + groupName + " — " + ex.getMessage());
        }
    }

    /**
     * Step 2D (React Admin Client plan v4): fixes "only parent-group delete
     * exists today" - deleteSuperGroup above cascades and removes an entire
     * parent group plus every subgroup under it; this deletes exactly one
     * subgroup, leaving the parent and its other subgroups untouched.
     */
    @Override
    @Transactional
    public BaseResponse deleteSubGroup(String parentGroupName, String subGroupName) {

        if (StringUtils.isBlank(parentGroupName) || StringUtils.isBlank(subGroupName)) {
            throw PermissionException.emptyField("Parent group name and sub group name are required");
        }

        parentGroupName = parentGroupName.toLowerCase().trim();
        subGroupName = subGroupName.toLowerCase().trim();

        try {
            permissionEntityService.deleteSubGroup(parentGroupName, subGroupName);
            return new BaseResponse(HttpStatus.OK.value(), "Subgroup deleted successfully: " + subGroupName);
        } catch (PermissionException e) {
            throw e;
        } catch (Exception ex) {
            throw PermissionException.internalError("Unexpected error deleting subgroup: " + subGroupName + " — " + ex.getMessage());
        }
    }
}
