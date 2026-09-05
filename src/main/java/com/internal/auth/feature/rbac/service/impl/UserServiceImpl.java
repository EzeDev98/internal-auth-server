package com.internal.auth.feature.rbac.service.impl;

import com.internal.auth.common.exception.PermissionErrorCode;
import com.internal.auth.common.exception.PermissionException;
import com.internal.auth.common.response.BaseResponse;
import com.internal.auth.feature.rbac.model.PermissionGroup;
import com.internal.auth.feature.rbac.model.Role;
import com.internal.auth.feature.rbac.service.PermissionManagementService;
import com.internal.auth.feature.rbac.service.UserService;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

import static com.internal.auth.common.constant.AppConstant.ADMIN_PERMISSION_GROUP;
import static com.internal.auth.common.constant.AppConstant.ADMIN_PERMISSION_GROUP_DESCRIPTION;
import static com.internal.auth.common.constant.AppConstant.ADMIN_ROLE;
import static com.internal.auth.common.constant.AppConstant.ADMIN_ROLE_DESCRIPTION;
import static com.internal.auth.common.constant.AppConstant.DEFAULT_PERMISSION_GROUP;
import static com.internal.auth.common.constant.AppConstant.DEFAULT_PERMISSION_GROUP_DESCRIPTION;
import static com.internal.auth.common.constant.AppConstant.DEFAULT_ROLE;
import static com.internal.auth.common.constant.AppConstant.DEFAULT_ROLE_DESCRIPTION;

/**
 * Exception policy: throws only {@link PermissionException}.
 *
 * <p>{@link #addUserToDefaultPermissionGroup} and
 * {@link #addUserToAdminPermissionGroup} are orchestrators designed to
 * return a {@link BaseResponse} error instead of propagating exceptions —
 * this behavior is fully preserved. Both now share one parameterized
 * implementation ({@code addUserToPermissionGroup}) - same get-or-create
 * group/role/mapping/membership logic, just pointed at a different
 * group/role name pair (DEFAULT_* for every new user, ADMIN_* for the admin
 * bootstrap flow in AdminRegistrationServiceImpl).
 *
 * <p><b>Keycloak-mirroring control flow — decision record (Stage 1 punch-list
 * item 2):</b> this class used to branch every "does the default role/group
 * already exist" check on {@code KeycloakUtils} (querying Keycloak state),
 * with a separate code path for "exists in Keycloak but not locally yet" vs
 * "doesn't exist anywhere." Now that the local database is the sole source
 * of truth for RBAC (see {@link PermissionManagementServiceImpl}'s class
 * javadoc for the full decision record), there is only one thing to check —
 * local state — so the Keycloak-vs-local duality collapses to a plain
 * "create it locally if it's missing" and the {@code KeycloakUtils}
 * dependency is gone entirely.
 *
 * <p><b>Create-vs-create race (V20):</b> validateAndCreateGroup/
 * validateAndCreateRole below follow a get-then-create-if-missing pattern,
 * which is itself a check-then-act race when two callers (e.g. two
 * concurrent registrations) both find the default group/role missing and
 * both attempt to create it. PermissionEntityServiceImpl now backs its own
 * pre-check with a DB unique constraint and turns the loser's constraint
 * violation into a PermissionException.alreadyExists(...) rather than a raw
 * persistence failure — the two methods below catch that specific case and
 * treat it as success (the row exists, just not because of this call)
 * instead of failing the whole assignment.
 */
@Service
public class UserServiceImpl implements UserService {

    private static final Logger logger = LoggerFactory.getLogger(UserServiceImpl.class);

    private final PermissionManagementService permissionService;
    private final EntityUtilityService entityUtils;

    public UserServiceImpl(PermissionManagementService permissionService, EntityUtilityService entityUtils) {
        this.permissionService = permissionService;
        this.entityUtils = entityUtils;
    }


    @Override
    @Transactional
    public BaseResponse addUserToDefaultPermissionGroup(String username) {
        return addUserToPermissionGroup(username,
                DEFAULT_PERMISSION_GROUP, DEFAULT_PERMISSION_GROUP_DESCRIPTION,
                DEFAULT_ROLE, DEFAULT_ROLE_DESCRIPTION);
    }

    @Override
    @Transactional
    public BaseResponse addUserToAdminPermissionGroup(String username) {
        return addUserToPermissionGroup(username,
                ADMIN_PERMISSION_GROUP, ADMIN_PERMISSION_GROUP_DESCRIPTION,
                ADMIN_ROLE, ADMIN_ROLE_DESCRIPTION);
    }

    private BaseResponse addUserToPermissionGroup(String username, String groupName, String groupDescription,
                                                    String roleName, String roleDescription) {
        try {
            PermissionGroup permissionGroup = validateAndCreateGroup(groupName, groupDescription);
            validateAndCreateRole(roleName, roleDescription);
            validateAndAssignRoleToGroup(permissionGroup, roleName);
            addUserToGroup(username, permissionGroup.getGroupName());
            assignGroupRoleToUser(username, permissionGroup.getGroupName());

            return new BaseResponse(HttpServletResponse.SC_CREATED, "User " + username + " successfully added into " + groupName + " with role " + roleName);

        } catch (PermissionException ex) {
            /*
             * Behavior unchanged from before the Keycloak-mirroring redesign:
             *
             *  GROUP_CREATION_FAILED: Log + return 500 "Failed to create permission group".
             *  ROLE_NOT_ASSIGNED: Log + return 500 "Role could not be assigned".
             *  USER_NOT_ADDED_TO_GROUP: Log + return 500 "User could not be added to group".
             *  Anything else: falls through to the outer catch (Exception) path.
             */
            if (ex.getErrorCode() == PermissionErrorCode.GROUP_CREATION_FAILED) {
                logger.error("Failed to create or validate permission group: {}", ex.getMessage(), ex);
                return new BaseResponse(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Failed to create permission group");
            }

            if (ex.getErrorCode() == PermissionErrorCode.ROLE_NOT_ASSIGNED) {
                logger.error("Failed to assign role to group: {}", ex.getMessage(), ex);
                return new BaseResponse(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Role could not be assigned");
            }

            if (ex.getErrorCode() == PermissionErrorCode.USER_NOT_ADDED_TO_GROUP) {
                logger.error("Failed to add user to group: {}", ex.getMessage(), ex);
                return new BaseResponse(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "User could not be added to group");
            }

            logger.error("Unexpected permission error adding user to default group: {}",
                    ex.getMessage(), ex);
            return new BaseResponse(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "An unexpected error occurred");

        } catch (Exception ex) {
            logger.error("Unexpected error adding user to default permission group: {}", ex.getMessage(), ex);
            return new BaseResponse(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "An unexpected error occurred");
        }
    }

    // ── Private helpers ────────────────────────────────────────────────────────

    private void assignGroupRoleToUser(String username, String groupName) {
        try {
            PermissionGroup group = entityUtils.getPermissionGroup(groupName);
            List<String> roles = entityUtils.getGroupRoles(group).stream()
                    .map(Role::getRoleName)
                    .toList();

            if (roles.isEmpty()) {
                logger.info("No roles found for group {}", groupName);
                return;
            }

            List<String> assignedRoles = new ArrayList<>();
            List<String> failedRoles   = new ArrayList<>();

            for (String role : roles) {
                if (entityUtils.userRoleExists(username, role)) {
                    logger.debug("User {} already has role {}, skipping", username, role);
                    continue;
                }
                try {
                    permissionService.assignRoleToUser(username, role);
                    assignedRoles.add(role);
                    logger.debug("Assigned role {} to user {}", role, username);
                } catch (Exception e) {
                    failedRoles.add(role);
                    logger.error("Failed to assign role {} to user {}", role, username, e);
                }
            }

            if (!failedRoles.isEmpty()) {
                throw PermissionException.roleNotAssigned("Failed to assign roles: " + failedRoles);
            }

            logger.info("Successfully assigned roles {} to user {}", assignedRoles, username);

        } catch (PermissionException ex) {
            if (ex.getErrorCode() == PermissionErrorCode.PERMISSION_GROUP_NOT_FOUND) {
                logger.error("Group not found: {}", groupName, ex);
                throw ex;
            }
            logger.error("Unexpected error assigning group roles to user: {}", ex.getMessage(), ex);
            throw PermissionException.roleNotAssigned("Failed to assign group roles to user");

        } catch (Exception ex) {
            logger.error("Unexpected error assigning group roles to user: {}", ex.getMessage(), ex);
            throw PermissionException.roleNotAssigned("Failed to assign group roles to user");
        }
    }

    private PermissionGroup validateAndCreateGroup(String groupName, String groupDescription) {
        try {
            return entityUtils.getPermissionGroup(groupName);
        } catch (PermissionException e) {
            if (e.getErrorCode() == PermissionErrorCode.PERMISSION_GROUP_NOT_FOUND) {
                try {
                    BaseResponse response = permissionService.createSuperGroup(groupName, groupDescription);
                    if (response.getStatusCode() != HttpServletResponse.SC_CREATED) {
                        throw PermissionException.groupCreationFailed(
                                "Failed to create permission group " + groupName);
                    }
                } catch (PermissionException createEx) {
                    // Lost a create-vs-create race (V20) - the group now
                    // genuinely exists, just not because of this call. Fall
                    // through to the re-fetch below instead of failing.
                    if (createEx.getErrorCode() != PermissionErrorCode.ALREADY_EXISTS) {
                        throw createEx;
                    }
                }
                return entityUtils.getPermissionGroup(groupName);
            }
            throw e;
        }
    }

    private void validateAndCreateRole(String roleName, String roleDescription) {
        try {
            entityUtils.getRole(roleName);
        } catch (PermissionException ex) {
            if (ex.getErrorCode() == PermissionErrorCode.ROLE_NOT_FOUND) {
                try {
                    BaseResponse response = permissionService.createRole(roleName, roleDescription);
                    if (response.getStatusCode() != HttpServletResponse.SC_CREATED) {
                        throw PermissionException.roleCreationFailed("Failed to create role " + roleName);
                    }
                } catch (PermissionException createEx) {
                    // Same create-vs-create race as validateAndCreateGroup
                    // above (V20).
                    if (createEx.getErrorCode() != PermissionErrorCode.ALREADY_EXISTS) {
                        throw createEx;
                    }
                }
                return;
            }
            throw ex;
        }
    }

    private void validateAndAssignRoleToGroup(PermissionGroup permissionGroup, String roleName) {
        try {
            Role role = entityUtils.getRole(roleName);
            if (entityUtils.isRoleAndPermissionGroupMappingExisting(role, permissionGroup)) {
                return;
            }

            BaseResponse response = permissionService.assignRoleToGroup(permissionGroup.getGroupName(), roleName);
            // 201 = newly assigned, 200 = assignRoleToGroup's own idempotency
            // path found it already assigned — both are success here.
            if (response.getStatusCode() != HttpServletResponse.SC_CREATED
                    && response.getStatusCode() != HttpServletResponse.SC_OK) {
                throw PermissionException.roleNotAssigned(
                        "Failed to assign role " + roleName + " to group");
            }
        } catch (PermissionException ex) {
            if (ex.getErrorCode() == PermissionErrorCode.ROLE_NOT_FOUND) {
                throw PermissionException.internalError(
                        "Role " + roleName + " not found in the local database");
            }
            throw ex;
        }
    }

    private void addUserToGroup(String username, String groupName) {
        BaseResponse addUserResponse = permissionService.addUserToGroup(username, groupName);
        if (addUserResponse.getStatusCode() != HttpServletResponse.SC_CREATED) {
            throw PermissionException.userNotAddedToGroup(
                    "Failed to add user to permission group " + groupName);
        }
    }
}
