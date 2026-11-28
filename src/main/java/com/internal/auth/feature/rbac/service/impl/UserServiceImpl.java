package com.internal.auth.feature.rbac.service.impl;

import com.internal.auth.common.exception.PermissionErrorCode;
import com.internal.auth.common.exception.PermissionException;
import com.internal.auth.common.response.BaseResponse;
import com.internal.auth.feature.rbac.model.PermissionGroup;
import com.internal.auth.feature.rbac.model.Role;
import com.internal.auth.feature.rbac.service.PermissionManagementService;
import com.internal.auth.feature.rbac.service.UserService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
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

/** Places users in the default and admin permission groups. */
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
    @Transactional(propagation = Propagation.REQUIRES_NEW)
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
