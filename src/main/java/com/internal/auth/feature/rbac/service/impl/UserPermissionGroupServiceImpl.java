package com.internal.auth.feature.rbac.service.impl;

import com.internal.auth.common.exception.PermissionException;
import com.internal.auth.feature.rbac.model.PermissionGroup;
import com.internal.auth.feature.rbac.model.Role;
import com.internal.auth.feature.rbac.model.RolePermissionGroupMapping;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.rbac.model.UserPermissionGroup;
import com.internal.auth.feature.rbac.response.*;
import com.internal.auth.feature.rbac.service.UserPermissionGroupService;
import com.internal.auth.feature.rbac.service.UserRoleService;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class UserPermissionGroupServiceImpl implements UserPermissionGroupService {

    private static final Logger log = LoggerFactory.getLogger(UserPermissionGroupServiceImpl.class);
    private final EntityUtilityService entityUtils;
    private final DtoMapper mapper;
    private final UserRoleService roleService;

    public UserPermissionGroupServiceImpl(EntityUtilityService entityUtils, DtoMapper mapper, UserRoleService roleService) {
        this.entityUtils = entityUtils;
        this.mapper = mapper;
        this.roleService = roleService;
    }

    @Override
    public BulkUserGroupAssignmentResponse addBulkUsersToParentGroup(List<String> usernames, String groupName) {

        if (CollectionUtils.isEmpty(usernames)) {
            throw PermissionException.emptyRequest("Usernames are required");
        }

        if (StringUtils.isBlank(groupName)) {
            throw PermissionException.emptyField("Group name is required");
        }

        PermissionGroup group = entityUtils.getPermissionGroup(groupName);
        List<Role> groupRoles = getRolesForPermissionGroup(group);

        List<UserPermissionGroup> toSave = new ArrayList<>();
        List<UserPermissionGroupResponse> alreadyInGroup = new ArrayList<>();
        List<String> failures = new ArrayList<>();

        for (String username : usernames) {

            if (StringUtils.isBlank(username)) {
                failures.add("blank-username [blank field]");
                log.warn("Skipping blank username entry");
                continue;
            }

            try {
                if (entityUtils.userPermissionGroupExists(username, groupName)) {
                    log.info("User '{}' is already in group '{}'", username, groupName);
                    alreadyInGroup.add(mapper.buildUserPermissionGroup(entityUtils.getUserPermissionGroup(username, groupName)));
                    continue;
                }

                toSave.add(createUserPermissionGroup(username, groupName));

            } catch (Exception ex) {
                failures.add(username + " [" + ex.getMessage() + "]");
                log.error("Failed to prepare group mapping for user '{}': {}", username, ex.getMessage());
            }
        }

        List<UserPermissionGroup> savedMemberships = new ArrayList<>();
        if (!toSave.isEmpty()) {
            try {
                savedMemberships = entityUtils.saveAllUserPermissionGroups(toSave);
            } catch (DataAccessException ex) {
                throw PermissionException.userGroupMappingFailed("Bulk group assignment failed at persistence layer: " + ex.getMessage());
            }
        }

        if (!savedMemberships.isEmpty() && !groupRoles.isEmpty()) {

            List<String> newUsernames = savedMemberships.stream()
                    .map(m -> m.getUser().getUsername())
                    .toList();

            List<String> roleNames = groupRoles.stream()
                    .map(Role::getRoleName)
                    .toList();

            BulkRoleAssignmentResponse roleAssignmentResult = roleService.bulkRoleAssignment(newUsernames, roleNames);
            log.info("Role assignment for bulk group add — assigned: {}, duplicates: {}, failed: {}", roleAssignmentResult.getSuccessfullyAssigned(), roleAssignmentResult.getSkippedDuplicates(), roleAssignmentResult.getFailed());
        }

        List<UserPermissionGroupResponse> successfullyAdded = savedMemberships.stream()
                .map(mapper::buildUserPermissionGroup)
                .toList();

        return new BulkUserGroupAssignmentResponse(usernames.size(), successfullyAdded.size(), alreadyInGroup.size(), failures.size(), successfullyAdded, alreadyInGroup, failures);
    }


    @Override
    public RemoveUserResponse removeUserFromPermissionGroup(String username, String groupName) {
        if (StringUtils.isBlank(username) || StringUtils.isBlank(groupName)) {
            throw PermissionException.emptyField("Username and group name are required");
        }

        try {
            User user = entityUtils.getUser(username);
            PermissionGroup permissionGroup = entityUtils.getPermissionGroup(groupName);
            UserPermissionGroup userPermissionGroup = entityUtils.getUserAndGroup(user, permissionGroup);
            List<Role> groupRoles = entityUtils.getGroupRoles(permissionGroup);

            log.info("Removing user '{}' from permission group '{}'. Will unassign {} roles.", username, groupName, groupRoles.size());

            for (Role role : groupRoles) {
                try {
                    roleService.unassignRole(username, role.getRoleName());
                } catch (Exception e) {
                    log.warn("Failed to unassign role '{}' from user '{}' during group removal. Continuing...", role.getRoleName(), username, e);
                }
            }

            entityUtils.deleteUserAndGroupMapping(userPermissionGroup);
            log.info("Successfully removed user '{}' from permission group '{}'", username, groupName);
            return new RemoveUserResponse(HttpServletResponse.SC_OK, "User successfully removed from permission group", username, groupName);
        } catch (PermissionException ex) {
            log.warn("Not found during remove: {}", ex.getMessage());
            throw ex;
        } catch (Exception e) {
            log.error("Unexpected error while removing user '{}' from group '{}': {}", username, groupName, e.getMessage(), e);
            throw PermissionException.operationFailed("Failed to remove user from the specified group", e);
        }
    }

    @Override
    public List<String> addExistingUsersIntoDefaultPermissionGroup(String groupName) {
        if (groupName == null) {
            throw PermissionException.emptyField("Group name field is mandatory");
        }

        PermissionGroup group = entityUtils.getPermissionGroup(groupName);
        List<Role> groupRoles = getRolesForPermissionGroup(group);
        List<User> users = entityUtils.getAllUsers();

        // Returns every username that was already in the group or is now in it,
        // so the caller (PermissionManagementServiceImpl) can report back who's
        // covered without needing a second, separate lookup. Local DB is the
        // only source of truth here, so a per-user failure is logged and skipped
        // rather than aborting the whole batch.
        List<String> processed = new ArrayList<>();
        for (User user : users) {
            try {
                addUserToGroup(user.getUsername(), groupName, groupRoles);
                processed.add(user.getUsername());
            } catch (Exception e) {
                log.warn("Failed to add user {} to group {}: {}", user.getUsername(), groupName, e.getMessage());
            }
        }
        return processed;
    }

    @Override
    public void addUserToNamedPermissionGroup(String username, String groupName) {

        if (StringUtils.isBlank(username) || StringUtils.isBlank(groupName)) {
            throw PermissionException.emptyField("Username and group name are required");
        }

        PermissionGroup group = entityUtils.getPermissionGroup(groupName);
        List<Role> groupRoles = getRolesForPermissionGroup(group);

        try {
            addUserToGroup(username, groupName, groupRoles);
        } catch (Exception e) {
            log.warn("Failed to add user {} to group {}: {}", username, groupName, e.getMessage());
        }
    }

    @Override
    public UserPermissionGroupResponse addUserToGroup(String username, String groupName) {
        if (username == null || groupName == null) {
            throw PermissionException.emptyField("Username and group name fields are mandatory");
        }

        PermissionGroup group = entityUtils.getPermissionGroup(groupName);
        List<Role> groupRoles = getRolesForPermissionGroup(group);

        return addUserToGroup(username, groupName, groupRoles);
    }

    private UserPermissionGroupResponse addUserToGroup(String username, String groupName, List<Role> groupRoles) {
        try {

            if (entityUtils.userPermissionGroupExists(username, groupName)) {
                log.info("User {} is already in group {}", username, groupName);
                return mapper.buildUserPermissionGroup(entityUtils.getUserPermissionGroup(username, groupName));
            }

            UserPermissionGroup permissionGroup = createUserPermissionGroup(username, groupName);
            UserPermissionGroup savedUserPermissionGroup = entityUtils.saveUserPermissionGroup(permissionGroup);

            assignGroupRolesToUser(username, groupRoles);
            return mapper.buildUserPermissionGroup(savedUserPermissionGroup);
        } catch (DataAccessException ex) {
            throw PermissionException.userGroupMappingFailed("User not added to permission group " + groupName);
        }
    }

    private void assignGroupRolesToUser(String username, List<Role> roles) {
        if (roles == null || roles.isEmpty()) {
            return;
        }

        for (Role role : roles) {
            safelyAssignRole(username, role.getRoleName());
        }
    }

    private void safelyAssignRole(String username, String roleName) {
        try {
            roleService.assignRole(username, roleName);
        } catch (PermissionException e) {
            log.debug("User {} already has role {} - skipping assignment", username, roleName);
        } catch (Exception e) {
            log.error("Failed to assign role {} to user {}: {}", roleName, username, e.getMessage());
        }
    }


    private UserPermissionGroup createUserPermissionGroup(String username, String groupName) {
        UserPermissionGroup permissionGroup = new UserPermissionGroup();
        permissionGroup.setUser(entityUtils.getUser(username));
        permissionGroup.setPermissionGroup(entityUtils.getPermissionGroup(groupName));
        permissionGroup.setCreatedAt(LocalDateTime.now());
        return permissionGroup;
    }

    private List<Role> getRolesForPermissionGroup(PermissionGroup group) {

        if (group.getRolePermissionGroupMappings() == null) {
            throw PermissionException.operationFailed("No mapping found for permission group " + group.getGroupName());
        }

        return group.getRolePermissionGroupMappings().stream()
                .map(RolePermissionGroupMapping::getRole)
                .collect(Collectors.toList());
    }

    @Override
    public UserSubPermissionGroupResponse addUserToSubGroup(String username, String groupName, String subGroupName) {
        try {
            UserPermissionGroup permissionGroup = addUserToChildGroup(username, groupName, subGroupName);
            UserPermissionGroup savedGroup = entityUtils.saveUserPermissionGroup(permissionGroup);
            return mapper.buildUserSubPermissionGroup(savedGroup);
        } catch (DataAccessException ex) {
            throw PermissionException.userGroupMappingFailed("Failed to add user to sub permission group " + subGroupName);
        }
    }

    @Override
    public List<UserPermissionGroupResponse> addUserToSubGroups(String username, String groupName, List<String> subGroupNames) {
        try {
            List<UserPermissionGroup> userPermissionGroups = addUserToChildGroups(username, groupName, subGroupNames);
            List<UserPermissionGroup> savedUserPermissionGroups = entityUtils.saveUserPermissionGroups(userPermissionGroups);
            return mapper.buildUserPermissionGroups(savedUserPermissionGroups);
        } catch (DataAccessException ex) {
            throw PermissionException.userGroupMappingFailed("Failed to add user to sub permission groups " + subGroupNames);
        }
    }

    private List<UserPermissionGroup> addUserToChildGroups(String username, String groupName, List<String> subGroupNames) {

        List<UserPermissionGroup> subPermissionGroups = new ArrayList<>();
        for (String subGroupName: subGroupNames) {
            UserPermissionGroup permissionGroup = addUserToChildGroup(username, groupName, subGroupName);
            subPermissionGroups.add(permissionGroup);
        }

        return subPermissionGroups;
    }

    private UserPermissionGroup addUserToChildGroup(String username, String groupName, String subGroupName) {
        UserPermissionGroup permissionGroup = new UserPermissionGroup();
        permissionGroup.setUser(entityUtils.getUser(username));
        permissionGroup.setPermissionGroup(entityUtils.getPermissionGroup(groupName));
        permissionGroup.setSubPermissionGroup(entityUtils.getSubPermissionGroup(subGroupName));
        permissionGroup.setCreatedAt(LocalDateTime.now());
        return permissionGroup;
    }
}