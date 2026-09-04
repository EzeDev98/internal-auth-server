package com.internal.auth.feature.rbac.service.impl;

import com.internal.auth.common.exception.PermissionException;
import com.internal.auth.feature.rbac.model.Role;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.rbac.model.UserRole;
import com.internal.auth.feature.rbac.response.BulkRoleAssignmentResponse;
import com.internal.auth.feature.rbac.response.RemoveRoleResponse;
import com.internal.auth.feature.rbac.response.UserRoleResponse;
import com.internal.auth.feature.rbac.service.UserRoleService;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Service
public class UserRoleServiceImpl implements UserRoleService {
    private static final Logger log = LoggerFactory.getLogger(UserRoleServiceImpl.class);

    private final DtoMapper mapper;
    private final EntityUtilityService entityUtils;

    public UserRoleServiceImpl(DtoMapper mapper, EntityUtilityService entityUtils) {
        this.mapper = mapper;
        this.entityUtils = entityUtils;
    }

    @Override
    public BulkRoleAssignmentResponse bulkRoleAssignment(List<String> usernames, List<String> roles) {

        if (usernames == null || usernames.isEmpty()) {
            throw PermissionException.emptyField("Usernames list is mandatory");
        }

        if (roles == null || roles.isEmpty()) {
            throw PermissionException.emptyField("Roles list is mandatory");
        }

        List<UserRole> toSave = new ArrayList<>();
        List<String> duplicates = new ArrayList<>();
        List<String> failures = new ArrayList<>();

        for (String username : usernames) {
            for (String role : roles) {

                if (StringUtils.isBlank(username) || StringUtils.isBlank(role)) {
                    failures.add(formatEntry(username, role) + " [blank field]");
                    continue;
                }

                try {
                    if (entityUtils.userRoleExists(username, role)) {
                        duplicates.add(formatEntry(username, role));
                        log.debug("Skipping duplicate: user '{}' already has role '{}'", username, role);
                        continue;
                    }

                    UserRole userRole = assignRoleToUser(username, role);
                    toSave.add(userRole);

                } catch (Exception ex) {
                    failures.add(formatEntry(username, role) + " [" + ex.getMessage() + "]");
                    log.error("Failed to prepare role '{}' for user '{}': {}", role, username, ex.getMessage());
                }
            }
        }

        List<UserRole> savedRoles = new ArrayList<>();
        if (!toSave.isEmpty()) {
            try {
                savedRoles = entityUtils.saveAllUserRoles(toSave);
            } catch (DataAccessException ex) {
                throw PermissionException.userRolePersistenceFailed("Bulk role assignment failed at persistence layer: " + ex.getMessage());
            }
        }

        List<UserRoleResponse> assigned = savedRoles.stream()
                .map(mapper::buildUserRole)
                .toList();

        int totalRequested = usernames.size() * roles.size();

        return new BulkRoleAssignmentResponse(totalRequested, assigned.size(), duplicates.size(), failures.size(), assigned, duplicates, failures);
    }

    private String formatEntry(String username, String role) {
        return "user='" + username + "' role='" + role + "'";
    }



    @Override
    public RemoveRoleResponse unassignRole(String username, String roleName) {

        if (StringUtils.isBlank(username) || StringUtils.isBlank(roleName)) {
            throw PermissionException.emptyField("Username and role name are required");
        }

        try {

            User user = entityUtils.getUser(username);
            Role role = entityUtils.getRole(roleName);

            UserRole mapping = entityUtils.getUserAndRole(user, role);
            if (mapping == null) {
                log.warn("User '{}' does not have role '{}'. Skipping unassignment.", username, roleName);
                return new RemoveRoleResponse(HttpServletResponse.SC_OK, String.format("User '%s' did not have role '%s' — nothing to remove", username, roleName), username, roleName);
            }

            entityUtils.deleteUserAndRoleMapping(mapping);
            log.info("Successfully unassigned role '{}' from user '{}'", roleName, username);
            return new RemoveRoleResponse(HttpServletResponse.SC_OK, String.format("Role '%s' successfully removed from user '%s'", roleName, username), username, roleName);

        } catch (Exception e) {
            log.error("Failed to unassign role '{}' from user '{}': {}", roleName, username, e.getMessage());
            throw PermissionException.operationFailed(String.format("Failed to unassign role '%s' from user '%s'", roleName, username), e);
        }
    }

    @Override
    public void assignRoles(String username, List<String> roles) {
        if (username == null) {
            throw PermissionException.emptyField("Username field is mandatory");
        }
        if (roles == null || roles.isEmpty()) {
            throw PermissionException.emptyField("Roles list cannot be null or empty");
        }

        Set<String> uniqueRoles = new HashSet<>(roles);
        validateRolesExist(uniqueRoles);

        uniqueRoles.forEach(role -> assignRole(username, role));
    }

    @Override
    public UserRoleResponse assignRole(String username, String role) {
        validateInput(username, role);

        try {
            if (entityUtils.userRoleExists(username, role)) {
                throw PermissionException.duplicateRoleAssignment("User " + username + " already has role " + role);
            }
            UserRole userRole = assignRoleToUser(username, role);
            UserRole savedUserRole = entityUtils.saveUserRole(userRole);
            return mapper.buildUserRole(savedUserRole);
        } catch (DataAccessException ex) {
            throw PermissionException.userRolePersistenceFailed("Role not persisted for user " + username + " in the database");
        }
    }

    private void validateInput(String username, String role) {
        if (username == null || role == null) {
            throw PermissionException.emptyField("Username and role fields are mandatory");
        }
    }

    private void validateRolesExist(Set<String> roleNames) {
        roleNames.forEach(roleName -> {
            if (!entityUtils.isRoleExist(roleName)) {
                throw PermissionException.roleNotFound("Role with provided name " + roleName + " does not exist");
            }
        });
    }

    private UserRole assignRoleToUser(String username, String roleName) {
        UserRole userRole = new UserRole();
        userRole.setUser(entityUtils.getUser(username));
        userRole.setRole(entityUtils.getRole(roleName));
        userRole.setCreatedAt(LocalDateTime.now());
        return userRole;
    }
}