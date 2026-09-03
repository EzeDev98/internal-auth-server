package com.internal.auth.feature.rbac.service.impl;

import com.internal.auth.common.exception.PermissionException;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.identity.repository.UserRepository;
import com.internal.auth.feature.rbac.model.*;
import com.internal.auth.feature.rbac.repository.*;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;

import java.util.Collections;
import java.util.List;

@Component
public class EntityUtilityService {

    private final SubPermissionGroupRepository subPermissionGroupRepository;
    private final PermissionGroupsRepository permissionGroupsRepository;
    private final UserPermissionGroupRepository userPermissionGroupRepository;
    private final RolesRepository rolesRepository;
    private final RolePermissionGroupMappingRepository rolePermissionGroupMappingRepository;
    private final UserRolesRepository userRolesRepository;
    private final UserRepository userRepository;

    public EntityUtilityService(SubPermissionGroupRepository subPermissionGroupRepository, PermissionGroupsRepository permissionGroupsRepository, UserPermissionGroupRepository userPermissionGroupRepository, RolesRepository rolesRepository, RolePermissionGroupMappingRepository rolePermissionGroupMappingRepository, UserRolesRepository userRolesRepository, UserRepository userRepository) {
        this.subPermissionGroupRepository = subPermissionGroupRepository;
        this.permissionGroupsRepository = permissionGroupsRepository;
        this.userPermissionGroupRepository = userPermissionGroupRepository;
        this.rolesRepository = rolesRepository;
        this.rolePermissionGroupMappingRepository = rolePermissionGroupMappingRepository;
        this.userRolesRepository = userRolesRepository;
        this.userRepository = userRepository;
    }

    public User getUser(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> PermissionException.userNotFound(username));
    }

    public List<User> getAllUsers() {
        return userRepository.findAll();
    }


    public List<UserRole> saveAllUserRoles(List<UserRole> userRoles) {
        return userRolesRepository.saveAll(userRoles);
    }

    public List<UserPermissionGroup> saveAllUserPermissionGroups(List<UserPermissionGroup> memberships) {
        return userPermissionGroupRepository.saveAll(memberships);
    }

    public Role saveRole(Role role) {
        return rolesRepository.save(role);
    }

    public PermissionGroup savePermissionGroup(PermissionGroup permissionGroup) {
        return permissionGroupsRepository.save(permissionGroup);
    }

    public UserPermissionGroup saveUserPermissionGroup(UserPermissionGroup group) {
        return userPermissionGroupRepository.save(group);
    }

    public List<UserPermissionGroup> saveUserPermissionGroups(List<UserPermissionGroup> groups) {
        return userPermissionGroupRepository.saveAll(groups);
    }

    public SubPermissionGroup saveSubPermissionGroup(SubPermissionGroup group) {
        return subPermissionGroupRepository.save(group);
    }

    public PermissionGroup getPermissionGroup(String groupName) {
        return permissionGroupsRepository.findByGroupName(groupName)
                .orElseThrow(() -> PermissionException.permissionGroupNotFound(groupName));
    }

    public SubPermissionGroup getSubPermissionGroupByName(String groupName) {
        return subPermissionGroupRepository.findByGroupName(groupName)
                .orElseThrow(() -> PermissionException.subGroupNotFound(groupName));
    }

    public SubPermissionGroup getSubPermissionGroup(String groupName) {
        return subPermissionGroupRepository.findByGroupName(groupName)
                .orElseThrow(() -> PermissionException.subGroupNotFound(groupName));
    }

    public Role getRole(String roleName) {
        return rolesRepository.findByRoleName(roleName)
                .orElseThrow(() -> PermissionException.roleNotFound(roleName));
    }

    public RolePermissionGroupMapping saveRolePermissionGroupMapping(RolePermissionGroupMapping mapping) {
        return rolePermissionGroupMappingRepository.save(mapping);
    }

    public UserRole saveUserRole(UserRole userRole) {
        return userRolesRepository.save(userRole);
    }

    public boolean isRoleAndPermissionGroupMappingExisting(Role role, PermissionGroup permissionGroup) {
        return rolePermissionGroupMappingRepository.existsByRoleAndPermissionGroup(role, permissionGroup);
    }

    public boolean isRoleExist(String roleName) {
        return rolesRepository.existsByRoleName(roleName);
    }

    public boolean isGroupExist(String groupName) {
        return permissionGroupsRepository.existsByGroupName(groupName);
    }

    public boolean isSubGroupExist(String groupName) {
        return subPermissionGroupRepository.existsByGroupName(groupName);
    }

    public boolean userRoleExists(String username, String role) {
        return userRolesRepository.existsByUsernameAndRoleName(username, role);
    }

    public boolean userPermissionGroupExists(String username, String groupName) {
        return userPermissionGroupRepository.existsByUserUsernameAndPermissionGroupGroupName(username, groupName);
    }

    public UserPermissionGroup getUserPermissionGroup(String username, String groupName) {
        return userPermissionGroupRepository.findByUserUsernameAndPermissionGroupGroupName(username, groupName)
                .orElseThrow(() -> PermissionException.userNotFound(groupName));
    }

    public UserRole getUserAndRole(User user, Role role) {
        return userRolesRepository.findByUserAndRole(user, role)
                .orElseThrow(() -> PermissionException.roleNotFound(
                        String.format("Role '%s' is not assigned to user '%s'", role.getRoleName(), user.getUsername())));
    }

    public UserPermissionGroup getUserAndGroup(User user, PermissionGroup permissionGroup) {
        return userPermissionGroupRepository.findByUserAndPermissionGroup(user, permissionGroup)
                .orElseThrow(() -> PermissionException.groupNotFound(String.format(
                        "User '%s' is not assigned to permission group '%s'", user.getUsername(), permissionGroup.getGroupName())));
    }

    public void deleteUserAndGroupMapping(UserPermissionGroup userPermissionGroup) {
        userPermissionGroupRepository.delete(userPermissionGroup);
    }

    public void deleteUserAndRoleMapping(UserRole userRole) {
        userRolesRepository.delete(userRole);
    }

    public List<UserPermissionGroup> fetchAllUserPermissionGroups(PermissionGroup group) {
        List<UserPermissionGroup> userGroups = userPermissionGroupRepository.findAllByPermissionGroup(group);
        if (CollectionUtils.isEmpty(userGroups)) {
            return Collections.emptyList();
        }
        return userGroups;
    }

    public List<Role> getGroupRoles(PermissionGroup group) {
        return rolePermissionGroupMappingRepository.findRolesByPermissionGroup(group);
    }

    public void deleteSuperGroup(String groupName) {

        PermissionGroup parentGroup = permissionGroupsRepository.findByGroupName(groupName)
                .orElseThrow(() -> PermissionException.groupNotFound(groupName));

        deleteAllSubGroups(parentGroup.getKeycloakGroupId());

        rolePermissionGroupMappingRepository.deleteAllByPermissionGroup(parentGroup);
        userPermissionGroupRepository.deleteAllByPermissionGroup(parentGroup);
        permissionGroupsRepository.delete(parentGroup);
    }

    private void deleteAllSubGroups(String parentGroupId) {
        if (parentGroupId == null || parentGroupId.trim().isEmpty()) {
            return;
        }

        rolePermissionGroupMappingRepository.deleteAllByParentGroupId(parentGroupId);
        userPermissionGroupRepository.deleteAllByParentGroupId(parentGroupId);
        subPermissionGroupRepository.deleteAllByParentGroupId(parentGroupId);
    }

    public List<UserPermissionGroup> fetchAllUserPermissionGroups(String parentGroupName, String subGroupName) {

        PermissionGroup superGroup = permissionGroupsRepository.findByGroupName(parentGroupName)
                .orElseThrow(() -> PermissionException.subGroupNotFound(parentGroupName));

        if (superGroup.getKeycloakGroupId() == null) {
            throw PermissionException.keycloakServiceError("Parent group has no Keycloak ID assigned.");
        }

        SubPermissionGroup subPermissionGroup = subPermissionGroupRepository.findByGroupName(subGroupName)
                .orElseThrow(() -> PermissionException.superGroupNotFound(" for the provided subgroup name " + subGroupName));

        if (subPermissionGroup.getParentGroupId() == null) {
            throw PermissionException.keycloakServiceError("Sub group has no Parent ID assigned.");
        }

        if (!superGroup.getKeycloakGroupId().equals(subPermissionGroup.getParentGroupId())) {
            throw PermissionException.keycloakServiceError("Sub group " + subGroupName + " is not a child of super group " + parentGroupName + ".");
        }

        List<UserPermissionGroup> userGroups = userPermissionGroupRepository.findAllBySubPermissionGroup(subPermissionGroup);

        if (CollectionUtils.isEmpty(userGroups)) {
            return Collections.emptyList();
        }

        return userGroups;
    }

    public SubPermissionGroup getSubGroup(String parentGroupName, String subGroupName) {
        PermissionGroup superGroup = permissionGroupsRepository.findByGroupName(parentGroupName)
                .orElseThrow(() -> PermissionException.superGroupNotFound(" for the provided group name " + parentGroupName));

        if (superGroup.getKeycloakGroupId() == null) {
            throw PermissionException.keycloakServiceError("Parent group has no Keycloak ID assigned.");
        }

        SubPermissionGroup subPermissionGroup = subPermissionGroupRepository.findByGroupName(subGroupName)
                .orElseThrow(() -> PermissionException.subGroupNotFound(" for the provided subgroup name " + subGroupName));

        if (subPermissionGroup.getParentGroupId() == null) {
            throw PermissionException.keycloakServiceError("Sub group has no Parent ID assigned.");
        }

        if (!superGroup.getKeycloakGroupId().equals(subPermissionGroup.getParentGroupId())) {
            throw PermissionException.keycloakServiceError("Sub group " + subGroupName + " is not a child of super group " + parentGroupName + ".");
        }

        return subPermissionGroup;
    }

    public List<PermissionGroup> findUserPermissionGroups(String username) {
        List<PermissionGroup> permissionGroups = userPermissionGroupRepository.findPermissionGroupsByUsername(username);
        if (CollectionUtils.isEmpty(permissionGroups)) {
            return Collections.emptyList();
        }
        return permissionGroups;
    }

    public List<Role> findUserRoles(String username) {

        List<Role> userRoles = userRolesRepository.findRolesByUsername(username);
        if (CollectionUtils.isEmpty(userRoles)) {
            return Collections.emptyList();
        }
        return userRoles;
    }
}
