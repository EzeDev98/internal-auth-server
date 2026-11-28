package com.internal.auth.feature.rbac.service.impl;

import com.internal.auth.common.exception.PermissionErrorCode;
import com.internal.auth.common.exception.PermissionException;
import com.internal.auth.feature.rbac.model.PermissionGroup;
import com.internal.auth.feature.rbac.model.Role;
import com.internal.auth.feature.rbac.model.RolePermissionGroupMapping;
import com.internal.auth.feature.rbac.response.RoleAndPermissionGroupMappingResponse;
import com.internal.auth.feature.rbac.service.GroupRoleService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

/** Assigns and removes roles on groups. */
@Slf4j
@Service
public class GroupRoleServiceImpl implements GroupRoleService {

    private final DtoMapper mapper;
    private final EntityUtilityService utils;

    public GroupRoleServiceImpl(DtoMapper mapper, EntityUtilityService utils) {
        this.mapper = mapper;
        this.utils = utils;
    }

    @Override
    public RoleAndPermissionGroupMappingResponse assignRoleToGroup(String groupName, String roleName) {

        if (groupName == null || roleName == null) {
            throw PermissionException.emptyField("Group or role field cannot be null");
        }

        try {

            Role role = utils.getRole(roleName);
            PermissionGroup permissionGroup = utils.getPermissionGroup(groupName);

            if (utils.isRoleAndPermissionGroupMappingExisting(role, permissionGroup)) {
                throw PermissionException.alreadyExists("Role '" + roleName + "' is already assigned to group '" + groupName + "'");
            }

            RolePermissionGroupMapping groupMapping = mapRoleToGroup(groupName, roleName);
            RolePermissionGroupMapping saved = utils.saveRolePermissionGroupMapping(groupMapping);
            return mapper.buildRoleAndPermissionGroupMappingResponse(saved);

        } catch (PermissionException ex) {
            if (ex.getErrorCode() == PermissionErrorCode.ROLE_NOT_FOUND
                    || ex.getErrorCode() == PermissionErrorCode.PERMISSION_GROUP_NOT_FOUND) {
                throw PermissionException.roleNotFound(
                        "Role or permission group not found: " + roleName);
            }
            throw ex;

        } catch (DataAccessException ex) {
            throw PermissionException.groupRoleMappingFailed(
                    "Failed to successfully map role to group " + groupName);
        }
    }

    @Override
    public RoleAndPermissionGroupMappingResponse assignRoleToSubGroup(String groupName, String roleName) {

        if (groupName == null || roleName == null) {
            throw PermissionException.emptyField("Sub-group or role field cannot be null");
        }

        try {
            RolePermissionGroupMapping groupMapping = mapRoleToSubGroup(groupName, roleName);
            RolePermissionGroupMapping saved = utils.saveRolePermissionGroupMapping(groupMapping);
            return mapper.buildRoleAndPermissionGroupMappingResponse(saved);

        } catch (DataAccessException ex) {
            throw PermissionException.groupRoleMappingFailed("Failed to successfully map role to group " + groupName);
        }
    }

    private RolePermissionGroupMapping mapRoleToGroup(String groupName, String roleName) {
        RolePermissionGroupMapping mapping = new RolePermissionGroupMapping();
        mapping.setRole(utils.getRole(roleName));
        mapping.setPermissionGroup(utils.getPermissionGroup(groupName));
        mapping.setCreatedAt(LocalDateTime.now());
        return mapping;
    }

    private RolePermissionGroupMapping mapRoleToSubGroup(String groupName, String roleName) {
        RolePermissionGroupMapping mapping = new RolePermissionGroupMapping();
        mapping.setRole(utils.getRole(roleName));
        mapping.setSubPermissionGroup(utils.getSubPermissionGroupByName(groupName));
        mapping.setCreatedAt(LocalDateTime.now());
        return mapping;
    }
}
