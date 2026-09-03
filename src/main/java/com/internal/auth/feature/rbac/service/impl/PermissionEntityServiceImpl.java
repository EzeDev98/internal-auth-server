package com.internal.auth.feature.rbac.service.impl;

import com.internal.auth.common.exception.PermissionException;
import com.internal.auth.common.response.BaseResponse;
import com.internal.auth.feature.rbac.model.PermissionGroup;
import com.internal.auth.feature.rbac.model.Role;
import com.internal.auth.feature.rbac.model.SubPermissionGroup;
import com.internal.auth.feature.rbac.model.UserPermissionGroup;
import com.internal.auth.feature.rbac.response.*;
import com.internal.auth.feature.rbac.service.PermissionEntityService;
import io.micrometer.common.util.StringUtils;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class PermissionEntityServiceImpl implements PermissionEntityService {

    private final EntityUtilityService entityUtils;
    private final DtoMapper mapper;

    @Autowired
    public PermissionEntityServiceImpl(EntityUtilityService entityUtils, DtoMapper mapper) {
        this.entityUtils = entityUtils;
        this.mapper = mapper;
    }

    @Override
    public RoleResponse createRole(String roleName, String description) {

        if (entityUtils.isRoleExist(roleName)) {
            throw PermissionException.alreadyExists("Role already exists in the database");
        }

        Role newRole = createNewRole(roleName, description);
        try {
            Role savedRole = entityUtils.saveRole(newRole);
            return mapper.buildRoleResponse(savedRole);
        } catch (DataAccessException ex) {
            throw PermissionException.rolePersistenceFailed("Failed to save role to database");
        }
    }

    private Role createNewRole(String roleName, String description) {
        Role newRole = new Role();
        newRole.setRoleName(roleName);
        newRole.setDescription(description);
        newRole.setCreatedAt(LocalDateTime.now());
        return newRole;
    }

    @Override
    public GroupCreationResponse createSuperGroup(String groupName, String description) {

        if (entityUtils.isGroupExist(groupName)) {
            throw PermissionException.alreadyExists("Group already exists in the database");
        }

        PermissionGroup group = createGroup(groupName, description);
        try {
            PermissionGroup savedGroup = entityUtils.savePermissionGroup(group);
            return mapper.buildPermissionGroupResponse(savedGroup);
        } catch (DataAccessException ex) {
            throw PermissionException.groupPersistenceFailed("Failed to save group to database");
        }
    }

    private PermissionGroup createGroup(String groupName, String description) {
        PermissionGroup permissionGroup = new PermissionGroup();
        permissionGroup.setGroupName(groupName);
        permissionGroup.setDescription(description);
        permissionGroup.setCreatedAt(LocalDateTime.now());
        return permissionGroup;
    }

    @Override
    public SubGroupCreationResponse createSubGroup(String groupName, String description, String parentGroupName) {

        if (entityUtils.isSubGroupExist(groupName)) {
            throw PermissionException.alreadyExists("Subgroup already exists in the database");
        }

        PermissionGroup parentGroup = entityUtils.getPermissionGroup(parentGroupName);
        SubPermissionGroup group = createGroup(groupName, description, parentGroup);
        try {
            SubPermissionGroup savedGroup = entityUtils.saveSubPermissionGroup(group);
            return mapper.buildSubPermissionGroupResponse(savedGroup);
        } catch (DataAccessException ex) {
            throw PermissionException.subGroupPersistenceFailed(groupName);
        }
    }

    private SubPermissionGroup createGroup(String groupName, String description, PermissionGroup parentGroup) {
        SubPermissionGroup subGroup = new SubPermissionGroup();
        subGroup.setGroupName(groupName);
        subGroup.setDescription(description);
        subGroup.setParentGroup(parentGroup);
        subGroup.setCreatedAt(LocalDateTime.now());
        return subGroup;
    }

    @Override
    @Transactional
    public BaseResponse getPermissionGroupUsersByGroupName(String groupName) {
        PermissionGroup permissionGroup = entityUtils.getPermissionGroup(groupName);
        List<UserPermissionGroup> userPermissionGroups = entityUtils.fetchAllUserPermissionGroups(permissionGroup);
        GroupResponse permissionGroupResponse = mapper.createUserPermissionGroupResponseForSuperGroup(permissionGroup, userPermissionGroups);
        return new BaseResponse(HttpServletResponse.SC_OK, "Operation successful", permissionGroupResponse);
    }

    @Override
    @Transactional
    public BaseResponse getSubPermissionGroupUsersByGroupName(String superGroupName, String subGroupName) {
        List<UserPermissionGroup> userPermissionGroups = entityUtils.fetchAllUserPermissionGroups(superGroupName, subGroupName);
        SubGroupResponse subPermissionGroupResponse = mapper.createUserPermissionGroupResponseForSubGroup(userPermissionGroups);
        return new BaseResponse(HttpServletResponse.SC_OK, "Operation successful", subPermissionGroupResponse);
    }

    @Override
    public void deleteSuperGroup(String groupName) {
        try {
            entityUtils.deleteSuperGroup(groupName);
        } catch (Exception ex) {
            throw PermissionException.internalError("An unexpected error occurred during group deletion");
        }
    }

    @Override
    public BaseResponse getSubGroupByName(String parentGroupName, String subGroupName) {

        if (StringUtils.isBlank(parentGroupName) || StringUtils.isBlank(subGroupName)) {
            throw PermissionException.emptyField("Parent group name and sub group name fields are mandatory");
        }
        SubPermissionGroup subGroup = entityUtils.getSubGroup(parentGroupName, subGroupName);
        return new BaseResponse(HttpServletResponse.SC_OK, "Subgroup retrieved successfully", subGroup);
    }

    @Override
    public BaseResponse retrieveUserGroups(String username) {
        if (StringUtils.isBlank(username)) {
            throw PermissionException.emptyField("Username field is mandatory");
        }

        List<PermissionGroup> permissionGroups = entityUtils.findUserPermissionGroups(username);
        List<PermissionGroupResponse> permissionGroupResponses = mapper.buildUserGroupsResponse(permissionGroups);

        return new BaseResponse(HttpServletResponse.SC_OK, "Operation successful", permissionGroupResponses);
    }

    @Override
    public BaseResponse retrieveUserRoles(String username) {
        if (StringUtils.isBlank(username)) {
            throw PermissionException.emptyField("Username field is mandatory");
        }

        List<Role> roles = entityUtils.findUserRoles(username);
        List<RoleResponse> roleResponses = mapper.buildUserRoleResponse(roles);

        return new BaseResponse(HttpServletResponse.SC_OK, "Operation successful", roleResponses);
    }

}