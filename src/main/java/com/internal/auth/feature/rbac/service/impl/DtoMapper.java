package com.internal.auth.feature.rbac.service.impl;

import com.internal.auth.common.exception.PermissionException;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.rbac.model.*;
import com.internal.auth.feature.rbac.repository.UserPermissionGroupRepository;
import com.internal.auth.feature.rbac.response.*;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/** Maps RBAC entities to response objects. */
@Component
public class DtoMapper {

    private final UserPermissionGroupRepository userPermissionGroupRepository;

    public DtoMapper(UserPermissionGroupRepository userPermissionGroupRepository) {
        this.userPermissionGroupRepository = userPermissionGroupRepository;
    }

    public GroupResponse createUserPermissionGroupResponseForSuperGroup(PermissionGroup permissionGroup, List<UserPermissionGroup> userGroups) {

        if (permissionGroup == null) {
            throw PermissionException.permissionGroupNotFound("Permission group not found");
        }

        GroupResponse groupResponse = new GroupResponse();
        groupResponse.setGroupId(permissionGroup.getId());
        groupResponse.setGroupName(permissionGroup.getGroupName());
        groupResponse.setDescription(permissionGroup.getDescription());
        groupResponse.setRoles(createRoleResponses(permissionGroup));

        if (CollectionUtils.isEmpty(userGroups)) {
            groupResponse.setUserResponses(Collections.emptyList());
        } else {
            groupResponse.setUserResponses(createGroupedUserResponse(userGroups));
        }

        return groupResponse;
    }

    public SubGroupResponse createUserPermissionGroupResponseForSubGroup(List<UserPermissionGroup> userGroups) {
        if (CollectionUtils.isEmpty(userGroups)) {
            throw PermissionException.emptyField("User groups list cannot be empty");
        }

        SubPermissionGroup subPermissionGroup = userGroups.get(0).getSubPermissionGroup();
        if (subPermissionGroup == null) {
            throw PermissionException.subGroupNotFound("Sub permission group not found in user permission group mapping");
        }

        SubGroupResponse groupResponse = new SubGroupResponse();
        groupResponse.setSubGroupId(subPermissionGroup.getId());
        groupResponse.setSubgroupName(subPermissionGroup.getGroupName());
        groupResponse.setDescription(subPermissionGroup.getDescription());
        groupResponse.setRoles(createRoleResponses(subPermissionGroup));
        groupResponse.setUserResponses(createGroupedUserResponse(userGroups));

        return groupResponse;
    }

    private List<AssociatedRolesResponse> createRoleResponses(PermissionGroup group) {

        List<Role> roles = group.getRolePermissionGroupMappings().stream().map(RolePermissionGroupMapping::getRole)
                .collect(Collectors.toList());

        if (CollectionUtils.isEmpty(roles)) {
            return Collections.emptyList();
        }

        List<AssociatedRolesResponse> rolesResponses = new ArrayList<>();
        for (Role role : roles) {
            rolesResponses.add(createRoleResponse(role));
        }

        return rolesResponses;
    }

    private List<AssociatedRolesResponse> createRoleResponses(SubPermissionGroup group) {

        List<Role> roles = group.getRolePermissionGroupMappings().stream().map(RolePermissionGroupMapping::getRole)
                .collect(Collectors.toList());

        if (CollectionUtils.isEmpty(roles)) {
            return Collections.emptyList();
        }

        List<AssociatedRolesResponse> rolesResponses = new ArrayList<>();
        for (Role role : roles) {
            rolesResponses.add(createRoleResponse(role));
        }

        return rolesResponses;
    }

    private List<GroupedUserResponse> createGroupedUserResponse(List<UserPermissionGroup> userGroups) {

        List<User> users = userGroups.stream()
                .map(UserPermissionGroup::getUser)
                .toList();

        if (CollectionUtils.isEmpty(users)) {
            return Collections.emptyList();
        }

        List<GroupedUserResponse> userResponses = new ArrayList<>();
        for (User user : users) {
            userResponses.add(createUserResponse(user));
        }

        return userResponses;
    }

    private AssociatedRolesResponse createRoleResponse(Role role) {
        AssociatedRolesResponse roleResponse = new AssociatedRolesResponse();
        roleResponse.setId(role.getId());
        roleResponse.setRoleName(role.getRoleName());
        roleResponse.setDescription(role.getDescription());
        return roleResponse;
    }

    private GroupedUserResponse createUserResponse(User user) {
        GroupedUserResponse userResponse = new GroupedUserResponse();
        userResponse.setUserId(user.getId());
        userResponse.setUsername(user.getUsername());
        userResponse.setEmail(user.getEmail());
        userResponse.setMembership(buildMembershipPaths(user));
        return userResponse;
    }

    private String buildMembershipPaths(User user) {
        List<UserPermissionGroup> memberships = userPermissionGroupRepository.findAllByUser(user);
        if (CollectionUtils.isEmpty(memberships)) {
            return "";
        }
        return memberships.stream()
                .map(this::formatMembershipPath)
                .filter(StringUtils::isNotBlank)
                .distinct()
                .collect(Collectors.joining(", "));
    }

    private String formatMembershipPath(UserPermissionGroup membership) {
        SubPermissionGroup subGroup = membership.getSubPermissionGroup();
        if (subGroup != null) {
            String parentName = subGroup.getParentGroup() != null ? subGroup.getParentGroup().getGroupName() : "";
            return "/" + parentName + "/" + subGroup.getGroupName();
        }
        if (membership.getPermissionGroup() != null) {
            return "/" + membership.getPermissionGroup().getGroupName();
        }
        return "";
    }

    public GroupCreationResponse buildPermissionGroupResponse(PermissionGroup group) {
        GroupCreationResponse newGroupResponse = new GroupCreationResponse();
        newGroupResponse.setGroupId(group.getId());
        newGroupResponse.setGroupName(group.getGroupName());
        newGroupResponse.setDescription(group.getDescription());
        return newGroupResponse;
    }

    public SubGroupCreationResponse buildSubPermissionGroupResponse(SubPermissionGroup group) {
        SubGroupCreationResponse newGroupResponse = new SubGroupCreationResponse();
        newGroupResponse.setGroupId(group.getId());
        newGroupResponse.setGroupName(group.getGroupName());
        newGroupResponse.setDescription(group.getDescription());
        newGroupResponse.setSuperGroupId(group.getParentGroup().getId());
        return newGroupResponse;
    }

    public RoleResponse buildRoleResponse(Role role) {
        RoleResponse newRoleResponse = new RoleResponse();
        newRoleResponse.setRoleId(role.getId());
        newRoleResponse.setRoleName(role.getRoleName());
        newRoleResponse.setDescription(role.getDescription());
        return newRoleResponse;
    }

    public RoleAndPermissionGroupMappingResponse buildRoleAndPermissionGroupMappingResponse(RolePermissionGroupMapping mapping) {
        RoleAndPermissionGroupMappingResponse response = new RoleAndPermissionGroupMappingResponse();
        response.setId(mapping.getId());
        response.setGroupName(mapping.getPermissionGroup() != null
                ? mapping.getPermissionGroup().getGroupName()
                : mapping.getSubPermissionGroup().getGroupName());
        response.setRoleName(mapping.getRole().getRoleName());
        return response;
    }

    public UserRoleResponse buildUserRole(UserRole role) {
        UserRoleResponse response = new UserRoleResponse();
        response.setId(role.getId());
        response.setUserId(role.getUser().getId());
        response.setRoleId(role.getRole().getId());
        return response;
    }

    public List<UserPermissionGroupResponse> buildUserPermissionGroups(List<UserPermissionGroup> groups) {

        if (CollectionUtils.isEmpty(groups)) {
            return Collections.emptyList();
        }

        List<UserPermissionGroupResponse> userPermissionGroupResponses = new ArrayList<>();
        for (UserPermissionGroup group : groups) {
            userPermissionGroupResponses.add(buildUserPermissionGroup(group));
        }

        return userPermissionGroupResponses;
    }

    public UserPermissionGroupResponse buildUserPermissionGroup(UserPermissionGroup group) {

        if (group == null) {
            throw PermissionException.emptyRequest("UserPermissionGroup cannot be null");
        }

        UserPermissionGroupResponse response = new UserPermissionGroupResponse();
        response.setId(group.getId());

        if (group.getUser() != null) {
            response.setUserId(group.getUser().getId());
        }

        if (group.getPermissionGroup() != null && group.getPermissionGroup().getId() != null) {
            response.setGroupId(group.getPermissionGroup().getId());
        }

        return response;
    }

    public UserSubPermissionGroupResponse buildUserSubPermissionGroup(UserPermissionGroup group) {

        if (group == null) {
            throw PermissionException.emptyRequest("UserPermissionGroup cannot be null");
        }

        UserSubPermissionGroupResponse response = new UserSubPermissionGroupResponse();
        response.setId(group.getId());

        if (group.getUser() != null) {
            response.setUserId(group.getUser().getId());
        }

        if (group.getPermissionGroup() != null && group.getPermissionGroup().getId() != null) {
            response.setGroupId(group.getPermissionGroup().getId());
        }

        if (group.getSubPermissionGroup() != null && group.getSubPermissionGroup().getId() != null) {
            response.setSubGroupId(group.getSubPermissionGroup().getId());
        }

        return response;
    }

    public List<PermissionGroupResponse> buildUserGroupsResponse(List<PermissionGroup> permissionGroups) {
        if (CollectionUtils.isEmpty(permissionGroups)) {
            return Collections.emptyList();
        }

        List<PermissionGroupResponse> permissionGroupResponses = new ArrayList<>();

        for (PermissionGroup permissionGroup : permissionGroups) {
            PermissionGroupResponse permissionGroupResponse = new PermissionGroupResponse();
            permissionGroupResponse.setGroupId(permissionGroup.getId());
            permissionGroupResponse.setGroupName(permissionGroup.getGroupName());
            permissionGroupResponse.setDescription(permissionGroup.getDescription());

            permissionGroupResponses.add(permissionGroupResponse);
        }

        return permissionGroupResponses;
    }

    public List<RoleResponse> buildUserRoleResponse(List<Role> roles) {

        if (CollectionUtils.isEmpty(roles)) {
            return Collections.emptyList();
        }

        List<RoleResponse> roleResponses = new ArrayList<>();
        for (Role role : roles) {

            RoleResponse roleResponse = new RoleResponse();
            roleResponse.setRoleId(role.getId());
            roleResponse.setRoleName(role.getRoleName());
            roleResponse.setDescription(role.getDescription());
            roleResponses.add(roleResponse);
        }

        return roleResponses;
    }
}
