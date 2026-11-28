package com.internal.auth.feature.rbac.service.impl;

import com.internal.auth.common.exception.PermissionException;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.rbac.model.Permission;
import com.internal.auth.feature.rbac.model.Role;
import com.internal.auth.feature.rbac.model.RolePermissionGroupMapping;
import com.internal.auth.feature.rbac.repository.RolePermissionGroupMappingRepository;
import com.internal.auth.feature.rbac.repository.RolePermissionMappingRepository;
import com.internal.auth.feature.rbac.repository.RolesRepository;
import com.internal.auth.feature.rbac.repository.UserRolesRepository;
import com.internal.auth.feature.rbac.response.RoleDetailResponse;
import com.internal.auth.feature.rbac.response.RolePermissionSummary;
import com.internal.auth.feature.rbac.response.RoleSummaryResponse;
import com.internal.auth.feature.rbac.response.RoleUserSummary;
import com.internal.auth.feature.rbac.service.RoleQueryService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/** Queries roles with their permissions and users. */
@Service
@RequiredArgsConstructor
public class RoleQueryServiceImpl implements RoleQueryService {

    private final RolesRepository rolesRepository;
    private final RolePermissionMappingRepository rolePermissionMappingRepository;
    private final RolePermissionGroupMappingRepository rolePermissionGroupMappingRepository;
    private final UserRolesRepository userRolesRepository;

    @Override
    @Transactional(readOnly = true)
    public List<RoleSummaryResponse> listRoles() {
        return rolesRepository.findAll().stream()
                .map(this::toSummary)
                .toList();
    }

    @Override
    @Transactional(readOnly = true)
    public RoleDetailResponse getRoleDetail(Long id) {
        Role role = rolesRepository.findById(id)
                .orElseThrow(() -> PermissionException.roleNotFound("Role not found: id=" + id));

        List<Permission> permissions = rolePermissionMappingRepository.findPermissionsByRoleName(role.getRoleName());
        List<RolePermissionGroupMapping> groupMappings = rolePermissionGroupMappingRepository.findByRole(role);
        List<User> usersInRole = userRolesRepository.findUsersByRoleId(role.getId());

        return new RoleDetailResponse(
                role.getId(),
                role.getRoleName(),
                role.getDescription(),
                role.getClientApplication() == null ? null : role.getClientApplication().getId(),
                role.getCreatedAt(),
                permissions.stream()
                        .map(p -> new RolePermissionSummary(p.getId(), p.getPermissionName(), p.getDescription()))
                        .toList(),
                groupMappings.stream()
                        .map(this::toGroupLabel)
                        .toList(),
                usersInRole.stream()
                        .map(u -> new RoleUserSummary(u.getId(), u.getUsername(), u.getEmail()))
                        .toList());
    }

    private RoleSummaryResponse toSummary(Role role) {
        return new RoleSummaryResponse(
                role.getId(),
                role.getRoleName(),
                role.getDescription(),
                role.getClientApplication() == null ? null : role.getClientApplication().getId(),
                role.getCreatedAt());
    }

    private String toGroupLabel(RolePermissionGroupMapping mapping) {
        if (mapping.getSubPermissionGroup() != null) {
            return mapping.getSubPermissionGroup().getParentGroup().getGroupName() + " > " + mapping.getSubPermissionGroup().getGroupName();
        }
        if (mapping.getPermissionGroup() != null) {
            return mapping.getPermissionGroup().getGroupName();
        }
        return null;
    }
}
