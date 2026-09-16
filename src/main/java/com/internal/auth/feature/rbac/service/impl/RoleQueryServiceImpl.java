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

/**
 * Step 2C (React Admin Client plan v4). getRoleDetail's response carries
 * three distinct, separately-populated pieces of "what this role is
 * connected to" rather than one unified "permissions" list, because this
 * codebase currently has two unrelated concepts that both use the word
 * "permission":
 *
 * <p>- permissions: Role -> Permission via RolePermissionMapping (Step
 * 13A) - the traditional RBAC sense (actions this role grants). Currently
 * always empty for every role in practice - Step 13A's own Javadoc notes
 * this join is "deliberately not yet wired into ... any controller", i.e.
 * nothing in this codebase currently writes to it. Included anyway since
 * it's the semantically correct field and the join already exists - it
 * starts populating for free once a future step wires up assignment.
 *
 * <p>- permissionGroups: Role -> PermissionGroup/SubPermissionGroup via
 * RolePermissionGroupMapping - despite the name, PermissionGroup is a
 * grouping of USERS (see its class Javadoc), not a set of actions. This is
 * the actually-populated join today (via POST /groups/{groupName}/roles
 * and .../subgroups/{subGroupName}/roles) - "which user-groups have this
 * role", not "what this role can do".
 *
 * <p>- usersInRole: Role -> User via UserRole (POST /users/{username}/roles)
 * - users directly assigned the role, independent of any group membership.
 */
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
