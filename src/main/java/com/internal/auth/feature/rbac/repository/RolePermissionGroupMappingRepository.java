package com.internal.auth.feature.rbac.repository;

import com.internal.auth.feature.rbac.model.PermissionGroup;
import com.internal.auth.feature.rbac.model.Role;
import com.internal.auth.feature.rbac.model.RolePermissionGroupMapping;
import com.internal.auth.feature.rbac.model.SubPermissionGroup;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

/** Repository for role to permission group mappings. */
public interface RolePermissionGroupMappingRepository extends JpaRepository<RolePermissionGroupMapping, Long> {
    boolean existsByRoleAndPermissionGroup(Role role, PermissionGroup permissionGroup);

    @Query("SELECT roleGroupMapping.role FROM RolePermissionGroupMapping roleGroupMapping WHERE roleGroupMapping.permissionGroup = :group")
    List<Role> findRolesByPermissionGroup(@Param("group") PermissionGroup group);

    @Modifying
    @Query("DELETE FROM RolePermissionGroupMapping m WHERE m.permissionGroup = :group")
    void deleteAllByPermissionGroup(@Param("group") PermissionGroup group);

    @Modifying
    @Query("DELETE FROM RolePermissionGroupMapping m WHERE m.subPermissionGroup.parentGroup = :parentGroup")
    void deleteAllByParentGroup(@Param("parentGroup") PermissionGroup parentGroup);

    void deleteAllBySubPermissionGroup(SubPermissionGroup subPermissionGroup);

    @Query("SELECT m FROM RolePermissionGroupMapping m WHERE m.role = :role")
    List<RolePermissionGroupMapping> findByRole(@Param("role") Role role);
}
