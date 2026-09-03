package com.internal.auth.feature.rbac.repository;

import com.internal.auth.feature.rbac.model.PermissionGroup;
import com.internal.auth.feature.rbac.model.Role;
import com.internal.auth.feature.rbac.model.RolePermissionGroupMapping;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface RolePermissionGroupMappingRepository extends JpaRepository<RolePermissionGroupMapping, Long> {
    boolean existsByRoleAndPermissionGroup(Role role, PermissionGroup permissionGroup);

    @Query("SELECT roleGroupMapping.role FROM RolePermissionGroupMapping roleGroupMapping WHERE roleGroupMapping.permissionGroup = :group")
    List<Role> findRolesByPermissionGroup(@Param("group") PermissionGroup group);

    @Modifying
    @Query("DELETE FROM RolePermissionGroupMapping m WHERE m.permissionGroup = :group")
    void deleteAllByPermissionGroup(@Param("group") PermissionGroup group);

    @Modifying
    @Query("DELETE FROM RolePermissionGroupMapping m WHERE m.subPermissionGroup.parentGroupId = :parentGroupId")
    void deleteAllByParentGroupId(@Param("parentGroupId") String parentGroupId);
}
