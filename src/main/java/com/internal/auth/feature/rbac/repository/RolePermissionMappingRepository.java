package com.internal.auth.feature.rbac.repository;

import com.internal.auth.feature.rbac.model.Permission;
import com.internal.auth.feature.rbac.model.Role;
import com.internal.auth.feature.rbac.model.RolePermissionMapping;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

/** Repository for role to permission mappings. */
public interface RolePermissionMappingRepository extends JpaRepository<RolePermissionMapping, Long> {
    Optional<RolePermissionMapping> findByRoleAndPermission(Role role, Permission permission);

    @Query("SELECT DISTINCT rpm.permission FROM RolePermissionMapping rpm " + "WHERE rpm.role.roleName = :roleName")
    List<Permission> findPermissionsByRoleName(@Param("roleName") String roleName);
}
