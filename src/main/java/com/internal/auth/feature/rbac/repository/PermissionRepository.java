package com.internal.auth.feature.rbac.repository;

import com.internal.auth.feature.rbac.model.Permission;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

/**
 * Step 13A. Mirrors RolesRepository's shape - not yet used by any service
 * or controller (see Permission's class javadoc).
 */
public interface PermissionRepository extends JpaRepository<Permission, Long> {
    Optional<Permission> findByPermissionName(String permissionName);
}
