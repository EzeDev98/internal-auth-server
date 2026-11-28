package com.internal.auth.feature.rbac.repository;

import com.internal.auth.feature.rbac.model.Permission;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

/** Repository for fine-grained permissions. */
public interface PermissionRepository extends JpaRepository<Permission, Long> {
    Optional<Permission> findByPermissionName(String permissionName);
}
