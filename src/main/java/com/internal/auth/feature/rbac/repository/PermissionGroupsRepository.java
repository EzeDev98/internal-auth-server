package com.internal.auth.feature.rbac.repository;

import com.internal.auth.feature.rbac.model.PermissionGroup;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

/** Repository for permission groups. */
public interface PermissionGroupsRepository extends JpaRepository<PermissionGroup, Long> {
    Optional<PermissionGroup> findByGroupName(String groupName);
    boolean existsByGroupName(String groupName);
}
