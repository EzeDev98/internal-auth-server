package com.internal.auth.feature.rbac.repository;

import com.internal.auth.feature.rbac.model.PermissionScope;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PermissionScopesRepository extends JpaRepository<PermissionScope, Long> {
}
