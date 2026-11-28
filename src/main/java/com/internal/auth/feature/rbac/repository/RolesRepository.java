package com.internal.auth.feature.rbac.repository;

import com.internal.auth.feature.rbac.model.Role;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

/** Repository for roles. */
public interface RolesRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByRoleName(String roleName);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT role FROM Role role WHERE role.roleName = :roleName")
    Optional<Role> findByRoleNameForUpdate(@Param("roleName") String roleName);
    @Query("SELECT role FROM Role role WHERE role.roleName IN :roleNames")
    List<Role> findByRoleNames(@Param("roleNames") List<String> roleNames);
    boolean existsByRoleName(String roleName);
}
