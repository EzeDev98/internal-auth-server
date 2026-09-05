package com.internal.auth.feature.rbac.repository;

import com.internal.auth.feature.rbac.model.Role;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface RolesRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByRoleName(String roleName);

    /**
     * Step 5 (admin bootstrap race fix): pessimistic row lock (SELECT ...
     * FOR UPDATE) on the named Role row, held for the rest of the caller's
     * transaction. Used to serialize concurrent admin-bootstrap attempts in
     * AdminRegistrationServiceImpl so "does an admin already exist" and the
     * resulting insert happen atomically as a group, instead of two
     * concurrent requests both reading "no admin yet" before either
     * commits. Must be called inside an active transaction.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT role FROM Role role WHERE role.roleName = :roleName")
    Optional<Role> findByRoleNameForUpdate(@Param("roleName") String roleName);
    @Query("SELECT role FROM Role role WHERE role.roleName IN :roleNames")
    List<Role> findByRoleNames(@Param("roleNames") List<String> roleNames);
    boolean existsByRoleName(String roleName);
}
