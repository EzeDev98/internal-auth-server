package com.internal.auth.feature.rbac.repository;

import com.internal.auth.feature.rbac.model.Role;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.rbac.model.UserRole;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface UserRolesRepository extends JpaRepository<UserRole, Long> {
    @Query("SELECT COUNT(userRole) > 0 FROM UserRole userRole " + "JOIN userRole.user user " + "JOIN userRole.role role " + "WHERE user.username = :username AND role.roleName = :roleName")
    boolean existsByUsernameAndRoleName(@Param("username") String username, @Param("roleName") String roleName);

    Optional<UserRole> findByUserAndRole(User user, Role role);

    @Query("SELECT DISTINCT userRole.role FROM UserRole userRole " + "WHERE userRole.user.username = :username")
    List<Role> findRolesByUsername(String username);

    void deleteAllByUser_Id(Long userId);

    /**
     * Tenant-safe alternative to {@link #findRolesByUsername(String)}: scoped
     * by the numeric user_id primary key instead of the (per-tenant, not
     * globally unique) username, so it can't match a same-named user in a
     * different client_application_id. Use this wherever the caller already
     * has a resolved, tenant-scoped User entity in hand.
     */
    @Query("SELECT DISTINCT userRole.role FROM UserRole userRole " + "WHERE userRole.user.id = :userId")
    List<Role> findRolesByUserId(@Param("userId") Long userId);

    /**
     * Admin bootstrap (AdminRegistrationServiceImpl): "does any user in the
     * whole system already hold this role" - deliberately not scoped by
     * client_application_id, consistent with RBAC being global (your
     * decision: role/group management stays inside internal-auth-server,
     * not per tenant app). Used to self-limit admin registration: open with
     * no auth required only until the first create-admin user exists.
     */
    @Query("SELECT COUNT(userRole) > 0 FROM UserRole userRole " + "JOIN userRole.role role " + "WHERE role.roleName = :roleName")
    boolean existsByRoleRoleName(@Param("roleName") String roleName);

    /**
     * Step 2C (React Admin Client plan v4): backs the Role - Detail
     * screen's "Users in role" tab (GET ${app.title}/roles/{id}). Scoped
     * by the role's numeric id rather than roleName, consistent with
     * findRolesByUserId's tenant-safety rationale above.
     */
    @Query("SELECT DISTINCT userRole.user FROM UserRole userRole WHERE userRole.role.id = :roleId")
    List<User> findUsersByRoleId(@Param("roleId") Long roleId);

    /** Backs TenantDataWipeService - batch equivalent of deleteAllByUser_Id above. */
    long deleteAllByUser_IdIn(List<Long> userIds);
}
