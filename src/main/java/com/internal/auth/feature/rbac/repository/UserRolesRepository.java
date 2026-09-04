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
}
