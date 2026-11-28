package com.internal.auth.feature.rbac.repository;

import com.internal.auth.feature.rbac.model.Role;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.rbac.model.UserRole;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

/** Repository for user to role mappings. */
public interface UserRolesRepository extends JpaRepository<UserRole, Long> {
    @Query("SELECT COUNT(userRole) > 0 FROM UserRole userRole " + "JOIN userRole.user user " + "JOIN userRole.role role " + "WHERE user.username = :username AND role.roleName = :roleName")
    boolean existsByUsernameAndRoleName(@Param("username") String username, @Param("roleName") String roleName);

    Optional<UserRole> findByUserAndRole(User user, Role role);

    @Query("SELECT DISTINCT userRole.role FROM UserRole userRole " + "WHERE userRole.user.username = :username")
    List<Role> findRolesByUsername(String username);

    void deleteAllByUser_Id(Long userId);

    @Query("SELECT DISTINCT userRole.role FROM UserRole userRole " + "WHERE userRole.user.id = :userId")
    List<Role> findRolesByUserId(@Param("userId") Long userId);

    @Query("SELECT COUNT(userRole) > 0 FROM UserRole userRole " + "JOIN userRole.role role " + "WHERE role.roleName = :roleName")
    boolean existsByRoleRoleName(@Param("roleName") String roleName);

    @Query("SELECT DISTINCT userRole.user FROM UserRole userRole WHERE userRole.role.id = :roleId")
    List<User> findUsersByRoleId(@Param("roleId") Long roleId);

    long deleteAllByUser_IdIn(List<Long> userIds);
}
