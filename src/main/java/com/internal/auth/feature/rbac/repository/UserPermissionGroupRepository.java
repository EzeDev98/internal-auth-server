package com.internal.auth.feature.rbac.repository;

import com.internal.auth.feature.rbac.model.PermissionGroup;
import com.internal.auth.feature.rbac.model.SubPermissionGroup;
import com.internal.auth.feature.identity.model.User;
import com.internal.auth.feature.rbac.model.UserPermissionGroup;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface UserPermissionGroupRepository extends JpaRepository<UserPermissionGroup, Long> {
    boolean existsByUserUsernameAndPermissionGroupGroupName(String username, String groupName);
    Optional<UserPermissionGroup> findByUserUsernameAndPermissionGroupGroupName(String username, String groupName);
    List<UserPermissionGroup> findAllByPermissionGroup(PermissionGroup permissionGroup);
    List<UserPermissionGroup> findAllBySubPermissionGroup(SubPermissionGroup subPermissionGroup);
    Optional<UserPermissionGroup> findByUserAndPermissionGroup(User user, PermissionGroup permissionGroup);

    @Modifying
    @Query("DELETE FROM UserPermissionGroup upg WHERE upg.permissionGroup = :group")
    void deleteAllByPermissionGroup(@Param("group") PermissionGroup group);

    @Modifying
    @Query("DELETE FROM UserPermissionGroup upg WHERE upg.subPermissionGroup.parentGroupId = :parentGroupId")
    void deleteAllByParentGroupId(@Param("parentGroupId") String parentGroupId);

    List<UserPermissionGroup> findAllByUser(User user);

    @Query("SELECT DISTINCT userPermissionGroup.permissionGroup FROM UserPermissionGroup userPermissionGroup " +
            "WHERE userPermissionGroup.user.username = :username")
    List<PermissionGroup> findPermissionGroupsByUsername(String username);
}
