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
    @Query("DELETE FROM UserPermissionGroup upg WHERE upg.subPermissionGroup.parentGroup = :parentGroup")
    void deleteAllByParentGroup(@Param("parentGroup") PermissionGroup parentGroup);

    /**
     * Step 2D (React Admin Client plan v4): backs deleteSubGroup - removes
     * only the UserPermissionGroup rows tied to one specific subgroup, as
     * opposed to deleteAllByParentGroup above (every subgroup under a
     * parent, used when the whole parent group is deleted).
     */
    void deleteAllBySubPermissionGroup(SubPermissionGroup subPermissionGroup);

    List<UserPermissionGroup> findAllByUser(User user);

    void deleteAllByUser_Id(Long userId);

    @Query("SELECT DISTINCT userPermissionGroup.permissionGroup FROM UserPermissionGroup userPermissionGroup " +
            "WHERE userPermissionGroup.user.username = :username")
    List<PermissionGroup> findPermissionGroupsByUsername(String username);
}
