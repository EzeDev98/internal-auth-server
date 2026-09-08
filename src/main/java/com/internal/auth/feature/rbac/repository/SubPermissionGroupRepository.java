package com.internal.auth.feature.rbac.repository;

import com.internal.auth.feature.rbac.model.PermissionGroup;
import com.internal.auth.feature.rbac.model.SubPermissionGroup;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface SubPermissionGroupRepository extends JpaRepository<SubPermissionGroup, Long> {
    Optional<SubPermissionGroup> findByGroupName(String groupName);
    boolean existsByGroupName(String groupName);

    /**
     * Step 2D (React Admin Client plan v4): backs GET
     * ${app.title}/groups/{id}/subgroups - the admin group directory's
     * "list every subgroup under this parent" gap (no way to enumerate
     * subgroup names today without already knowing them).
     */
    List<SubPermissionGroup> findAllByParentGroup(PermissionGroup parentGroup);

    @Modifying
    @Query("DELETE FROM SubPermissionGroup spg WHERE spg.parentGroup = :parentGroup")
    void deleteAllByParentGroup(@Param("parentGroup") PermissionGroup parentGroup);
}
