package com.internal.auth.feature.rbac.repository;

import com.internal.auth.feature.rbac.model.PermissionGroup;
import com.internal.auth.feature.rbac.model.SubPermissionGroup;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface SubPermissionGroupRepository extends JpaRepository<SubPermissionGroup, Long> {
    Optional<SubPermissionGroup> findByGroupName(String groupName);
    boolean existsByGroupName(String groupName);

    @Modifying
    @Query("DELETE FROM SubPermissionGroup spg WHERE spg.parentGroup = :parentGroup")
    void deleteAllByParentGroup(@Param("parentGroup") PermissionGroup parentGroup);
}
