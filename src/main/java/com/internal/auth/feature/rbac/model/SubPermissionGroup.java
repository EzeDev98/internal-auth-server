package com.internal.auth.feature.rbac.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.List;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "sub_permission_group")
public class SubPermissionGroup {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "group_name")
    private String groupName;

    @Column(name = "description")
    private String description;

    /**
     * Step 13D - real FK to the parent PermissionGroup, replacing the old
     * Keycloak-ID string match (parentGroupId used to be compared against
     * PermissionGroup.keycloakGroupId, which every group now always has as
     * null since Step 13C's control-flow rewrite stopped calling Keycloak
     * at all - that comparison was silently broken for every subgroup
     * created under current code).
     */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "parent_group_id", nullable = false)
    private PermissionGroup parentGroup;


    @OneToMany(mappedBy = "subPermissionGroup", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<RolePermissionGroupMapping> rolePermissionGroupMappings;

    @Column(name = "created_at")
    private LocalDateTime createdAt;
}
