package com.internal.auth.feature.rbac.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.List;

/** Sub-group entity nested under a permission group. */
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

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "parent_group_id", nullable = false)
    private PermissionGroup parentGroup;


    @OneToMany(mappedBy = "subPermissionGroup", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<RolePermissionGroupMapping> rolePermissionGroupMappings;

    @Column(name = "created_at")
    private LocalDateTime createdAt;
}
