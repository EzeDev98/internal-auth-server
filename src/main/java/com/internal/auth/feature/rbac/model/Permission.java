package com.internal.auth.feature.rbac.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.List;

/** Fine-grained permission entity describing an action on a resource. */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "permissions")
public class Permission {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "permission_name")
    private String permissionName;

    @Column(name = "description")
    private String description;

    @OneToMany(mappedBy = "permission", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    private List<RolePermissionMapping> rolePermissionMappings;

    @Column(name = "created_at")
    private LocalDateTime createdAt;
}
