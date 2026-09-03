package com.internal.auth.feature.rbac.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

/**
 * Step 13A - links a Role to a fine-grained Permission, mirroring
 * RolePermissionGroupMapping's shape (which links Role to
 * PermissionGroup/SubPermissionGroup instead). See Permission's class
 * javadoc for why this join exists and what it deliberately doesn't do
 * yet (no service/controller/JWT wiring - that's Step 13C).
 */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "role_permission_mapping")
public class RolePermissionMapping {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "role_id")
    private Role role;

    @ManyToOne
    @JoinColumn(name = "permission_id")
    private Permission permission;

    @Column(name = "created_at")
    private LocalDateTime createdAt;
}
