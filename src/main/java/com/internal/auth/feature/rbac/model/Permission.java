package com.internal.auth.feature.rbac.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Step 13A - a genuinely fine-grained permission (an action on a resource,
 * e.g. NOTE_CREATE, TRANSACTION_VIEW), distinct from PermissionGroup -
 * which, despite the name, is actually a grouping of USERS (a
 * team/org-unit concept), not a set of actions. See PermissionGroup's own
 * javadoc/table for the existing shape this is deliberately not touching.
 *
 * <p>Deliberately not yet wired into PermissionManagementServiceImpl, any
 * controller, or the JWT roles claim (SelfIssuedJwtRolesConverter) - that
 * control-flow rewrite is Step 13C's job. This step only adds the data
 * model: Permission itself and its join to Role (RolePermissionMapping),
 * mirroring RolePermissionGroupMapping's existing shape (which links Role
 * to PermissionGroup/SubPermissionGroup instead).
 *
 * <p>permissionName is a single flat identifier (e.g. "NOTE_CREATE"),
 * matching the existing single-string convention Role.roleName and
 * PermissionGroup.groupName already use, rather than splitting into
 * separate resource/action columns - keeps this step's scope to "add the
 * entity" rather than committing to a structured resource/action querying
 * model before anything actually needs one (that's a 13C-era decision, if
 * it turns out to be needed at all).
 */
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
