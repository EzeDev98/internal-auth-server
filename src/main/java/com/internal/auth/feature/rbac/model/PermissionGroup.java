package com.internal.auth.feature.rbac.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;
import com.internal.auth.feature.client.model.ClientApplication;
import java.util.List;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "permission_groups")
public class PermissionGroup {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "group_name")
    private String groupName;

    @Column(name = "description")
    private String description;


    @OneToMany(mappedBy = "permissionGroup", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    private List<RolePermissionGroupMapping> rolePermissionGroupMappings;

    /**
     * Step 13B - optional client-application scope. Null means this group
     * is global (visible/assignable regardless of which ClientApplication
     * (Step 8) a user belongs to) - the same thing every existing row
     * already means today. A non-null value scopes the group to exactly
     * one client application. Deliberately not enforced by any
     * repository/service/controller yet - this is the data model only,
     * mirroring Step 13A's Permission entity. SubPermissionGroup is
     * deliberately not touched by this step.
     */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "client_application_id")
    private ClientApplication clientApplication;

    @Column(name = "created_at")
    private LocalDateTime createdAt;
}
