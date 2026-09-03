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
@Table(name = "roles")
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "role_name")
    private String roleName;

    @Column(name = "description")
    private String description;

    @OneToMany(mappedBy = "role", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    private List<RolePermissionGroupMapping> rolePermissionGroupMappings;

    // Step 13A - the analogous join to the new, genuinely fine-grained
    // Permission entity (see its class javadoc for how this differs from
    // PermissionGroup above). Not yet used by any service or controller.
    @OneToMany(mappedBy = "role", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    private List<RolePermissionMapping> rolePermissionMappings;

    /**
     * Step 13B - optional client-application scope. Null means this role
     * is global (visible/assignable regardless of which ClientApplication
     * (Step 8) a user belongs to) - the same thing every existing row
     * already means today. A non-null value scopes the role to exactly
     * one client application. Deliberately not enforced by any
     * repository/service/controller yet - this is the data model only,
     * mirroring Step 13A's Permission entity.
     */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "client_application_id")
    private ClientApplication clientApplication;

    @Column(name = "created_at")
    private LocalDateTime createdAt;
}
