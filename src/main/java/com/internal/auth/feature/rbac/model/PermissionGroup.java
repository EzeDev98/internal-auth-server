package com.internal.auth.feature.rbac.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;
import com.internal.auth.feature.client.model.ClientApplication;
import java.util.List;

/** Permission group entity. */
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

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "client_application_id")
    private ClientApplication clientApplication;

    @Column(name = "created_at")
    private LocalDateTime createdAt;
}
