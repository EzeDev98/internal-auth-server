package com.internal.auth.feature.rbac.model;

import com.internal.auth.feature.identity.model.User;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

/** Links a user to a permission group. */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "user_permission_group")
public class UserPermissionGroup {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User user;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "permission_group_id")
    private PermissionGroup permissionGroup;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "sub_permission_group_id")
    private SubPermissionGroup subPermissionGroup;


    @Column(name = "created_at")
    private LocalDateTime createdAt;
}
