package com.internal.auth.feature.identity.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;

/** User identity entity. */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "users", uniqueConstraints = {
        @UniqueConstraint(name = "uk_users_client_username", columnNames = {"client_application_id", "username"}),
        @UniqueConstraint(name = "uk_users_client_phone_number", columnNames = {"client_application_id", "phone_number"}),
        @UniqueConstraint(name = "uk_users_client_email", columnNames = {"client_application_id", "email"})
})
@org.springframework.modulith.NamedInterface
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "internal_auth_user_id", nullable = false)
    private String internalAuthUserId;

    @Column(name = "client_application_id", nullable = false)
    private Long clientApplicationId;

    @Column(name = "username", nullable = false)
    private String username;

    @Column(name = "phone_number")
    private String phoneNumber;

    @Column(name = "email")
    private String email;

    @Column(name = "password")
    private String password;

    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @Column(name = "password_changed_at")
    private LocalDateTime passwordChangedAt;

    @Column(name = "enabled", nullable = false)
    private boolean enabled = true;

    @Column(name = "email_verified", nullable = false)
    private boolean emailVerified = false;

    @Column(name = "phone_verified", nullable = false)
    private boolean phoneVerified = false;
}
