package com.internal.auth.feature.client.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

/** Client application (tenant) entity. */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "client_applications")
@org.springframework.modulith.NamedInterface
public class ClientApplication {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "client_id", nullable = false, unique = true)
    private String clientId;

    @Column(name = "client_secret_hash")
    private String clientSecretHash;

    @Column(name = "client_secret_encrypted", columnDefinition = "TEXT")
    private String clientSecretEncrypted;

    @Column(name = "name", nullable = false)
    private String name;

    @Column(name = "description", length = 1000)
    private String description;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(
            name = "client_application_redirect_uris",
            joinColumns = @JoinColumn(name = "client_application_id")
    )
    @Column(name = "redirect_uri", nullable = false)
    private Set<String> redirectUris = new HashSet<>();

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(
            name = "client_application_scopes",
            joinColumns = @JoinColumn(name = "client_application_id")
    )
    @Column(name = "scope", nullable = false)
    private Set<String> scopes = new HashSet<>();

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(
            name = "client_application_grant_types",
            joinColumns = @JoinColumn(name = "client_application_id")
    )
    @Column(name = "grant_type", nullable = false)
    private Set<String> grantTypes = new HashSet<>();

    @Column(name = "enabled", nullable = false)
    private boolean enabled = true;

    @Column(name = "refresh_token_rotation_enabled", nullable = false)
    private boolean refreshTokenRotationEnabled = true;

    @Column(name = "refresh_token_ttl_days")
    private Integer refreshTokenTtlDays;

    @Column(name = "refresh_token_max_lifetime_days")
    private Integer refreshTokenMaxLifetimeDays;

    @Column(name = "revoke_prior_sessions_on_login", nullable = false)
    private boolean revokePriorSessionsOnLogin = true;

    @Column(name = "max_active_sessions", nullable = false)
    private int maxActiveSessions = 1;

    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
}
