package com.internal.auth.feature.audit.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

/** Audit log entity. */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "audit_log")
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "actor_user_id")
    private Long actorUserId;

    @Column(name = "actor_username")
    private String actorUsername;

    @Column(name = "client_application_id")
    private Long clientApplicationId;

    @Column(name = "action", nullable = false)
    private String action;

    @Column(name = "description", length = 1000)
    private String description;

    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;
}
