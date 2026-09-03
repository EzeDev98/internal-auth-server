package com.internal.auth.feature.audit.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

/**
 * Step 14A - the audit trail's storage table. One row per auditable
 * action, written exclusively by AuditEventListener (see its Javadoc for
 * why the write happens there, via a Spring Modulith
 * {@code @ApplicationModuleListener}, rather than as a direct repository
 * call from whichever service triggered the action).
 *
 * actorUserId/actorUsername are both nullable and captured independently:
 * actorUserId is the durable cross-entity reference (a plain Long, not a
 * {@code @ManyToOne} - see User's class Javadoc for why every reference
 * added since Step 6 uses this pattern), while actorUsername is captured
 * at write time so the row still reads as something meaningful even if the
 * User row it points to is later deleted. Both are null for any action
 * with no resolved actor - none exist yet as of Step 14A, but the shape
 * allows for one later (e.g. a failed-login event where the username
 * typed doesn't resolve to a real user).
 *
 * clientApplicationId follows the same multi-tenant scoping convention as
 * every table added since Step 8/V8 - see User's class Javadoc.
 *
 * action stores {@code AuditAction.name()} as a plain string rather than a
 * DB-level enum type, so adding a new AuditAction value never requires a
 * migration.
 */
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
