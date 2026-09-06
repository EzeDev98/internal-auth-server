package com.internal.auth.feature.identity.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;

/**
 * Local Identity record - Stage 2 "Identity Foundation" entity (Stage 1
 * assessment section 14, item 9 / Stage 2 punch-list item 1).
 *
 * Moved here from feature.rbac.model, where it lived only as a stopgap so
 * existing RBAC callers (UserPermissionGroup, UserRole, DtoMapper,
 * EntityUtilityService, PasswordResetServiceImpl, etc.) had something to
 * compile against. Those callers now import this class from its new
 * package.
 *
 * `keycloakId` and the "wmUniqueId" field (`uniqueId`) have been removed
 * (Stage 2 item 1 follow-up) - this app does not use Keycloak, and
 * wmUniqueId had no purpose beyond duplicating what `username` already
 * provides as the one non-null unique identifier. Every former wmUniqueId
 * lookup (GET /groups/users/{wmUniqueId}, GET /roles/users/{wmUniqueId},
 * AuthenticationHelper#requireSelfOrAdmin) now keys off `username` instead.
 *
 * `phoneNumber` and `email` are both optional at the column level, but at
 * least one must be present - enforced by a DB CHECK constraint (see V1
 * migration's ck_users_phone_or_email) and, since Step 10A, also by
 * RegistrationValidator#validateContactInfoPresent at the application
 * level.
 *
 * `enabled`, `emailVerified` and `phoneVerified`: `enabled` defaults true
 * (Step 10A registers users active immediately, per that step's scoping
 * decision - verification does not gate account creation). `emailVerified`
 * and `phoneVerified` both default false and are set by dedicated
 * verification flows, not by registration itself.
 *
 * Step 10C built email verification (a token/link sent to `email`,
 * EmailVerificationServiceImpl sets `emailVerified` on success). No
 * equivalent phone-verification flow exists yet as of this writing.
 *
 * Step 10E (decision, enforced by Step 11A's login endpoint): login
 * strictly gates on verification, per-field, for whichever contact methods
 * are actually present on the row. An email-only account needs
 * emailVerified=true to log in; a phone-only account needs
 * phoneVerified=true; an account with both needs both true. Known,
 * accepted consequence: since no phone-verification flow exists yet, a
 * phone-only account cannot satisfy this gate today.
 *
 * `mfaEnabled` (Step 11E): opt-in login step-up via SMS OTP, off by
 * default. Only meaningful for an account with a phoneNumber on file - the
 * channel is SMS, so MfaAdminServiceImpl refuses to enable it otherwise.
 * Toggled by an admin (MfaAdminController) rather than self-service for
 * now, since local login (Step 11A) issues no token yet for a user to
 * authenticate a follow-up request with - see that controller's Javadoc.
 *
 * `clientApplicationId` (multi-tenant user namespace redesign, schema/model
 * step - see V8 migration): each integrating app (SyncPoint, Notare, ...)
 * gets its own isolated namespace. username/phoneNumber/email are unique
 * only within one client_application_id now, not globally - see this
 * class's @Table(uniqueConstraints = ...) below, which replaces the old
 * per-column unique=true (that alone would have kept dev, which runs
 * Hibernate ddl-auto=update directly against MySQL with Flyway disabled,
 * silently enforcing GLOBAL uniqueness while prod enforced per-app
 * uniqueness via this migration - table-level constraints keep dev and
 * prod consistent). Plain Long FK field rather than a @ManyToOne relation,
 * consistent with every other cross-entity reference added since Stage 2
 * (UserSession.userId, PasswordResetOtp.userId, EmailVerificationToken.userId,
 * etc.) - RBAC's older entities use real JPA relations, but nothing built
 * since Step 6 does.
 *
 * NOTE - transient state: RegistrationServiceImpl/LoginServiceImpl and
 * UserRepository's findByUsername/findByPhoneNumber/findByEmail have NOT
 * been updated to scope by clientApplicationId yet (that's the next step).
 * Those three finders are UNSAFE the moment two different apps register
 * the same username/phone/email - do not exercise that scenario until the
 * registration/login step lands.
 */
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

    /** FK to ClientApplication.id (see V8 migration). */
    @Column(name = "client_application_id", nullable = false)
    private Long clientApplicationId;

    @Column(name = "username", nullable = false)
    private String username;

    @Column(name = "phone_number")
    private String phoneNumber;

    @Column(name = "email")
    private String email;

    /**
     * BCrypt hash - never the raw password. See PasswordResetServiceImpl,
     * RegistrationServiceImpl.
     */
    @Column(name = "password")
    private String password;

    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    /**
     * Set alongside `password` whenever it changes (see
     * PasswordResetServiceImpl#completeReset). Null means "never changed
     * since account creation" - kept distinct from createdAt so a future
     * password-age policy has something to check.
     */
    @Column(name = "password_changed_at")
    private LocalDateTime passwordChangedAt;

    @Column(name = "enabled", nullable = false)
    private boolean enabled = true;

    @Column(name = "email_verified", nullable = false)
    private boolean emailVerified = false;

    @Column(name = "phone_verified", nullable = false)
    private boolean phoneVerified = false;

    @Column(name = "mfa_enabled", nullable = false)
    private boolean mfaEnabled = false;
}
