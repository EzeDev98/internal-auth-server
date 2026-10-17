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

/**
 * Stage 2 punch-list item 3: a client application record - the "who is
 * calling this service" counterpart to User's "who is this person".
 *
 * This is data modeling only. It is NOT wired to Spring Authorization
 * Server's RegisteredClientRepository (which has its own RegisteredClient
 * domain object) - that integration is out of scope until Stage 4 per the
 * architecture assessment. Nothing in this codebase creates, reads, or
 * validates against these rows yet; there is no service or controller
 * layer for client registration. This entity exists so the shape of a
 * client application is decided and persistable ahead of that wiring.
 *
 * clientSecretHash (Stage 2 punch-list item 4): nullable on purpose - OAuth2
 * has a real concept of public clients (PKCE-only, no secret at all), and
 * forcing a non-null secret here would misrepresent that. When something
 * does write to this field, it must go through the same BCrypt
 * PasswordEncoder bean used for users.password (see WebSecurityConfig) -
 * not TokenHasher, which is for values that need direct lookup-by-hash,
 * not brute-force resistance. A client secret is more like a password than
 * a bearer token: it is compared with PasswordEncoder#matches against an
 * already-located row, never looked up by its hash directly.
 *
 * clientSecretEncrypted (admin-console secret reveal): a second,
 * reversible copy of the same raw secret, encrypted (not hashed) via
 * SecretEncryptionService - see that field's own javadoc below for why it
 * exists alongside clientSecretHash instead of replacing it.
 */
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

    /**
     * The public identifier other services/callers use to reference this
     * client (OAuth2's client_id). Distinct from the surrogate id above.
     */
    @Column(name = "client_id", nullable = false, unique = true)
    private String clientId;

    /**
     * Null for public clients (PKCE-only, no secret). See class javadoc for
     * the storage policy (BCrypt via PasswordEncoder).
     */
    @Column(name = "client_secret_hash")
    private String clientSecretHash;

    /**
     * AES-256-GCM ciphertext of the same raw secret clientSecretHash is the
     * one-way hash of (SecretEncryptionService - the same key already
     * protecting signing_key.encrypted_private_key). Purely additive and
     * never consulted for authentication - verifyClientSecret/
     * authenticateClient/ClientApplicationRegisteredClientRepository all
     * still compare against clientSecretHash exactly as before. This exists
     * only so the admin console can decrypt and display/copy a client's
     * secret on demand (matching Keycloak's Credentials tab), not just once
     * at creation/rotation time. Null for public clients and for any
     * confidential client created before this column existed - those rows
     * have no recoverable secret and must be rotated to get one.
     */
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

    /**
     * Part B (refresh-token-fix doc): true (default) = today's exact
     * behavior - UserLoginServiceImpl.refreshToken() deletes the spent
     * refresh token's OAuth2Authorization and mints a brand-new one on
     * every call (strict single-use rotation). false = non-destructive
     * refresh - only a new access token is minted; the existing refresh
     * token keeps its exact value and just has its expiry pushed forward
     * (see refreshTokenTtlDays). Admin-settable, plain boolean like
     * enabled above - no enum, so it can be surfaced directly as a form
     * field once an admin UI exists for it.
     */
    @Column(name = "refresh_token_rotation_enabled", nullable = false)
    private boolean refreshTokenRotationEnabled = true;

    /**
     * Part B: per-client override of refresh token lifetime in days. Null
     * (default) falls back to the global
     * app.authorization-server.refresh-token-ttl-days property - see
     * ClientApplicationRegisteredClientRepository#resolveRefreshTokenTtlDays
     * and UserLoginServiceImpl#resolveRefreshTokenTtl, which both read it
     * the same way. Only meaningful when refreshTokenRotationEnabled is
     * false; a rotating client's refresh token is already single-use, so
     * a long TTL on it is close to moot.
     */
    @Column(name = "refresh_token_ttl_days")
    private Integer refreshTokenTtlDays;

    /**
     * Absolute cap, in days from the original login, on a persistent
     * (non-rotating) refresh token session, however often it is used. Null
     * (default) = no cap. Only meaningful when refreshTokenRotationEnabled
     * is false. Must be >= refreshTokenTtlDays.
     */
    @Column(name = "refresh_token_max_lifetime_days")
    private Integer refreshTokenMaxLifetimeDays;

    /**
     * Part D: whether a genuinely new login (login()/verifyLoginOtp() in
     * UserLoginServiceImpl) revokes every other still-valid OAuth2Authorization
     * this user already holds for this client. true (default) preserves
     * today's exact behavior - at most one live session per user per client,
     * enforced by UserLoginServiceImpl#revokePriorAuthorizations. false lets
     * multiple devices stay signed in at once for the same user+client - for
     * clients like an offline payment terminal, where a second device (or a
     * reconnecting first device) logging in must never invalidate another
     * device's still-valid refresh token.
     */
    @Column(name = "revoke_prior_sessions_on_login", nullable = false)
    private boolean revokePriorSessionsOnLogin = true;

    /**
     * Step 17h (B-14): how many devices one user may keep signed in to this client at once. 1 (default)
     * keeps the single-session behaviour above. Above 1, a sign-in past the limit signs out the device
     * used least recently (SessionManagementServiceImpl). More than 1 requires
     * revokePriorSessionsOnLogin = false, or every sign-in would end the other devices anyway.
     */
    @Column(name = "max_active_sessions", nullable = false)
    private int maxActiveSessions = 1;

    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
}
