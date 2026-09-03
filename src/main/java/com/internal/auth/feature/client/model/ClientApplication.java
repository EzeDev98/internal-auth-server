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
 */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "client_applications")
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

    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
}
