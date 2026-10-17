package com.internal.auth.feature.session.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

/**
 * Stage 2 punch-list item 4 (credential storage policy): tokenHash is a
 * SHA-256 hash (see TokenHasher), never the raw bearer JWT - a leaked copy
 * of this table must not hand out live, replayable session tokens.
 *
 * Step 11B: phoneNumber is optional, informational-only data - never a
 * lookup key. It used to be NOT NULL and the sole lookup key
 * (findByPhoneNumberAndIsActiveTrue), which silently broke session
 * tracking for any email-only user once phone number became optional on
 * User (Stage 2): JwtSessionTrackingFilter would pass a null phoneNumber
 * into createSession, the NOT NULL column would reject the INSERT, and the
 * filter swallows that exception by design - so tracking just silently
 * never worked for that user. See SessionManagementServiceImpl's class
 * Javadoc for the full fix. userId is now the only lookup key, since it's
 * always present regardless of which contact methods a user has - also the
 * natural anchor for the future clientApplicationId column Step 12 will
 * add here, once sessions can be scoped per (user, application) per the
 * Step 11B decision.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "user_sessions")
public class UserSession {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(name = "phone_number")
    private String phoneNumber;

    @Column(name = "token_hash", nullable = false, unique = true)
    private String tokenHash;

    @Column(name = "is_active", nullable = false)
    private boolean isActive;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @Column(name = "ended_at")
    private LocalDateTime endedAt;

    @Column(name = "end_reason", length = 50)
    private String endReason;

    /**
     * Step 2E (React Admin Client plan v4): the caller's IP and User-Agent
     * at session-creation time (see JwtSessionTrackingFilter), captured
     * for the admin Sessions - List screen's filters. Both nullable -
     * informational-only, same status as phoneNumber above (see this
     * class's Javadoc) - and absent on every session row created before
     * this step.
     */
    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    @Column(name = "user_agent", length = 500)
    private String userAgent;

    /**
     * Step 17h (B-14): "Mac, Chrome", parsed from userAgent once, when the session is created
     * (DeviceLabelParser). Null on rows created before V30; those are labelled when read.
     */
    @Column(name = "device_label", length = 100)
    private String deviceLabel;

    /** Step 17h: set at sign-in and on every token refresh. Null on rows created before V30. */
    @Column(name = "last_active_at")
    private LocalDateTime lastActiveAt;

    /**
     * Step 17h: the oauth2_authorization row (refresh token) this session was issued with, replaced on
     * every refresh. Signing one device out deletes exactly this row, so the others keep working. Null
     * on rows created before V30 and on sessions backfilled from a request (JwtSessionTrackingFilter).
     */
    @Column(name = "authorization_id", length = 100)
    private String authorizationId;

}
