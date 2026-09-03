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

}
